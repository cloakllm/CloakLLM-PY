"""
Tests for v0.6.0 Compliance Mode (Article 12 / GDPR alignment).

Covers:
- ShieldConfig validation of compliance_mode and retention_hint_days
- Audit entries gain the 4 compliance fields when compliance_mode is set
- Compliance fields are part of the hash chain (tamper-detectable)
- _assert_no_pii_in_entry runtime guard fires on PII leak attempts
- compliance_summary() returns the expected structure
- export_compliance_config() writes a valid JSON snapshot
- verify_audit(output_format="compliance_report") returns COMPLIANT/NON_COMPLIANT verdicts
- Tampered audit dirs produce NON_COMPLIANT verdict
"""

import json
import os
import tempfile
from pathlib import Path

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.audit import AuditLogger, _assert_no_pii_in_entry


@pytest.fixture
def tmp_log_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


# --- ShieldConfig validation -------------------------------------------------


def test_compliance_mode_default_is_none():
    cfg = ShieldConfig()
    assert cfg.compliance_mode is None
    assert cfg.retention_hint_days == 180


def test_compliance_mode_accepts_eu_ai_act_article12():
    cfg = ShieldConfig(compliance_mode="eu_ai_act_article12")
    assert cfg.compliance_mode == "eu_ai_act_article12"


def test_compliance_mode_rejects_invalid_value():
    with pytest.raises(ValueError, match="Invalid compliance_mode"):
        ShieldConfig(compliance_mode="not_a_real_mode")


def test_retention_hint_days_must_be_positive():
    with pytest.raises(ValueError, match="retention_hint_days"):
        ShieldConfig(retention_hint_days=0)


def test_attestation_key_provider_rejects_invalid_value():
    with pytest.raises(ValueError, match="Invalid attestation_key_provider"):
        ShieldConfig(attestation_key_provider="bad_kms", attestation_key_id="x")


def test_attestation_key_provider_requires_key_id():
    with pytest.raises(ValueError, match="attestation_key_id is required"):
        ShieldConfig(attestation_key_provider="aws_kms", attestation_key_id=None)


# --- Audit entry compliance fields ------------------------------------------


def test_compliance_fields_added_when_mode_set(tmp_log_dir):
    cfg = ShieldConfig(
        log_dir=tmp_log_dir,
        compliance_mode="eu_ai_act_article12",
        retention_hint_days=365,
        audit_enabled=True,
    )
    shield = Shield(cfg)
    shield.sanitize("Email me at john@acme.com")

    log_files = list(tmp_log_dir.glob("audit_*.jsonl"))
    assert len(log_files) == 1
    entries = [json.loads(line) for line in log_files[0].read_text().splitlines() if line]
    assert all(e["compliance_version"] == "eu_ai_act_article12_v1" for e in entries)
    assert all(e["article_ref"] == ["EU_AI_Act_Art_12", "EU_AI_Act_Art_19"] for e in entries)
    assert all(e["retention_hint_days"] == 365 for e in entries)
    assert all(e["pii_in_log"] is False for e in entries)


def test_compliance_fields_omitted_when_mode_none(tmp_log_dir):
    cfg = ShieldConfig(log_dir=tmp_log_dir, audit_enabled=True)
    shield = Shield(cfg)
    shield.sanitize("Email me at john@acme.com")

    log_files = list(tmp_log_dir.glob("audit_*.jsonl"))
    entries = [json.loads(line) for line in log_files[0].read_text().splitlines() if line]
    for e in entries:
        # AuditEntry has the fields as Optional[None] when not in compliance mode;
        # they should NOT be written into the JSON in the first place.
        assert "compliance_version" not in e
        assert "pii_in_log" not in e


def test_compliance_fields_part_of_hash_chain(tmp_log_dir):
    """If we tamper with a compliance field, verify_chain must catch it."""
    cfg = ShieldConfig(
        log_dir=tmp_log_dir,
        compliance_mode="eu_ai_act_article12",
        audit_enabled=True,
    )
    shield = Shield(cfg)
    shield.sanitize("john@acme.com")

    log_file = next(tmp_log_dir.glob("audit_*.jsonl"))
    text = log_file.read_text()
    # Flip pii_in_log from false to true on disk
    tampered = text.replace('"pii_in_log":false', '"pii_in_log":true')
    assert tampered != text
    log_file.write_text(tampered)

    is_valid, errors, _ = AuditLogger(cfg).verify_chain()
    assert not is_valid
    assert any("tampered" in err.lower() for err in errors)


# --- _assert_no_pii_in_entry runtime guard ----------------------------------


def test_pii_guard_passes_for_safe_entity_details():
    safe = {"entity_details": [
        {"category": "EMAIL", "start": 0, "end": 13, "token": "[EMAIL_0]"},
    ]}
    _assert_no_pii_in_entry(safe)  # no exception


def test_pii_guard_raises_on_original_value_field():
    bad = {"entity_details": [
        {"category": "EMAIL", "original_value": "john@acme.com", "token": "[EMAIL_0]"},
    ]}
    with pytest.raises(RuntimeError, match="COMPLIANCE VIOLATION"):
        _assert_no_pii_in_entry(bad)


def test_pii_guard_raises_on_raw_text_field():
    bad = {"entity_details": [{"category": "PHONE", "raw_text": "+1-555-1234"}]}
    with pytest.raises(RuntimeError, match="COMPLIANCE VIOLATION"):
        _assert_no_pii_in_entry(bad)


# --- compliance_summary -----------------------------------------------------


def test_compliance_summary_structure():
    cfg = ShieldConfig(compliance_mode="eu_ai_act_article12")
    shield = Shield(cfg)
    summary = shield.compliance_summary()

    assert summary["compliance_mode"] == "eu_ai_act_article12"
    assert "articles_addressed" in summary
    assert len(summary["articles_addressed"]) == 6

    article_names = {a["article"] for a in summary["articles_addressed"]}
    expected = {
        "EU_AI_Act_Art_12",
        "EU_AI_Act_Art_19",
        "GDPR_Art_5_data_minimisation",
        "GDPR_Art_5_storage_limitation",
        "GDPR_Art_25_privacy_by_design",
        "EU_AI_Act_Art_4a",
    }
    assert article_names == expected

    # Article 4a is partial in v0.6.0
    art4a = next(a for a in summary["articles_addressed"] if a["article"] == "EU_AI_Act_Art_4a")
    assert art4a["status"] == "partial"

    assert summary["config_snapshot"]["compliance_mode"] == "eu_ai_act_article12"
    assert summary["config_snapshot"]["retention_hint_days"] == 180
    assert "generated_at" in summary
    assert "cloakllm_version" in summary


# --- export_compliance_config ----------------------------------------------


def test_export_compliance_config_writes_valid_json(tmp_path):
    cfg = ShieldConfig(compliance_mode="eu_ai_act_article12")
    shield = Shield(cfg)
    out_file = tmp_path / "compliance.json"
    written = shield.export_compliance_config(str(out_file))

    assert Path(written).exists()
    data = json.loads(out_file.read_text())
    assert data["compliance_mode"] == "eu_ai_act_article12"
    assert "note" in data
    assert "cloakllm" in data["note"].lower()


# --- verify_audit compliance_report ----------------------------------------


def test_verify_audit_compliance_report_compliant(tmp_log_dir):
    cfg = ShieldConfig(
        log_dir=tmp_log_dir,
        compliance_mode="eu_ai_act_article12",
        audit_enabled=True,
    )
    shield = Shield(cfg)
    shield.sanitize("Email me at john@acme.com")
    shield.sanitize("Call +1-555-1234")

    report = shield.verify_audit(output_format="compliance_report")
    assert report["verdict"] == "COMPLIANT"
    assert report["chain_integrity"] == "verified"
    assert report["pii_in_logs"] is False
    assert report["total_entries"] == 2
    assert report["compliance_mode_entries"] == 2
    assert "EMAIL" in report["pii_categories_detected"]


def test_verify_audit_compliance_report_non_compliant_on_tamper(tmp_log_dir):
    cfg = ShieldConfig(
        log_dir=tmp_log_dir,
        compliance_mode="eu_ai_act_article12",
        audit_enabled=True,
    )
    shield = Shield(cfg)
    shield.sanitize("john@acme.com")

    log_file = next(tmp_log_dir.glob("audit_*.jsonl"))
    text = log_file.read_text()
    log_file.write_text(text.replace('"pii_in_log":false', '"pii_in_log":true'))

    report = shield.verify_audit(output_format="compliance_report")
    assert report["verdict"] == "NON_COMPLIANT"
    assert len(report["anomalies"]) > 0


def test_verify_audit_default_format_returns_existing_shape(tmp_log_dir):
    """Backward compat: omitting output_format returns the existing dict shape."""
    cfg = ShieldConfig(log_dir=tmp_log_dir, audit_enabled=True)
    shield = Shield(cfg)
    shield.sanitize("john@acme.com")

    result = shield.verify_audit()
    assert "valid" in result
    assert "errors" in result
    assert "final_seq" in result


def test_verify_audit_alternate_log_dir(tmp_log_dir):
    cfg = ShieldConfig(
        log_dir=tmp_log_dir,
        compliance_mode="eu_ai_act_article12",
        audit_enabled=True,
    )
    shield = Shield(cfg)
    shield.sanitize("john@acme.com")

    # Verify with alternate dir explicitly
    report = shield.verify_audit(log_dir=str(tmp_log_dir), output_format="compliance_report")
    assert report["verdict"] == "COMPLIANT"
