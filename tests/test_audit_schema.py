"""
v0.6.1 B3: always-on allow-list audit schema validator.

The validator runs on EVERY audit write (not gated on compliance_mode) to
enforce the project-wide invariant: "CloakLLM audit logs must contain zero
original PII." Reviewer-approved Q5 = always-on.
"""

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.audit import (
    _validate_audit_entry_schema,
    _ENTITY_DETAIL_ALLOWED_KEYS,
    _ENTRY_ALLOWED_KEYS,
)


# --- Allow-list constants are exactly what the audit emits -----------------


def test_entity_detail_allowed_keys_is_9():
    """Verified against tokenizer.py:114-120 + shield.py:306 (text_index).

    If a future contributor adds a key to entity_details, this test will fail
    until the allow-list is updated to match. That's intentional — every new
    field needs a deliberate allow-list decision.
    """
    assert len(_ENTITY_DETAIL_ALLOWED_KEYS) == 9
    expected = {
        "category", "start", "end", "length", "confidence",
        "source", "token", "entity_hash", "text_index",
    }
    assert _ENTITY_DETAIL_ALLOWED_KEYS == expected


def test_entry_allowed_keys_includes_compliance_fields():
    for k in ("compliance_version", "article_ref", "retention_hint_days", "pii_in_log"):
        assert k in _ENTRY_ALLOWED_KEYS


# --- Validator behavior ----------------------------------------------------


def _valid_entry():
    """Minimal valid entry shape."""
    return {
        "seq": 0,
        "event_id": "abc",
        "timestamp": "2026-04-16T00:00:00Z",
        "event_type": "sanitize",
        "model": None,
        "provider": None,
        "entity_count": 0,
        "categories": {},
        "tokens_used": [],
        "prompt_hash": "",
        "sanitized_hash": "",
        "latency_ms": 0.0,
        "mode": "tokenize",
        "entity_details": [],
        "timing": None,
        "certificate_hash": None,
        "key_id": None,
        "prev_hash": "0" * 64,
        "metadata": {},
        "risk_assessment": None,
    }


def test_valid_entry_passes():
    _validate_audit_entry_schema(_valid_entry())


def test_unknown_top_level_key_rejected():
    e = _valid_entry()
    e["unknown_field"] = "anything"
    with pytest.raises(RuntimeError, match="top-level key"):
        _validate_audit_entry_schema(e)


def test_unknown_entity_detail_key_rejected():
    e = _valid_entry()
    e["entity_details"] = [{"category": "EMAIL", "start": 0, "end": 13, "evil": "pii"}]
    with pytest.raises(RuntimeError, match="entity_details"):
        _validate_audit_entry_schema(e)


def test_legacy_pii_keys_in_entity_details_rejected():
    """The deny-list is also enforced for clarity (belt + suspenders)."""
    for key in ("original_value", "original_text", "raw_text", "plain_text", "value"):
        e = _valid_entry()
        e["entity_details"] = [{"category": "EMAIL", key: "leaked"}]
        with pytest.raises(RuntimeError):
            _validate_audit_entry_schema(e)


def test_text_index_allowed_in_entity_details():
    e = _valid_entry()
    e["entity_details"] = [
        {"category": "EMAIL", "start": 0, "end": 13, "text_index": 0,
         "length": 13, "confidence": 0.95, "source": "regex", "token": "[EMAIL_0]"}
    ]
    _validate_audit_entry_schema(e)  # no exception


def test_metadata_string_too_long_rejected():
    e = _valid_entry()
    e["metadata"] = {"key": "x" * 257}
    with pytest.raises(RuntimeError, match="exceeds 256 chars"):
        _validate_audit_entry_schema(e)


def test_metadata_too_deep_rejected():
    e = _valid_entry()
    e["metadata"] = {"a": {"b": {"c": {"d": "deep"}}}}  # depth 4
    with pytest.raises(RuntimeError, match="max nesting depth"):
        _validate_audit_entry_schema(e)


def test_metadata_disallowed_value_type_rejected():
    e = _valid_entry()
    e["metadata"] = {"k": object()}  # arbitrary object
    with pytest.raises(RuntimeError, match="disallowed type"):
        _validate_audit_entry_schema(e)


def test_metadata_with_safe_scalars_allowed():
    e = _valid_entry()
    e["metadata"] = {
        "user_id": "user-123",
        "request_count": 42,
        "is_premium": True,
        "score": 0.95,
        "tags": ["a", "b"],
        "nested": {"k": "v"},
    }
    _validate_audit_entry_schema(e)


# --- Always-on (not gated on compliance mode) ------------------------------


def test_always_on_even_without_compliance_mode(tmp_path):
    """The validator runs on EVERY sanitize, regardless of compliance_mode."""
    config = ShieldConfig(
        log_dir=tmp_path / "audit",
        audit_enabled=True,
        # NOT in compliance mode
    )
    shield = Shield(config)
    # Refuses metadata with disallowed value type (arbitrary objects)
    with pytest.raises(RuntimeError, match="disallowed type"):
        shield.sanitize("Email john@acme.com", metadata={"key": object()})


def test_always_on_rejects_long_metadata_value(tmp_path):
    config = ShieldConfig(
        log_dir=tmp_path / "audit",
        audit_enabled=True,
    )
    shield = Shield(config)
    with pytest.raises(RuntimeError, match="exceeds 256 chars"):
        shield.sanitize("Email john@acme.com", metadata={"prompt": "x" * 1000})


def test_always_on_with_compliance_mode_too(tmp_path):
    """Same enforcement also applies under compliance mode."""
    config = ShieldConfig(
        log_dir=tmp_path / "audit",
        audit_enabled=True,
        compliance_mode="eu_ai_act_article12",
    )
    shield = Shield(config)
    with pytest.raises(RuntimeError, match="AUDIT SCHEMA|exceeds"):
        shield.sanitize("Email john@acme.com", metadata={"prompt": "x" * 1000})
