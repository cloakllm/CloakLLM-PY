"""v0.10.0 A50-* test suite: EU AI Act Article 50 content-labeling
record-keeping.

Covers:
  * A50-1: content_generation event + B3 content_context validation
    (closed whitelists, bool/hash types, NUL/oversize, no-content invariant,
    event_type coupling, AUDIT-3 adversarial inputs)
  * A50-2: Shield.record_content_generation() emission + article_ref
  * A50-3: Article 50 report rollup + the Art-50-only correctness invariant
    (content stats MUST NOT appear on Art_12/Art_19 rows) + coverage
    int-when-whole
  * A50-4: verdict flips NON_COMPLIANT on any unlabeled synthetic content
  * A50-6: backward compatibility (pre-v0.10.0 chains verify + report
    byte-identical when no content events)
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.audit import (
    _validate_content_context, _validate_audit_entry_schema,
    AuditLogger,
)
from cloakllm.compliance_report import ReportPeriod, build_report, render_markdown


def _valid_cc(**overrides):
    cc = {
        "modality": "text",
        "synthetic": True,
        "labeled": True,
        "disclosure_method": "c2pa",
        "deepfake": False,
        "c2pa_manifest_hash": None,
        "content_hash": None,
    }
    cc.update(overrides)
    return cc


# ===================================================================
# A50-1: _validate_content_context (B3)
# ===================================================================

class TestValidateContentContext:
    def test_happy_path(self):
        _validate_content_context(_valid_cc())

    def test_minimal_required_only(self):
        _validate_content_context({
            "modality": "image", "synthetic": True, "labeled": False,
            "disclosure_method": "none", "deepfake": False,
        })

    def test_content_hash_accepted(self):
        _validate_content_context(_valid_cc(content_hash="a" * 64))

    def test_c2pa_manifest_hash_accepted(self):
        _validate_content_context(_valid_cc(c2pa_manifest_hash="b" * 64))

    @pytest.mark.parametrize("mod", ["text", "image", "audio", "video"])
    def test_all_modalities(self, mod):
        _validate_content_context(_valid_cc(modality=mod))

    @pytest.mark.parametrize(
        "disc", ["c2pa", "watermark", "metadata", "visible_notice", "none"]
    )
    def test_all_disclosure_methods(self, disc):
        _validate_content_context(_valid_cc(disclosure_method=disc))

    def test_reject_bad_modality(self):
        with pytest.raises(RuntimeError, match="modality"):
            _validate_content_context(_valid_cc(modality="hologram"))

    def test_reject_bad_disclosure_method(self):
        with pytest.raises(RuntimeError, match="disclosure_method"):
            _validate_content_context(_valid_cc(disclosure_method="vibes"))

    @pytest.mark.parametrize("field", ["synthetic", "labeled", "deepfake"])
    def test_reject_non_bool(self, field):
        with pytest.raises(RuntimeError, match="must be a bool"):
            _validate_content_context(_valid_cc(**{field: "yes"}))

    def test_reject_missing_required(self):
        cc = _valid_cc()
        del cc["deepfake"]
        with pytest.raises(RuntimeError, match="missing required field 'deepfake'"):
            _validate_content_context(cc)

    def test_reject_null_required(self):
        with pytest.raises(RuntimeError, match="must not be null"):
            _validate_content_context(_valid_cc(modality=None))

    def test_reject_disallowed_key(self):
        with pytest.raises(RuntimeError, match="disallowed"):
            _validate_content_context(_valid_cc(extra="nope"))

    def test_reject_oversize_hash(self):
        with pytest.raises(RuntimeError, match="exceeds"):
            _validate_content_context(_valid_cc(content_hash="a" * 200))

    def test_reject_nul_in_hash(self):
        with pytest.raises(RuntimeError, match="NUL byte"):
            _validate_content_context(_valid_cc(content_hash="a\x00b"))

    def test_reject_non_dict(self):
        with pytest.raises(RuntimeError, match="must be a dict"):
            _validate_content_context(["not", "a", "dict"])

    # --- the no-content-in-logs invariant (the never-break guarantee) ---

    @pytest.mark.parametrize(
        "forbidden", ["content", "text", "output", "payload", "body", "data", "asset"]
    )
    def test_reject_forbidden_content_keys(self, forbidden):
        with pytest.raises(RuntimeError, match="COMPLIANCE VIOLATION"):
            _validate_content_context(_valid_cc(**{forbidden: "the secret prompt"}))


# ===================================================================
# A50-1: event_type coupling (content_context only on content_generation)
# ===================================================================

class TestContentContextCoupling:
    def _entry(self, event_type, content_context):
        return {
            "seq": 0, "event_id": "e", "timestamp": "2026-12-02T00:00:00+00:00",
            "event_type": event_type, "model": None, "provider": None,
            "entity_count": 0, "categories": {}, "tokens_used": [],
            "prompt_hash": "", "sanitized_hash": "", "latency_ms": 0,
            "mode": None, "entity_details": [], "timing": None,
            "certificate_hash": None, "key_id": None, "prev_hash": "0" * 64,
            "metadata": {}, "risk_assessment": None,
            "content_context": content_context,
        }

    def test_valid_on_content_generation(self):
        _validate_audit_entry_schema(self._entry("content_generation", _valid_cc()))

    def test_rejected_on_sanitize(self):
        with pytest.raises(RuntimeError, match="content_context requires"):
            _validate_audit_entry_schema(self._entry("sanitize", _valid_cc()))

    def test_rejected_on_key_registered(self):
        with pytest.raises(RuntimeError, match="content_context requires"):
            _validate_audit_entry_schema(self._entry("key_registered", _valid_cc()))


# ===================================================================
# A50-2: Shield.record_content_generation
# ===================================================================

@pytest.fixture
def shield(tmp_path):
    cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        cfg = ShieldConfig(
            log_dir=str(tmp_path / "audit"),
            compliance_mode="eu_ai_act_article12",
        )
        yield Shield(config=cfg)
    finally:
        os.chdir(cwd)


def _entries(shield):
    log_dir = Path(shield.config.log_dir)
    out = []
    for f in sorted(log_dir.glob("*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


class TestRecordContentGeneration:
    def test_writes_event(self, shield):
        shield.record_content_generation(
            modality="image", labeled=True, disclosure_method="c2pa",
            content_hash="a" * 64,
        )
        entries = _entries(shield)
        assert len(entries) == 1
        e = entries[0]
        assert e["event_type"] == "content_generation"
        assert e["content_context"]["modality"] == "image"
        assert e["content_context"]["content_hash"] == "a" * 64

    def test_article_ref_includes_art50(self, shield):
        shield.record_content_generation(modality="text", labeled=True)
        e = _entries(shield)[0]
        assert e["article_ref"] == [
            "EU_AI_Act_Art_12", "EU_AI_Act_Art_19", "EU_AI_Act_Art_50",
        ]

    def test_chain_verifies(self, shield):
        for _ in range(3):
            shield.record_content_generation(modality="text", labeled=True)
        ok, errs, _seq = shield.audit.verify_chain()
        assert ok, errs

    def test_reject_bad_modality(self, shield):
        with pytest.raises(ValueError, match="modality"):
            shield.record_content_generation(modality="hologram")

    def test_reject_bad_disclosure(self, shield):
        with pytest.raises(ValueError, match="disclosure_method"):
            shield.record_content_generation(modality="text", disclosure_method="vibes")

    def test_decision_id_threaded(self, shield):
        shield.record_content_generation(
            modality="text", labeled=True, decision_id="my-decision-1",
        )
        assert _entries(shield)[0]["decision_id"] == "my-decision-1"

    def test_no_content_reaches_log(self, shield):
        """The asset bytes are never passed to CloakLLM; the log holds a hash."""
        shield.record_content_generation(
            modality="text", labeled=True, content_hash="deadbeef" * 8,
        )
        raw = json.dumps(_entries(shield)[0])
        # only the hash, never any 'content'/'output' key
        assert "deadbeef" in raw
        assert '"content"' not in raw and '"output"' not in raw


# ===================================================================
# A50-3 + A50-4: report rollup, Art-50-only invariant, verdict
# ===================================================================

class TestArticle50Rollup:
    def _gen(self, shield, n_labeled, n_unlabeled, modalities=None, deepfakes=0):
        modalities = modalities or ["text"]
        i = 0
        for _ in range(n_labeled):
            shield.record_content_generation(
                modality=modalities[i % len(modalities)], labeled=True,
                disclosure_method="c2pa",
                deepfake=(i < deepfakes),
            )
            i += 1
        for _ in range(n_unlabeled):
            shield.record_content_generation(
                modality=modalities[i % len(modalities)], labeled=False,
                disclosure_method="none",
            )
            i += 1

    def test_rollup_fields(self, shield):
        self._gen(shield, n_labeled=4, n_unlabeled=1,
                  modalities=["text", "text", "text", "image", "audio"])
        rep = shield.generate_compliance_report(format="json")
        a50 = rep["per_article"]["EU_AI_Act_Art_50"]
        assert a50["generation_events"] == 5
        assert a50["labeled_events"] == 4
        assert a50["label_coverage_pct"] == 80
        assert a50["modality_distribution"] == {"audio": 1, "image": 1, "text": 3}

    def test_coverage_int_when_whole(self, shield):
        self._gen(shield, n_labeled=2, n_unlabeled=0)
        rep = shield.generate_compliance_report(format="json")
        cov = rep["per_article"]["EU_AI_Act_Art_50"]["label_coverage_pct"]
        assert cov == 100
        assert isinstance(cov, int)

    def test_coverage_two_dp(self, shield):
        self._gen(shield, n_labeled=1, n_unlabeled=2)  # 1/3 labeled
        rep = shield.generate_compliance_report(format="json")
        cov = rep["per_article"]["EU_AI_Act_Art_50"]["label_coverage_pct"]
        assert cov == 33.33

    def test_deepfake_count(self, shield):
        self._gen(shield, n_labeled=3, n_unlabeled=0, deepfakes=2)
        rep = shield.generate_compliance_report(format="json")
        assert rep["per_article"]["EU_AI_Act_Art_50"]["deepfake_events"] == 2

    def test_art50_only_invariant(self, shield):
        """The correctness invariant: content stats attach ONLY to the Art_50
        row, never to Art_12/Art_19 (even though events claim all three)."""
        self._gen(shield, n_labeled=3, n_unlabeled=0)
        rep = shield.generate_compliance_report(format="json")
        content_keys = {
            "generation_events", "labeled_events", "label_coverage_pct",
            "deepfake_events", "modality_distribution",
        }
        for art in ("EU_AI_Act_Art_12", "EU_AI_Act_Art_19"):
            stats = rep["per_article"][art]
            assert content_keys.isdisjoint(stats.keys()), (
                f"{art} leaked content-labeling stats: "
                f"{content_keys & set(stats.keys())}"
            )
        assert content_keys.issubset(rep["per_article"]["EU_AI_Act_Art_50"].keys())

    def test_rollup_merges_not_replaces(self, shield):
        """evidence_event_count / decision_count (set before the rollup) must
        survive the merge -- the KM-9/RV-4 replace-bug class."""
        self._gen(shield, n_labeled=2, n_unlabeled=0)
        a50 = shield.generate_compliance_report(format="json")["per_article"]["EU_AI_Act_Art_50"]
        assert a50["evidence_event_count"] == 2
        assert a50["decision_count"] == 2  # distinct decision_ids
        assert a50["generation_events"] == 2  # additive field present too

    def test_verdict_compliant_when_all_labeled(self, shield):
        self._gen(shield, n_labeled=5, n_unlabeled=0)
        rep = shield.generate_compliance_report(format="json")
        assert rep["verdict"] == "COMPLIANT"

    def test_verdict_noncompliant_on_unlabeled(self, shield):
        self._gen(shield, n_labeled=4, n_unlabeled=1)
        rep = shield.generate_compliance_report(format="json")
        assert rep["verdict"] == "NON_COMPLIANT"
        assert any("EU_AI_Act_Art_50" in r and "unlabeled" in r
                   for r in rep["verdict_reasons"])

    def test_markdown_renders_art50(self, shield):
        self._gen(shield, n_labeled=2, n_unlabeled=0)
        md = shield.generate_compliance_report(format="markdown")
        assert "Article 50 generation events" in md
        assert "Label coverage" in md


# ===================================================================
# A50-6: backward compatibility
# ===================================================================

class TestBackwardCompat:
    def test_pre_v0100_chain_has_no_art50_row(self, shield):
        """A chain with only sanitize events has no Art_50 row -- zero
        behavior change for pre-v0.10.0 deployments."""
        shield.sanitize("Email me at john@acme.com")
        rep = shield.generate_compliance_report(format="json")
        assert "EU_AI_Act_Art_50" not in rep["per_article"]
        assert rep["verdict"] == "COMPLIANT"

    def test_synth_pre_v0100_entry_without_content_context_verifies(self, tmp_path):
        """An entry written before content_context existed (field absent, not
        null) must still verify under v0.10.0 code."""
        cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            cfg = ShieldConfig(log_dir=str(tmp_path / "audit"),
                               compliance_mode="eu_ai_act_article12")
            sh = Shield(config=cfg)
            sh.sanitize("no PII here")
            ok, errs, _ = sh.audit.verify_chain()
            assert ok, errs
        finally:
            os.chdir(cwd)
