"""v0.10.3 regression suite: the six bugs found by the deep audit + security
review of the compliance-report / audit engine. Each test FAILS without its
fix.

  CRITICAL-1: generate_compliance_report now actually verifies the hash chain.
  CRITICAL-2: the report no longer falsely claims per-signature verification;
              a failed KeyManifest provenance is a real NON_COMPLIANT reason.
  HIGH-3:     build_report does not crash on malformed `categories` (AUDIT-3).
  HIGH-4:     context_analyzer risk floats are cross-SDK byte-identical.
  HIGH-5:     canonical_json rejects prototype-pollution key names (both SDKs).
  MEDIUM-6:   an article filter cannot hide a pii_in_log=true violation.
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm._canonical import canonical_json
from cloakllm.compliance_report import build_report, ReportPeriod
from cloakllm.context_analyzer import ContextAnalyzer


@pytest.fixture
def shield(tmp_path):
    cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        yield Shield(config=ShieldConfig(
            log_dir=str(tmp_path / "audit"),
            compliance_mode="eu_ai_act_article12",
        ))
    finally:
        os.chdir(cwd)


def _tamper_first_entry(log_dir: str):
    f = sorted(Path(log_dir).glob("*.jsonl"))[0]
    lines = f.read_text(encoding="utf-8").strip().splitlines()
    e0 = json.loads(lines[0])
    e0["entity_count"] = 999  # mutate a hashed field, leave entry_hash stale
    lines[0] = json.dumps(e0)
    f.write_text("\n".join(lines) + "\n", encoding="utf-8")


# ---- CRITICAL-1 -----------------------------------------------------

class TestChainActuallyVerified:
    def test_tampered_chain_is_non_compliant(self, shield):
        shield.record_content_generation(modality="text", labeled=True)
        shield.record_content_generation(modality="text", labeled=True)
        _tamper_first_entry(shield.config.log_dir)
        rep = shield.generate_compliance_report(format="json")
        assert rep["verdict"] == "NON_COMPLIANT"
        assert rep["chain_integrity"]["verdict"] == "broken"
        assert len(rep["chain_integrity"]["anomalies"]) >= 1
        assert any("chain_integrity" in r for r in rep["verdict_reasons"])

    def test_clean_chain_still_verified_compliant(self, shield):
        shield.record_content_generation(modality="text", labeled=True)
        rep = shield.generate_compliance_report(format="json")
        assert rep["verdict"] == "COMPLIANT"
        assert rep["chain_integrity"]["verdict"] == "verified"


# ---- HIGH-3 ---------------------------------------------------------

class TestMalformedCategoriesNoCrash:
    def _entry(self, categories):
        return dict(
            seq=0, event_id="e", timestamp="2026-01-01T00:00:00+00:00",
            event_type="sanitize", model=None, provider=None, entity_count=0,
            tokens_used=[], prompt_hash="", sanitized_hash="", latency_ms=0,
            mode=None, entity_details=[], timing=None, certificate_hash=None,
            key_id=None, prev_hash="0" * 64, entry_hash="x", metadata={},
            risk_assessment=None, article_ref=["EU_AI_Act_Art_12"],
            categories=categories,
        )

    @pytest.mark.parametrize("categories", [
        "notadict", ["a", "b"], {"EMAIL": "5"}, {"EMAIL": None},
        {"EMAIL": 3.5}, {123: 4}, {"EMAIL": True},
    ])
    def test_does_not_crash(self, categories):
        rep = build_report(
            audit_entries=[self._entry(categories)],
            period=ReportPeriod(None, None), cloakllm_version="x", chain_valid=True,
        )
        # valid {str: int} survives; everything else is skipped, never crashes
        cats = rep["per_article"]["EU_AI_Act_Art_12"]["categories_detected"]
        assert all(isinstance(k, str) and isinstance(v, int) for k, v in cats.items())

    def test_valid_int_counts_still_aggregate(self):
        rep = build_report(
            audit_entries=[self._entry({"EMAIL": 3, "SSN": 2})],
            period=ReportPeriod(None, None), cloakllm_version="x", chain_valid=True,
        )
        assert rep["per_article"]["EU_AI_Act_Art_12"]["categories_detected"] == {"EMAIL": 3, "SSN": 2}


# ---- MEDIUM-6 -------------------------------------------------------

class TestPiiInLogIsGlobal:
    def _pii_entry(self, articles_ref):
        return dict(
            seq=0, event_id="e", timestamp="2026-01-01T00:00:00+00:00",
            event_type="sanitize", model=None, provider=None, entity_count=0,
            categories={}, tokens_used=[], prompt_hash="", sanitized_hash="",
            latency_ms=0, mode=None, entity_details=[], timing=None,
            certificate_hash=None, key_id=None, prev_hash="0" * 64,
            entry_hash="x", metadata={}, risk_assessment=None,
            article_ref=articles_ref, pii_in_log=True,
        )

    def test_filtered_out_pii_still_flips_verdict(self):
        rep = build_report(
            audit_entries=[self._pii_entry(["EU_AI_Act_Art_12"])],
            period=ReportPeriod(None, None), cloakllm_version="x",
            articles=["EU_AI_Act_Art_50"], chain_valid=True,
        )
        assert rep["verdict"] == "NON_COMPLIANT"
        assert any("pii_in_log" in r for r in rep["verdict_reasons"])

    def test_empty_article_ref_pii_still_flips_verdict(self):
        rep = build_report(
            audit_entries=[self._pii_entry([])],
            period=ReportPeriod(None, None), cloakllm_version="x", chain_valid=True,
        )
        assert rep["verdict"] == "NON_COMPLIANT"


# ---- HIGH-4 ---------------------------------------------------------

class TestRiskAssessmentCanonical:
    def test_empty_text_emits_int_zero(self):
        ra = ContextAnalyzer().analyze("   ")
        # int 0, not float 0.0 -> canonical "0" matches JS
        assert ra.token_density == 0 and isinstance(ra.token_density, int)
        assert ra.risk_score == 0 and isinstance(ra.risk_score, int)

    def test_whole_risk_score_emits_int(self):
        ra = ContextAnalyzer().analyze("[A_0] [B_0] [C_0] [D_0]")  # density 1.0
        assert canonical_json({"v": ra.risk_score}) == '{"v":1}'
        assert canonical_json({"v": ra.token_density}) == '{"v":1}'


# ---- HIGH-5 ---------------------------------------------------------

class TestCanonicalRejectsProtoKeys:
    @pytest.mark.parametrize("bad", [
        {"__proto__": 1}, {"constructor": 2}, {"prototype": 3},
        {"a": {"b": {"constructor": 9}}}, {"x": [{"__proto__": 0}]},
    ])
    def test_rejected(self, bad):
        with pytest.raises(ValueError, match="disallowed object key"):
            canonical_json(bad)

    def test_normal_keys_unaffected(self):
        assert canonical_json({"b": 2, "a": 1}) == '{"a":1,"b":2}'


# ---- CRITICAL-2 -----------------------------------------------------

class TestHonestAttestation:
    def test_no_false_signature_verdict_reason(self, shield):
        """A clean chain with certificate_hash entries must NOT produce an
        'X/Y signatures valid' verdict reason (the old dead guard); honest
        attestation comes from provenance, not an unverifiable cert count."""
        # write an entry carrying a certificate_hash but no real provenance
        shield.audit.log(event_type="sanitize", certificate_hash="a" * 64, key_id="k1")
        rep = shield.generate_compliance_report(format="json")
        assert not any("signatures valid" in r for r in rep["verdict_reasons"])
        # the attestation block still reports the count, just doesn't claim
        # cryptographic verification in the verdict
        assert rep["attestation"]["entries_with_certificates"] >= 1
