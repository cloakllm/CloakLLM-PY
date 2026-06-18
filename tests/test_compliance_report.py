"""v0.8.0 CR8: test suite for Shield.generate_compliance_report().

Covers:
  * Per-article rollup correctness
  * decision_id cross-article reconciliation
  * Bias-stats attach only to Article 4a (not Art_12 / Art_19 even though
    bias events claim those articles too)
  * Output formats: JSON, Markdown, PDF (skipif reportlab unavailable)
  * JSON Schema validation against the published schema
  * Verdict: COMPLIANT / NON_COMPLIANT with explicit reasons
  * Empty period / zero-entry / unfiltered articles edge cases
  * v0.8.1 forward-compat: attestation block shape matches the future
    KeyManifest ProvenanceReport contract (manifest fields null)
  * compliance_summary() now includes v0.7.1 + v0.8.0 fields
"""

from __future__ import annotations

import json
import os
from pathlib import Path

import pytest

from cloakllm import Shield, ShieldConfig, BiasDetectionSession
from cloakllm.compliance_report import (
    ReportPeriod, build_report, render_markdown, SCHEMA_VERSION,
    ATTESTATION_SCHEMA_VERSION,
)


_SCHEMA_PATH = (
    Path(__file__).resolve().parent.parent / "examples" / "compliance_report_schema.json"
)


@pytest.fixture
def schema():
    """The published JSON Schema. Test fails fast if the schema file is missing."""
    assert _SCHEMA_PATH.exists(), (
        f"Missing schema file at {_SCHEMA_PATH}. The schema is part of the "
        f"v0.8.0 contract -- it ships with the wheel via examples/."
    )
    return json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))


@pytest.fixture
def shield_a12(tmp_path):
    cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        cfg = ShieldConfig(
            log_dir=str(tmp_path / "audit"),
            compliance_mode="eu_ai_act_article12",
            deployment_version="prod-2026",
            instruction_version="sysprompt-v3",
        )
        yield Shield(config=cfg)
    finally:
        os.chdir(cwd)


@pytest.fixture
def shield_with_mixed_chain(shield_a12):
    """A shield with 3 regular sanitize + 1 bias session + 2 sanitize."""
    shield_a12.sanitize("Email a@x.com", model="gpt-4o")
    shield_a12.sanitize("Email b@x.com", model="gpt-4o")
    shield_a12.sanitize("Email c@x.com", model="gpt-4o")
    with BiasDetectionSession(
        shield=shield_a12, purpose="audit",
        necessity_justification="Synthetic test for compliance reporting suite.",
        categories_allowed={"RACE"}, max_lifetime_seconds=60,
    ) as session:
        session.pseudonymise("Asian patient", force_categories=[(0, 5, "RACE")])
        session.record_finding(
            finding_summary="no disparate impact",
            bias_metrics={"dp_diff": 0.012},
        )
    shield_a12.sanitize("Email d@x.com", model="gpt-4o")
    shield_a12.sanitize("Email e@x.com", model="gpt-4o")
    return shield_a12


# ---------------------------------------------------------------------------
# Core rollup correctness
# ---------------------------------------------------------------------------


class TestPerArticleRollup:
    def test_articles_in_scope_default_is_all_seen(self, shield_with_mixed_chain):
        r = shield_with_mixed_chain.generate_compliance_report()
        assert set(r["per_article"]) == {
            "EU_AI_Act_Art_12", "EU_AI_Act_Art_19", "EU_AI_Act_Art_4a",
        }

    def test_article_filter_includes_only_requested(self, shield_with_mixed_chain):
        r = shield_with_mixed_chain.generate_compliance_report(
            articles=["EU_AI_Act_Art_4a"],
        )
        assert set(r["per_article"]) == {"EU_AI_Act_Art_4a"}
        # And articles_in_scope is echoed back
        assert r["articles_in_scope"] == ["EU_AI_Act_Art_4a"]

    def test_article_filter_with_missing_article_yields_zero_row(
        self, shield_with_mixed_chain,
    ):
        """If the auditor asks for an article that has no events, we STILL
        show a zero-row so they see explicit coverage. Without this, an
        empty per_article row could mean 'we didn't check' instead of
        'we checked and found none'."""
        r = shield_with_mixed_chain.generate_compliance_report(
            articles=["EU_AI_Act_Art_50"],  # never present in our chain
        )
        assert "EU_AI_Act_Art_50" in r["per_article"]
        assert r["per_article"]["EU_AI_Act_Art_50"]["evidence_event_count"] == 0

    def test_event_count_per_article(self, shield_with_mixed_chain):
        r = shield_with_mixed_chain.generate_compliance_report()
        # 5 sanitize (each writes 1 entry under Art_12 + Art_19) +
        # 4 bias events (start, pseudonymise, finding, end -- each under all 3 articles)
        # Art_12 evidence events: 5 sanitize + 4 bias = 9
        # Art_19 evidence events: 5 sanitize + 4 bias = 9
        # Art_4a evidence events: 4 bias only
        assert r["per_article"]["EU_AI_Act_Art_12"]["evidence_event_count"] == 9
        assert r["per_article"]["EU_AI_Act_Art_19"]["evidence_event_count"] == 9
        assert r["per_article"]["EU_AI_Act_Art_4a"]["evidence_event_count"] == 4

    def test_bias_stats_attach_only_to_art4a(self, shield_with_mixed_chain):
        """Critical correctness: bias session events have article_ref=[Art_12,
        Art_19, Art_4a] but bias-specific stats (bias_sessions, findings_recorded,
        wipe_confirmed_pct) belong on Art_4a's row alone. Otherwise an auditor
        reading Art_12 would think 'Article 12 requires bias detection' -- it
        doesn't; Art_12 is about logging, bias detection is one TYPE of event
        you log.
        """
        r = shield_with_mixed_chain.generate_compliance_report()
        art4a = r["per_article"]["EU_AI_Act_Art_4a"]
        assert art4a.get("bias_sessions") == 1
        assert art4a.get("findings_recorded") == 1
        assert art4a.get("wipe_confirmed_pct") == 100.0
        # Critical: NOT on Art_12 or Art_19
        assert "bias_sessions" not in r["per_article"]["EU_AI_Act_Art_12"]
        assert "bias_sessions" not in r["per_article"]["EU_AI_Act_Art_19"]


# ---------------------------------------------------------------------------
# Cross-article reconciliation via decision_id
# ---------------------------------------------------------------------------


class TestDecisionIdReconciliation:
    def test_decision_count_per_article(self, shield_with_mixed_chain):
        r = shield_with_mixed_chain.generate_compliance_report()
        # 5 sanitize calls = 5 distinct decision_ids touching Art_12/Art_19.
        # Each sanitize writes one entry; sanitize creates a new decision_id per call.
        # Bias entries have decision_id=None (their anchor is bias_context.session_id).
        assert r["per_article"]["EU_AI_Act_Art_12"]["decision_count"] == 5
        assert r["per_article"]["EU_AI_Act_Art_19"]["decision_count"] == 5
        # Art_4a has no decision_id entries (bias only)
        assert r["per_article"]["EU_AI_Act_Art_4a"]["decision_count"] == 0

    def test_include_decisions_emits_per_decision_rollup(self, shield_with_mixed_chain):
        r = shield_with_mixed_chain.generate_compliance_report(include_decisions=True)
        assert "decisions" in r
        assert len(r["decisions"]) == 5
        for did, d in r["decisions"].items():
            assert d["entry_count"] >= 1
            assert "EU_AI_Act_Art_12" in d["articles_touched"]
            assert "first_timestamp" in d and "last_timestamp" in d

    def test_include_decisions_false_by_default(self, shield_with_mixed_chain):
        r = shield_with_mixed_chain.generate_compliance_report()
        assert "decisions" not in r


# ---------------------------------------------------------------------------
# JSON Schema validation (the contract)
# ---------------------------------------------------------------------------


class TestSchemaContract:
    def _validate(self, report, schema):
        try:
            import jsonschema
        except ImportError:
            pytest.skip("jsonschema not installed; can't validate the contract")
        jsonschema.validate(report, schema)

    def test_json_report_validates_against_published_schema(
        self, shield_with_mixed_chain, schema,
    ):
        r = shield_with_mixed_chain.generate_compliance_report()
        self._validate(r, schema)

    def test_report_with_decisions_validates(self, shield_with_mixed_chain, schema):
        r = shield_with_mixed_chain.generate_compliance_report(include_decisions=True)
        self._validate(r, schema)

    def test_empty_period_report_validates(self, shield_with_mixed_chain, schema):
        r = shield_with_mixed_chain.generate_compliance_report(
            period_from="2030-01-01T00:00:00+00:00",
        )
        self._validate(r, schema)
        assert r["chain_integrity"]["total_entries"] == 0
        assert r["verdict"] == "COMPLIANT"

    def test_zero_shield_chain_validates(self, shield_a12, schema):
        r = shield_a12.generate_compliance_report()
        self._validate(r, schema)


# ---------------------------------------------------------------------------
# Verdict semantics
# ---------------------------------------------------------------------------


class TestVerdict:
    def test_clean_chain_is_compliant(self, shield_with_mixed_chain):
        r = shield_with_mixed_chain.generate_compliance_report()
        assert r["verdict"] == "COMPLIANT"
        assert r["verdict_reasons"] == []

    def test_pii_in_log_flag_makes_noncompliant(self, shield_a12):
        """Synthesize an entry with pii_in_log=true and see NON_COMPLIANT."""
        # Note: we can't easily inject through the normal path (B3 validator
        # would catch it). Build the report directly from a forged entry list.
        entries = [{
            "seq": 0, "event_type": "sanitize",
            "timestamp": "2026-05-27T00:00:00+00:00",
            "article_ref": ["EU_AI_Act_Art_12"],
            "categories": {}, "pii_in_log": True,
        }]
        r = build_report(
            audit_entries=entries,
            period=ReportPeriod(from_ts=None, to_ts=None),
            cloakllm_version="0.7.1",
        )
        assert r["verdict"] == "NON_COMPLIANT"
        assert any("pii_in_log" in reason for reason in r["verdict_reasons"])

    def test_verdict_reasons_human_readable(self, shield_a12):
        entries = [{
            "seq": 0, "event_type": "sanitize",
            "timestamp": "2026-05-27T00:00:00+00:00",
            "article_ref": ["EU_AI_Act_Art_12"],
            "categories": {"EMAIL": 1}, "pii_in_log": True,
        }]
        r = build_report(
            audit_entries=entries,
            period=ReportPeriod(from_ts=None, to_ts=None),
            cloakllm_version="0.7.1",
        )
        for reason in r["verdict_reasons"]:
            # Reasons must be human-readable strings, not enum codes
            assert isinstance(reason, str) and len(reason) > 5


# ---------------------------------------------------------------------------
# Output formats
# ---------------------------------------------------------------------------


class TestMarkdownOutput:
    def test_markdown_renders(self, shield_with_mixed_chain):
        md = shield_with_mixed_chain.generate_compliance_report(format="markdown")
        assert isinstance(md, str)
        assert "# CloakLLM Compliance Report" in md
        assert "**Verdict:** **COMPLIANT**" in md
        assert "EU_AI_Act_Art_12" in md
        assert "EU_AI_Act_Art_4a" in md

    def test_markdown_writes_to_out_path(self, shield_with_mixed_chain, tmp_path):
        out = tmp_path / "report.md"
        md = shield_with_mixed_chain.generate_compliance_report(
            format="markdown", out_path=str(out),
        )
        assert out.exists()
        assert out.read_text(encoding="utf-8") == md

    def test_markdown_ascii_only_in_chrome(self, shield_with_mixed_chain):
        """The chrome / headers / labels (NOT the audit content) must be ASCII
        so the CLI doesn't crash on Windows non-UTF-8 console (the v0.7.0
        AUDIT-11 lesson). Audit content like deployer-supplied
        necessity_justification CAN contain UTF-8 -- that's deployer
        territory and not our problem to scrub."""
        md = shield_with_mixed_chain.generate_compliance_report(format="markdown")
        # Pick just the lines that are CloakLLM chrome (start with #, -, or *)
        for line in md.splitlines():
            stripped = line.strip()
            if not stripped or not stripped.startswith(("#", "-", "*", "_")):
                continue
            # Skip lines that quote backtick-delimited deployer content
            if "`" in stripped:
                continue
            try:
                stripped.encode("ascii")
            except UnicodeEncodeError:
                pytest.fail(f"non-ASCII in markdown chrome line: {line!r}")


class TestPdfOutput:
    def test_pdf_writes_a_real_pdf(self, shield_with_mixed_chain, tmp_path):
        reportlab = pytest.importorskip("reportlab")
        out = tmp_path / "report.pdf"
        result = shield_with_mixed_chain.generate_compliance_report(
            format="pdf", out_path=str(out),
        )
        assert result == str(out)
        assert out.exists()
        # PDF files start with %PDF-
        assert out.read_bytes()[:5] == b"%PDF-"

    def test_pdf_without_out_path_raises(self, shield_with_mixed_chain):
        with pytest.raises(ValueError, match="out_path"):
            shield_with_mixed_chain.generate_compliance_report(format="pdf")


class TestUnknownFormat:
    def test_rejects_unknown_format(self, shield_with_mixed_chain):
        with pytest.raises(ValueError, match="Unknown report format"):
            shield_with_mixed_chain.generate_compliance_report(format="xml")


# ---------------------------------------------------------------------------
# v0.8.1 forward-compat: attestation block shape
# ---------------------------------------------------------------------------


class TestAttestationForwardCompat:
    """The v0.8.0 attestation block emits the v0.8.1 ProvenanceReport shape
    with manifest-derived fields stubbed null. v0.8.1 fills them in.
    Zero schema break across the boundary."""

    def test_attestation_schema_version_is_1_0(self, shield_with_mixed_chain):
        r = shield_with_mixed_chain.generate_compliance_report()
        assert r["attestation"]["schema_version"] == ATTESTATION_SCHEMA_VERSION == "1.0"

    def test_provenance_summary_slot_present_with_nulls(self, shield_with_mixed_chain):
        r = shield_with_mixed_chain.generate_compliance_report()
        ps = r["attestation"]["provenance_summary"]
        # All four KeyManifest-derived fields present, all null in v0.8.0
        assert "manifests_found" in ps and ps["manifests_found"] is None
        assert "manifests_valid" in ps and ps["manifests_valid"] is None
        assert "within_validity_window_pct" in ps and ps["within_validity_window_pct"] is None
        assert "root_signature_status_distribution" in ps
        assert ps["root_signature_status_distribution"] is None


# ---------------------------------------------------------------------------
# CR8-9: compliance_summary() updated fields
# ---------------------------------------------------------------------------


class TestComplianceSummaryV080Fields:
    def test_decision_id_enabled_always_true(self, shield_a12):
        s = shield_a12.compliance_summary()
        assert s["config_snapshot"]["decision_id_enabled"] is True

    def test_system_version_pin_configured_true_when_both_set(self, shield_a12):
        s = shield_a12.compliance_summary()
        assert s["config_snapshot"]["system_version_pin_configured"] is True

    def test_system_version_pin_configured_false_when_partial(self, tmp_path):
        cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            cfg = ShieldConfig(
                log_dir=str(tmp_path / "audit"),
                compliance_mode="eu_ai_act_article12",
                deployment_version="prod-2026",
                # instruction_version missing
            )
            shield = Shield(config=cfg)
            s = shield.compliance_summary()
            assert s["config_snapshot"]["system_version_pin_configured"] is False
        finally:
            os.chdir(cwd)

    def test_compliance_reporting_available(self, shield_a12):
        s = shield_a12.compliance_summary()
        assert s["config_snapshot"]["compliance_reporting_available"] is True


# v0.8.0 AUDIT-3: build_report() must not crash on hand-crafted malformed
# audit entries (wrong types, missing keys, NUL bytes in fields). Producers
# always emit well-formed JSON, but a deployer might hand-load a corrupted
# JSONL file and we must not die at parse time -- skip malformed rows.
class TestBuildReportAdversarialInputs:
    def _adversarial_entries(self):
        return [
            # Minimal valid
            {"seq": 0, "timestamp": "2026-05-30T12:00:00+00:00",
             "article_ref": ["EU_AI_Act_Art_12"]},
            # Missing everything
            {"seq": 1},
            # Explicit nulls
            {"timestamp": None, "article_ref": None},
            # Wrong types: int timestamp would crash ts<ts comparison pre-fix
            {"seq": "string", "timestamp": 42, "article_ref": "not-a-list"},
            # Empty
            {},
            # Boolean pii_in_log on entry with no articles
            {"seq": 5, "timestamp": "2026-05-30T12:00:00+00:00",
             "article_ref": [], "pii_in_log": True},
        ]

    def test_does_not_crash_on_malformed_entries(self):
        r = build_report(
            audit_entries=self._adversarial_entries(),
            period=ReportPeriod(None, None),
            cloakllm_version="0.8.0",
        )
        # v0.10.3 MEDIUM-6: the adversarial set includes a pii_in_log=true entry
        # (seq 5) with empty article_ref. Pre-fix this was silently ignored
        # (no per_article row -> COMPLIANT) -- the exact bug. The no-PII-in-logs
        # invariant is global, so the verdict must now be NON_COMPLIANT. The
        # test's purpose (no crash on malformed input) still holds.
        assert r["verdict"] == "NON_COMPLIANT"
        assert any("pii_in_log=true" in x for x in r["verdict_reasons"])
        # Only the 2 entries with valid string timestamps + valid article_ref
        # list count toward total.
        assert r["chain_integrity"]["total_entries"] == 2

    def test_does_not_crash_with_include_decisions(self):
        r = build_report(
            audit_entries=self._adversarial_entries(),
            period=ReportPeriod(None, None),
            cloakllm_version="0.8.0",
            include_decisions=True,
        )
        assert "decisions" in r

    def test_nul_byte_timestamp_does_not_crash(self):
        r = build_report(
            audit_entries=[
                {"seq": 0,
                 "timestamp": "2026-05-30T12:00:00\x00+00:00",
                 "article_ref": ["X"]},
            ],
            period=ReportPeriod(None, None),
            cloakllm_version="0.8.0",
        )
        assert r["chain_integrity"]["total_entries"] == 1

    def test_string_article_ref_does_not_corrupt_per_article(self):
        # Pre-fix, a string article_ref="ABC" would iterate as 'A','B','C'
        # and create three bogus articles. After fix: skipped as non-list.
        r = build_report(
            audit_entries=[
                {"seq": 0,
                 "timestamp": "2026-05-30T12:00:00+00:00",
                 "article_ref": "EU_AI_Act_Art_12"},  # string, not list
            ],
            period=ReportPeriod(None, None),
            cloakllm_version="0.8.0",
        )
        assert r["per_article"] == {}


# v0.8.1 KM-9: ProvenanceReport aggregator wires into attestation.provenance_summary
class TestProvenanceSummary:
    def test_pre_v081_chain_stays_null(self):
        """v0.8.0 chains have no key_registered events -> all 4 fields null."""
        entries = [
            {"seq": 0, "timestamp": "2026-05-30T12:00:00+00:00",
             "event_type": "sanitize", "article_ref": ["EU_AI_Act_Art_12"],
             "key_id": "k1", "certificate_hash": "h0"},
        ]
        r = build_report(audit_entries=entries,
            period=ReportPeriod(None, None), cloakllm_version="0.8.1")
        ps = r["attestation"]["provenance_summary"]
        assert ps["manifests_found"] is None
        assert ps["manifests_valid"] is None
        assert ps["within_validity_window_pct"] is None
        assert ps["root_signature_status_distribution"] is None

    def test_v081_chain_fills_fields(self, tmp_path):
        kp = DeploymentKeyPair.generate()
        cfg = ShieldConfig(
            audit_enabled=True, log_dir=str(tmp_path),
            compliance_mode="eu_ai_act_article12", attestation_key=kp,
            deployer_id="acme",
            key_valid_from="2026-01-01T00:00:00+00:00",
            key_valid_until="2027-01-01T00:00:00+00:00",
        )
        sh = Shield(config=cfg)
        sh.sanitize("email a@b.com")
        sh.sanitize("email c@d.com")
        rep = sh.generate_compliance_report()
        ps = rep["attestation"]["provenance_summary"]
        assert ps["manifests_found"] == 1
        assert ps["manifests_valid"] == 1
        assert ps["root_signature_status_distribution"]["NOT_REQUESTED"] == 1


# Need imports at top -- pytest will resolve
from cloakllm import DeploymentKeyPair


# ===================================================================
# v0.10.3: cross-SDK parity for wipe_confirmed_pct + within_validity_window_pct
# (both now route through the exact-integer _pct -- regression guard against
# the banker's-vs-half-up divergence found post-v0.10.0).
# ===================================================================

from cloakllm.compliance_report import build_report, ReportPeriod, _pct


def _bias_entry(seq, etype, **bc):
    return dict(
        seq=seq, event_id="e%d" % seq, timestamp="2026-05-01T10:00:0%d.000000+00:00" % (seq % 10),
        event_type=etype, model=None, provider=None, entity_count=0, categories={},
        tokens_used=[], prompt_hash="", sanitized_hash="", latency_ms=0, mode=None,
        entity_details=[], timing=None, certificate_hash=None, key_id=None,
        prev_hash="0" * 64, entry_hash="x", metadata={}, risk_assessment=None,
        article_ref=["EU_AI_Act_Art_12", "EU_AI_Act_Art_19", "EU_AI_Act_Art_4a"],
        decision_id="d%d" % seq, bias_context=bc,
    )


class TestWipeConfirmedPctParityV0103:
    def test_fractional_wipe_is_two_dp_half_up(self):
        # 1 of 3 wiped -> 33.33 (was Py 33.33 vs JS 33.3 under the old 1dp path)
        entries = [
            _bias_entry(0, "bias_session_start", session_id="s0", purpose="audit"),
            _bias_entry(1, "bias_session_start", session_id="s1", purpose="audit"),
            _bias_entry(2, "bias_session_start", session_id="s2", purpose="audit"),
            _bias_entry(3, "bias_session_end", session_id="s0", wipe_confirmed=True),
            _bias_entry(4, "bias_session_end", session_id="s1", wipe_confirmed=False),
            _bias_entry(5, "bias_session_end", session_id="s2", wipe_confirmed=False),
        ]
        rep = build_report(audit_entries=entries, period=ReportPeriod(None, None),
                           cloakllm_version="0.10.3")
        assert rep["per_article"]["EU_AI_Act_Art_4a"]["wipe_confirmed_pct"] == 33.33

    def test_full_wipe_is_int_100(self):
        entries = [
            _bias_entry(0, "bias_session_start", session_id="s0", purpose="audit"),
            _bias_entry(1, "bias_session_end", session_id="s0", wipe_confirmed=True),
        ]
        rep = build_report(audit_entries=entries, period=ReportPeriod(None, None),
                           cloakllm_version="0.10.3")
        v = rep["per_article"]["EU_AI_Act_Art_4a"]["wipe_confirmed_pct"]
        assert v == 100 and isinstance(v, int)


class TestWithinWindowPctParityV0103:
    def test_routes_through_pct_helper(self):
        # The provenance fill uses _pct now; the half-way boundary value is the
        # cross-SDK contract (1 of 800 -> 0.13, was 0.12 under banker's round()).
        assert _pct(1, 800) == 0.13
        assert _pct(0, 0) == 0
