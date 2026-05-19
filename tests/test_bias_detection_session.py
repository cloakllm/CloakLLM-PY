"""v0.7.0 A4a-7: BiasDetectionSession test suite.

Covers the Article 4a workflow end-to-end:

  * Session lifecycle (construction, start, pseudonymise, finding, end, wipe)
  * Constructor validation (purpose / necessity_justification / categories /
    lifetime caps)
  * Article 4a safeguards #1–#6, individually + together
  * Audit-chain shape: 4 new event types appear, B3 schema passes, chain
    verifies, `article_ref` includes EU_AI_Act_Art_4a
  * Lifetime enforcement (BiasDetectionTimeoutError + auto-wipe)
  * Scope enforcement (BiasDetectionScopeError on out-of-set categories)
  * State enforcement (operations after end raise BiasDetectionStateError)
  * Integration with compliance_mode enforcement (requires Article 12)

Test isolation: each test gets its own tempdir-rooted Shield/AuditLogger so
the chain state never bleeds across tests.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

import pytest

from cloakllm import (
    BiasDetectionError,
    BiasDetectionScopeError,
    BiasDetectionSession,
    BiasDetectionStateError,
    BiasDetectionTimeoutError,
    Shield,
    ShieldConfig,
    SPECIAL_CATEGORY_CATEGORIES,
)


@pytest.fixture
def shield_a12(tmp_path: Path) -> Shield:
    """Shield in compliance_mode=eu_ai_act_article12, log dir under tmp_path."""
    cwd_before = Path.cwd()
    os.chdir(tmp_path)
    try:
        cfg = ShieldConfig(
            log_dir=str(tmp_path / "audit"),
            compliance_mode="eu_ai_act_article12",
        )
        yield Shield(config=cfg)
    finally:
        os.chdir(cwd_before)


@pytest.fixture
def session_kwargs() -> dict:
    """Canonical valid set of session-construction args."""
    return {
        "purpose": "Pre-deployment fairness audit of credit-scoring model v3.2",
        "necessity_justification": (
            "Synthetic data evaluated and rejected — covariance between "
            "protected characteristics and credit history not preserved. "
            "See internal report XYZ-2026-04."
        ),
        "categories_allowed": {"RACE", "ETHNICITY", "RELIGION"},
        "max_lifetime_seconds": 3600,
    }


# ---------------------------------------------------------------------------
# Lifecycle
# ---------------------------------------------------------------------------


class TestLifecycle:
    def test_full_workflow_chain_verifies(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            text = "Patient identifies as Asian and practices Buddhism."
            pseudo, counts = session.pseudonymise(
                text,
                force_categories=[(22, 27, "RACE"), (42, 50, "RELIGION")],
            )
            assert "[RACE_0]" in pseudo
            assert "[RELIGION_0]" in pseudo
            assert counts == {"RACE": 1, "RELIGION": 1}
            session.record_finding(
                finding_summary="No disparate impact detected.",
                bias_metrics={"demographic_parity_diff": 0.012, "n": 5000},
            )

        assert session.closed is True
        # Wipe occurred.
        assert session._token_map is None

        result = shield_a12.verify_audit()
        assert result["valid"] is True, result
        # 4 entries: start, pseudonymise, finding, end
        assert result["final_seq"] == 3

    def test_deterministic_tokens_within_session(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            text = "Asian. Asian. Asian."  # same span repeated
            spans = [(0, 5, "RACE"), (7, 12, "RACE"), (14, 19, "RACE")]
            pseudo, counts = session.pseudonymise(text, force_categories=spans)
            # Three RACE detections; same value → same token by determinism.
            assert pseudo == "[RACE_0]. [RACE_0]. [RACE_0]."
            assert counts == {"RACE": 3}

    def test_explicit_end_is_idempotent(self, shield_a12, session_kwargs):
        s = BiasDetectionSession(shield=shield_a12, **session_kwargs)
        s.start()
        s.end()
        # Second .end() must be a no-op (does not double-log).
        s.end()
        assert s.closed is True
        # Chain has start + end (no pseudonymise this time).
        result = shield_a12.verify_audit()
        assert result["valid"] is True
        # seq 0 = start, seq 1 = end
        assert result["final_seq"] == 1

    def test_start_idempotent_does_not_double_log(self, shield_a12, session_kwargs):
        s = BiasDetectionSession(shield=shield_a12, **session_kwargs)
        s.start()
        s.start()
        s.start()
        s.end()
        result = shield_a12.verify_audit()
        # Should be exactly 2 entries: one start, one end.
        assert result["final_seq"] == 1

    def test_pseudonymise_before_start_raises(self, shield_a12, session_kwargs):
        s = BiasDetectionSession(shield=shield_a12, **session_kwargs)
        with pytest.raises(BiasDetectionStateError):
            s.pseudonymise("x", force_categories=[(0, 1, "RACE")])

    def test_record_finding_before_start_raises(self, shield_a12, session_kwargs):
        s = BiasDetectionSession(shield=shield_a12, **session_kwargs)
        with pytest.raises(BiasDetectionStateError):
            s.record_finding(finding_summary="anything")

    def test_no_re_entry_after_end(self, shield_a12, session_kwargs):
        s = BiasDetectionSession(shield=shield_a12, **session_kwargs)
        s.start()
        s.end()
        with pytest.raises(BiasDetectionStateError):
            s.start()

    def test_operations_after_end_raise(self, shield_a12, session_kwargs):
        s = BiasDetectionSession(shield=shield_a12, **session_kwargs)
        with s:
            pass
        with pytest.raises(BiasDetectionStateError):
            s.pseudonymise("x", force_categories=[(0, 1, "RACE")])
        with pytest.raises(BiasDetectionStateError):
            s.record_finding(finding_summary="x")


# ---------------------------------------------------------------------------
# Constructor validation
# ---------------------------------------------------------------------------


class TestConstructorValidation:
    def test_rejects_non_shield_instance(self, session_kwargs):
        with pytest.raises(TypeError):
            BiasDetectionSession(shield="not-a-shield", **session_kwargs)

    def test_requires_compliance_mode_article12(self, tmp_path, session_kwargs):
        os.chdir(tmp_path)
        cfg = ShieldConfig(log_dir=str(tmp_path / "audit"))  # NO compliance_mode
        shield = Shield(config=cfg)
        with pytest.raises(BiasDetectionError, match="compliance_mode"):
            BiasDetectionSession(shield=shield, **session_kwargs)

    @pytest.mark.parametrize("bad_purpose", ["", "   ", None, 42])
    def test_rejects_empty_or_non_string_purpose(
        self, shield_a12, session_kwargs, bad_purpose,
    ):
        kw = dict(session_kwargs, purpose=bad_purpose)
        with pytest.raises((ValueError, TypeError)):
            BiasDetectionSession(shield=shield_a12, **kw)

    def test_rejects_overlong_purpose(self, shield_a12, session_kwargs):
        kw = dict(session_kwargs, purpose="x" * 501)
        with pytest.raises(ValueError, match=r"500"):
            BiasDetectionSession(shield=shield_a12, **kw)

    def test_rejects_overlong_necessity_justification(self, shield_a12, session_kwargs):
        kw = dict(session_kwargs, necessity_justification="x" * 2001)
        with pytest.raises(ValueError, match=r"2000"):
            BiasDetectionSession(shield=shield_a12, **kw)

    def test_rejects_empty_categories_allowed(self, shield_a12, session_kwargs):
        kw = dict(session_kwargs, categories_allowed=set())
        with pytest.raises(ValueError, match="non-empty"):
            BiasDetectionSession(shield=shield_a12, **kw)

    def test_rejects_non_special_category_in_allowed(self, shield_a12, session_kwargs):
        kw = dict(session_kwargs, categories_allowed={"RACE", "EMAIL"})
        with pytest.raises(ValueError, match="non-special-category"):
            BiasDetectionSession(shield=shield_a12, **kw)

    def test_rejects_missing_max_lifetime_seconds(self, shield_a12, session_kwargs):
        kw = dict(session_kwargs)
        del kw["max_lifetime_seconds"]
        with pytest.raises(TypeError):
            BiasDetectionSession(shield=shield_a12, **kw)

    @pytest.mark.parametrize("bad_lifetime", [0, -1, 1.5, "3600", True])
    def test_rejects_invalid_lifetime_types(
        self, shield_a12, session_kwargs, bad_lifetime,
    ):
        kw = dict(session_kwargs, max_lifetime_seconds=bad_lifetime)
        with pytest.raises((ValueError, TypeError)):
            BiasDetectionSession(shield=shield_a12, **kw)

    def test_rejects_lifetime_above_7d_ceiling(self, shield_a12, session_kwargs):
        kw = dict(session_kwargs, max_lifetime_seconds=7 * 24 * 60 * 60 + 1)
        with pytest.raises(ValueError, match="7 days"):
            BiasDetectionSession(shield=shield_a12, **kw)


# ---------------------------------------------------------------------------
# Scope enforcement (safeguard #4)
# ---------------------------------------------------------------------------


class TestScopeEnforcement:
    def test_pseudonymise_rejects_out_of_set_category(self, shield_a12, session_kwargs):
        kw = dict(session_kwargs, categories_allowed={"RACE"})
        with BiasDetectionSession(shield=shield_a12, **kw) as session:
            with pytest.raises(BiasDetectionScopeError, match="not in this session"):
                session.pseudonymise(
                    "Buddhist patient.",
                    force_categories=[(0, 8, "RELIGION")],
                )

    def test_scope_error_does_not_alter_state(self, shield_a12, session_kwargs):
        """A scope-rejected call must NOT touch the token map OR audit chain
        (audit entry would constitute a half-completed pseudonymisation)."""
        kw = dict(session_kwargs, categories_allowed={"RACE"})
        with BiasDetectionSession(shield=shield_a12, **kw) as session:
            with pytest.raises(BiasDetectionScopeError):
                session.pseudonymise(
                    "Buddhist patient.",
                    force_categories=[(0, 8, "RELIGION")],
                )
            # State unchanged: token map still empty.
            assert len(session._token_map.forward) == 0
            assert session.entries_processed == 0

        # Only 2 audit entries (start + end), no pseudonymise.
        result = shield_a12.verify_audit()
        assert result["valid"] is True
        assert result["final_seq"] == 1

    def test_rejects_span_beyond_text_length(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            with pytest.raises(ValueError, match="exceeds text length"):
                session.pseudonymise("abc", force_categories=[(0, 10, "RACE")])


# ---------------------------------------------------------------------------
# Lifetime enforcement (safeguard #5)
# ---------------------------------------------------------------------------


class TestLifetime:
    def test_timeout_force_ends_and_raises(self, shield_a12, session_kwargs, monkeypatch):
        """When time has advanced past max_lifetime_seconds, the next
        operation force-ends the session and raises BiasDetectionTimeoutError."""
        kw = dict(session_kwargs, max_lifetime_seconds=1)
        session = BiasDetectionSession(shield=shield_a12, **kw)
        session.start()
        # Move the monotonic clock forward by patching the module's
        # `_utcnow_seconds` helper. (We can't sleep — too slow for CI.)
        from cloakllm import bias_detection as bd_mod
        real_start = session._started_at_monotonic

        def _fast_forward():
            return real_start + 10.0  # 10 s past start
        monkeypatch.setattr(bd_mod, "_utcnow_seconds", _fast_forward)

        with pytest.raises(BiasDetectionTimeoutError, match="max_lifetime_seconds"):
            session.pseudonymise(
                "Asian patient.",
                force_categories=[(0, 5, "RACE")],
            )
        # Session was force-ended + wiped.
        assert session.closed is True
        assert session._token_map is None

    def test_timeout_logs_exit_reason_timeout(self, shield_a12, session_kwargs, monkeypatch):
        kw = dict(session_kwargs, max_lifetime_seconds=1)
        session = BiasDetectionSession(shield=shield_a12, **kw)
        session.start()
        from cloakllm import bias_detection as bd_mod
        real_start = session._started_at_monotonic
        monkeypatch.setattr(bd_mod, "_utcnow_seconds", lambda: real_start + 10.0)

        with pytest.raises(BiasDetectionTimeoutError):
            session.record_finding(finding_summary="any")

        # Inspect the audit chain: end entry must have exit_reason=timeout.
        log_dir = shield_a12.config.log_dir
        files = sorted(Path(log_dir).glob("audit_*.jsonl"))
        last_entry = json.loads(files[-1].read_text().strip().splitlines()[-1])
        assert last_entry["event_type"] == "bias_session_end"
        assert last_entry["bias_context"]["exit_reason"] == "timeout"
        assert last_entry["bias_context"]["wipe_confirmed"] is True


# ---------------------------------------------------------------------------
# Audit-chain shape (A4a-3 invariants)
# ---------------------------------------------------------------------------


class TestAuditChain:
    def _read_entries(self, shield):
        log_dir = shield.config.log_dir
        files = sorted(Path(log_dir).glob("audit_*.jsonl"))
        entries = []
        for fp in files:
            for line in fp.read_text().splitlines():
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
        return entries

    def test_all_four_event_types_appear(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            session.pseudonymise(
                "Asian patient.", force_categories=[(0, 5, "RACE")],
            )
            session.record_finding(
                finding_summary="fine", bias_metrics={"score": 0.0},
            )
        entries = self._read_entries(shield_a12)
        event_types = [e["event_type"] for e in entries]
        assert event_types == [
            "bias_session_start",
            "bias_pseudonymise",
            "bias_finding",
            "bias_session_end",
        ]

    def test_bias_events_have_article_4a_in_article_ref(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            session.pseudonymise(
                "Asian patient.", force_categories=[(0, 5, "RACE")],
            )
        entries = self._read_entries(shield_a12)
        for e in entries:
            if e["event_type"].startswith("bias_"):
                assert "EU_AI_Act_Art_4a" in e["article_ref"]
                # Article 12 invariant still satisfied.
                assert "EU_AI_Act_Art_12" in e["article_ref"]
                assert e["pii_in_log"] is False
                assert e["compliance_version"] == "eu_ai_act_article12_v1"

    def test_bias_context_carries_session_id_on_every_event(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            sid = session.session_id
            session.pseudonymise("Asian.", force_categories=[(0, 5, "RACE")])
            session.record_finding(finding_summary="ok")

        entries = self._read_entries(shield_a12)
        for e in entries:
            if e["event_type"].startswith("bias_"):
                assert e["bias_context"]["session_id"] == sid

    def test_start_entry_carries_purpose_and_necessity(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            pass
        entries = self._read_entries(shield_a12)
        start = entries[0]
        ctx = start["bias_context"]
        assert ctx["purpose"] == session_kwargs["purpose"]
        assert ctx["necessity_justification"] == session_kwargs["necessity_justification"]
        assert ctx["categories_allowed"] == sorted(session_kwargs["categories_allowed"])
        assert ctx["max_lifetime_seconds"] == session_kwargs["max_lifetime_seconds"]

    def test_end_entry_records_wipe_and_count(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            session.pseudonymise("Asian.", force_categories=[(0, 5, "RACE")])
            session.pseudonymise("Asian.", force_categories=[(0, 5, "RACE")])
        entries = self._read_entries(shield_a12)
        end = entries[-1]
        assert end["bias_context"]["wipe_confirmed"] is True
        assert end["bias_context"]["entries_processed"] == 2
        assert end["bias_context"]["exit_reason"] == "clean"

    def test_exception_inside_with_block_logs_exit_reason_error(
        self, shield_a12, session_kwargs,
    ):
        with pytest.raises(RuntimeError, match="boom"):
            with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
                session.pseudonymise("Asian.", force_categories=[(0, 5, "RACE")])
                raise RuntimeError("boom")
        entries = self._read_entries(shield_a12)
        end = entries[-1]
        assert end["bias_context"]["exit_reason"] == "error"
        # Wipe must still have happened.
        assert end["bias_context"]["wipe_confirmed"] is True

    def test_chain_verifies_with_bias_entries(self, shield_a12, session_kwargs):
        # Mix a regular sanitize call before and after a bias session — the
        # chain links must hold across the event-type boundary.
        shield_a12.sanitize("Contact john@example.com.")
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            session.pseudonymise("Asian.", force_categories=[(0, 5, "RACE")])
            session.record_finding(finding_summary="fine")
        shield_a12.sanitize("Contact jane@example.com.")
        result = shield_a12.verify_audit()
        assert result["valid"] is True, result

    def test_bias_context_does_not_contain_pii(self, shield_a12, session_kwargs):
        # Sanity: even with PII in input text, the audit entries' bias_context
        # never carries source content (the B3 invariant + bias_context shape).
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            session.pseudonymise(
                "Asian patient",
                force_categories=[(0, 5, "RACE")],
            )
        entries = self._read_entries(shield_a12)
        serialized = json.dumps(entries)
        assert "Asian patient" not in serialized
        assert "Asian" not in serialized.replace("RACE", "")  # value never appears

    def test_compliance_report_includes_bias_entries(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            session.pseudonymise("Asian.", force_categories=[(0, 5, "RACE")])
            session.record_finding(finding_summary="fine")
        report = shield_a12.verify_audit(output_format="compliance_report")
        assert report["verdict"] == "COMPLIANT"
        # All 4 bias entries counted as compliance-mode entries.
        assert report["compliance_mode_entries"] == 4
        assert report["chain_integrity"] == "verified"


# ---------------------------------------------------------------------------
# Safeguard composition: all 6 together
# ---------------------------------------------------------------------------


class TestSafeguardComposition:
    """One scenario that exercises all six Article 4a safeguards together."""

    def test_end_to_end_all_safeguards(self, shield_a12, session_kwargs):
        # Safeguard #4 enforcement: explicit categories set.
        # Safeguard #5: lifetime bounded.
        kw = dict(
            session_kwargs,
            categories_allowed={"RACE", "ETHNICITY"},
            max_lifetime_seconds=3600,
        )
        with BiasDetectionSession(shield=shield_a12, **kw) as session:
            # Safeguard #2 (pseudonymisation) + #3 (in-memory only).
            text = "Asian Latino"
            pseudo, _ = session.pseudonymise(
                text,
                force_categories=[(0, 5, "RACE"), (6, 12, "ETHNICITY")],
            )
            assert "[RACE_0]" in pseudo and "[ETHNICITY_0]" in pseudo
            # Safeguard #4: out-of-scope rejected.
            with pytest.raises(BiasDetectionScopeError):
                session.pseudonymise("Buddhist.", force_categories=[(0, 8, "RELIGION")])
            # Safeguard #6: justification + finding recorded.
            session.record_finding(
                finding_summary="No disparate impact.",
                bias_metrics={"max_dp_diff": 0.012},
            )

        # Safeguard #5: wipe occurred on exit.
        assert session._token_map is None
        # Safeguard #1: necessity_justification logged.
        log_dir = shield_a12.config.log_dir
        files = sorted(Path(log_dir).glob("audit_*.jsonl"))
        start_entry = json.loads(files[-1].read_text().splitlines()[0])
        assert start_entry["bias_context"]["necessity_justification"] == (
            session_kwargs["necessity_justification"]
        )

        # All entries Article 12 + Article 4a compliant.
        result = shield_a12.verify_audit(output_format="compliance_report")
        assert result["verdict"] == "COMPLIANT"


# ---------------------------------------------------------------------------
# Special-category token registry (A4a-2)
# ---------------------------------------------------------------------------


class TestSpecialCategoryRegistry:
    EXPECTED = {
        "RACE", "ETHNICITY", "RELIGION", "POLITICAL_OPINION",
        "HEALTH_BIOMETRIC", "SEXUAL_ORIENTATION", "TRADE_UNION", "GENETIC",
    }

    def test_eight_categories_registered(self):
        assert SPECIAL_CATEGORY_CATEGORIES == self.EXPECTED

    def test_all_in_builtin_categories(self):
        from cloakllm import BUILTIN_CATEGORIES
        assert self.EXPECTED.issubset(BUILTIN_CATEGORIES)

    @pytest.mark.parametrize("cat", sorted(EXPECTED))
    def test_category_name_format_valid(self, cat):
        from cloakllm import validate_category_name
        assert validate_category_name(cat)

    @pytest.mark.parametrize("cat", sorted(EXPECTED))
    def test_token_format_compliant(self, cat):
        from cloakllm import validate_token
        assert validate_token(f"[{cat}_0]")
        assert validate_token(f"[{cat}_REDACTED]")

    def test_regex_pass_does_not_auto_detect(self, tmp_path):
        """The regex backend must NOT auto-produce special-category tokens
        even when the text contains terms like 'Asian', 'Buddhist', etc.
        (Article 4a workflow requires explicit declaration.)"""
        cwd_before = Path.cwd()
        os.chdir(tmp_path)
        try:
            cfg = ShieldConfig(log_dir=str(tmp_path / "audit"))
            shield = Shield(config=cfg)
            text = "Asian Buddhist Catholic Jewish Democrat Republican"
            sanitized, tm = shield.sanitize(text)
            for cat in self.EXPECTED:
                assert f"[{cat}_" not in sanitized, (
                    f"Regex pass auto-detected special category {cat}: "
                    f"{sanitized!r}"
                )
        finally:
            os.chdir(cwd_before)


# ---------------------------------------------------------------------------
# v0.7.0 SECURITY-13: new-code security hardenings
# ---------------------------------------------------------------------------


class TestSecurity13Hardenings:
    """Three hardenings added during the pre-release security audit:
       1. Reject Unicode bidi formatting chars (auditor visual-spoofing defense)
       2. Cap bias_metrics at 64 keys (per-entry log-volume DoS defense)
       3. Cap force_categories at 1024 spans/call (memory DoS defense)
    """

    def test_bidi_rlo_rejected_in_purpose(self, shield_a12, session_kwargs):
        # U+202E Right-to-Left Override -- the classic spoofing vector
        kw = dict(session_kwargs, purpose="audit‮evil")
        with pytest.raises(ValueError, match="bidi formatting"):
            BiasDetectionSession(shield=shield_a12, **kw)

    def test_bidi_lro_rejected_in_purpose(self, shield_a12, session_kwargs):
        kw = dict(session_kwargs, purpose="audit‭evil")
        with pytest.raises(ValueError, match="bidi formatting"):
            BiasDetectionSession(shield=shield_a12, **kw)

    def test_bidi_rejected_in_necessity_justification(self, shield_a12, session_kwargs):
        kw = dict(session_kwargs, necessity_justification="approve‮reject. " + "x" * 30)
        with pytest.raises(ValueError, match="bidi formatting"):
            BiasDetectionSession(shield=shield_a12, **kw)

    def test_bidi_rejected_in_finding_summary(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            with pytest.raises(ValueError, match="bidi formatting"):
                session.record_finding(
                    finding_summary="finding‮text",
                )

    def test_clean_ascii_passes(self, shield_a12, session_kwargs):
        # Sanity: legitimate ASCII strings don't false-positive
        kw = dict(
            session_kwargs,
            purpose="Pre-deployment fairness audit (clean ASCII)",
            necessity_justification="Synthetic data evaluated and rejected. See report.",
        )
        with BiasDetectionSession(shield=shield_a12, **kw) as session:
            session.record_finding(finding_summary="No disparate impact detected.")

    def test_force_categories_cap_enforced(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            # 1025 spans (over the 1024 cap) on a wide-enough text
            spans = [(i, i + 1, "RACE") for i in range(1025)]
            text = "x" * 2000
            with pytest.raises(ValueError, match="1024 spans"):
                session.pseudonymise(text, force_categories=spans)

    def test_force_categories_at_cap_accepted(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            spans = [(i, i + 1, "RACE") for i in range(1024)]
            text = "x" * 2000
            pseudo, counts = session.pseudonymise(text, force_categories=spans)
            assert counts == {"RACE": 1024}

    def test_bias_metrics_64_key_cap(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            big_metrics = {f"k{i}": i for i in range(65)}
            with pytest.raises(RuntimeError, match="64 keys"):
                session.record_finding(
                    finding_summary="too many",
                    bias_metrics=big_metrics,
                )

    def test_bias_metrics_at_cap_accepted(self, shield_a12, session_kwargs):
        with BiasDetectionSession(shield=shield_a12, **session_kwargs) as session:
            big_metrics = {f"k{i}": i for i in range(64)}
            session.record_finding(
                finding_summary="exactly at cap",
                bias_metrics=big_metrics,
            )
