"""v0.7.1 C7.1-1 / C7.1-2 / C7.1-4 / C7.1-5: regression tests for the
six items in `PLAN_v080.md` § v0.7.1.

  - decision_id field (auto-gen ULID, caller-supplied, propagation, B3 caps)
  - system_version_pin field (composition, partial-component handling, B3 caps)
  - legacy_canonical sunset (DeprecationWarning emitted per call)
  - Shield.analyze() default flip (no warning when omitted, default is True)
"""

from __future__ import annotations

import json
import os
import tempfile
import warnings
from pathlib import Path

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm._ulid import (
    ULID_LENGTH,
    generate_ulid,
    is_valid_decision_id,
)


@pytest.fixture
def shield_a12(tmp_path):
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


@pytest.fixture
def shield_a12_with_pin(tmp_path):
    cwd = Path.cwd()
    os.chdir(tmp_path)
    try:
        cfg = ShieldConfig(
            log_dir=str(tmp_path / "audit"),
            compliance_mode="eu_ai_act_article12",
            deployment_version="prod-2026-05-19",
            instruction_version="sysprompt-v3.2",
        )
        yield Shield(config=cfg)
    finally:
        os.chdir(cwd)


def _read_entries(shield):
    files = sorted(Path(shield.config.log_dir).glob("audit_*.jsonl"))
    out = []
    for fp in files:
        for line in fp.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


# ---------------------------------------------------------------------------
# C7.1-1: ULID generator
# ---------------------------------------------------------------------------


class TestUlidGenerator:
    def test_ulid_length(self):
        u = generate_ulid()
        assert len(u) == ULID_LENGTH == 26

    def test_ulid_is_valid_decision_id(self):
        u = generate_ulid()
        assert is_valid_decision_id(u)

    def test_ulids_are_unique(self):
        # 1000 ULIDs should all be distinct (80-bit randomness collision is
        # astronomically unlikely)
        ulids = {generate_ulid() for _ in range(1000)}
        assert len(ulids) == 1000

    def test_ulids_sort_chronologically(self):
        # Sort property: lex sort = chronological order across calls separated
        # by ms (within a single ms order is random; we sleep 2ms between).
        import time
        a = generate_ulid()
        time.sleep(0.002)
        b = generate_ulid()
        time.sleep(0.002)
        c = generate_ulid()
        assert a < b < c

    def test_ulid_uses_crockford_alphabet(self):
        u = generate_ulid()
        ALLOWED = set("0123456789ABCDEFGHJKMNPQRSTVWXYZ")
        assert all(c in ALLOWED for c in u)

    @pytest.mark.parametrize("good", [
        "01HX3FXYZ",                  # short
        "01ARZ3NDEKTSV4RRFFQ69G5FAV",  # full ULID
        "uuid-style-v4-12345678-abcd",  # caller-supplied UUID-ish
        "decision_42",
    ])
    def test_is_valid_decision_id_accepts(self, good):
        assert is_valid_decision_id(good)

    @pytest.mark.parametrize("bad", [
        "",                           # empty
        "x" * 65,                     # > 64 chars
        "has\x00nul",                 # NUL byte
        "has\ttab",                   # control char
        "audit‮evil",            # bidi-formatting (SECURITY-13)
        42,                           # non-string
        None,
    ])
    def test_is_valid_decision_id_rejects(self, bad):
        assert not is_valid_decision_id(bad)


# ---------------------------------------------------------------------------
# C7.1-1: decision_id end-to-end
# ---------------------------------------------------------------------------


class TestDecisionId:
    def test_auto_generated_decision_id_on_sanitize(self, shield_a12):
        _, tm = shield_a12.sanitize("Email john@example.com")
        assert tm.decision_id is not None
        assert len(tm.decision_id) == 26

    def test_caller_supplied_decision_id_accepted(self, shield_a12):
        _, tm = shield_a12.sanitize("Email john@example.com", decision_id="custom-abc")
        assert tm.decision_id == "custom-abc"

    def test_decision_id_propagates_to_desanitize(self, shield_a12):
        sanitized, tm = shield_a12.sanitize("Email john@example.com")
        sid = tm.decision_id
        shield_a12.desanitize(sanitized, tm)
        entries = _read_entries(shield_a12)
        assert entries[0]["decision_id"] == sid
        assert entries[1]["decision_id"] == sid

    def test_desanitize_caller_override_wins(self, shield_a12):
        sanitized, tm = shield_a12.sanitize("Email john@example.com")
        shield_a12.desanitize(sanitized, tm, decision_id="override-xyz")
        entries = _read_entries(shield_a12)
        assert entries[0]["decision_id"] != "override-xyz"
        assert entries[1]["decision_id"] == "override-xyz"

    def test_decision_id_unique_across_sanitize_calls(self, shield_a12):
        _, tm1 = shield_a12.sanitize("a@b.com")
        _, tm2 = shield_a12.sanitize("c@d.com")
        assert tm1.decision_id != tm2.decision_id

    def test_decision_id_in_audit_entry(self, shield_a12):
        _, tm = shield_a12.sanitize("Email john@example.com")
        entries = _read_entries(shield_a12)
        assert "decision_id" in entries[0]
        assert entries[0]["decision_id"] == tm.decision_id

    def test_sanitize_batch_decision_id(self, shield_a12):
        _, tm = shield_a12.sanitize_batch(["a@b.com", "c@d.com"])
        assert tm.decision_id is not None
        entries = _read_entries(shield_a12)
        assert entries[0]["decision_id"] == tm.decision_id

    def test_b3_rejects_decision_id_with_control_char(self, shield_a12):
        with pytest.raises(RuntimeError, match="decision_id"):
            shield_a12.audit.log(
                event_type="sanitize",
                decision_id="has\x00nul",
            )

    def test_b3_rejects_oversized_decision_id(self, shield_a12):
        with pytest.raises(RuntimeError, match="1..64"):
            shield_a12.audit.log(
                event_type="sanitize",
                decision_id="x" * 65,
            )

    def test_b3_rejects_non_string_decision_id(self, shield_a12):
        with pytest.raises(RuntimeError, match="decision_id"):
            shield_a12.audit.log(
                event_type="sanitize",
                decision_id=42,
            )


# ---------------------------------------------------------------------------
# C7.1-2: system_version_pin
# ---------------------------------------------------------------------------


class TestSystemVersionPin:
    def test_pin_composed_when_all_three_present(self, shield_a12_with_pin):
        shield_a12_with_pin.sanitize("hello", model="gpt-4o")
        entries = _read_entries(shield_a12_with_pin)
        assert entries[0]["system_version_pin"] == "gpt-4o@prod-2026-05-19/sysprompt-v3.2"

    def test_pin_null_when_model_missing(self, shield_a12_with_pin):
        shield_a12_with_pin.sanitize("hello")  # no model
        entries = _read_entries(shield_a12_with_pin)
        assert entries[0]["system_version_pin"] is None

    def test_pin_null_when_deployment_version_missing(self, tmp_path):
        cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            cfg = ShieldConfig(
                log_dir=str(tmp_path / "audit"),
                compliance_mode="eu_ai_act_article12",
                instruction_version="sysprompt-v3.2",  # only instruction set
            )
            shield = Shield(config=cfg)
            shield.sanitize("hello", model="gpt-4o")
            entries = _read_entries(shield)
            assert entries[0]["system_version_pin"] is None
        finally:
            os.chdir(cwd)

    def test_pin_null_when_no_pin_config_at_all(self, shield_a12):
        shield_a12.sanitize("hello", model="gpt-4o")
        entries = _read_entries(shield_a12)
        assert entries[0]["system_version_pin"] is None

    def test_b3_rejects_non_string_pin(self, shield_a12):
        with pytest.raises(RuntimeError, match="system_version_pin"):
            shield_a12.audit.log(
                event_type="sanitize",
                system_version_pin=42,
            )

    def test_b3_rejects_oversized_pin(self, shield_a12):
        with pytest.raises(RuntimeError, match="256 chars"):
            shield_a12.audit.log(
                event_type="sanitize",
                system_version_pin="x" * 257,
            )

    def test_env_var_picks_up_deployment_version(self, tmp_path, monkeypatch):
        monkeypatch.setenv("CLOAKLLM_DEPLOYMENT_VERSION", "env-deploy-v1")
        monkeypatch.setenv("CLOAKLLM_INSTRUCTION_VERSION", "env-instr-v1")
        cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            cfg = ShieldConfig(
                log_dir=str(tmp_path / "audit"),
                compliance_mode="eu_ai_act_article12",
            )
            shield = Shield(config=cfg)
            shield.sanitize("hello", model="gpt-4o")
            entries = _read_entries(shield)
            assert entries[0]["system_version_pin"] == "gpt-4o@env-deploy-v1/env-instr-v1"
        finally:
            os.chdir(cwd)


# ---------------------------------------------------------------------------
# C7.1-4: legacy_canonical sunset (phase 1)
# ---------------------------------------------------------------------------


class TestLegacyCanonicalSunset:
    def test_legacy_canonical_emits_deprecation_warning(self, shield_a12):
        # Generate a chain
        shield_a12.sanitize("hello")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            shield_a12.verify_audit(legacy_canonical=True)
        deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
        assert len(deprecations) >= 1
        msg = str(deprecations[0].message)
        assert "legacy_canonical" in msg
        assert "v0.9.0" in msg

    def test_legacy_canonical_emits_warning_every_call(self, shield_a12):
        # Phase 1 of the sunset means EVERY call warns, not just first.
        shield_a12.sanitize("hello")
        for _ in range(3):
            with warnings.catch_warnings(record=True) as w:
                warnings.simplefilter("always")
                shield_a12.verify_audit(legacy_canonical=True)
            deps = [x for x in w if issubclass(x.category, DeprecationWarning)]
            assert len(deps) >= 1, "every call should emit at least one DeprecationWarning"

    def test_legacy_canonical_no_warning_when_false(self, shield_a12):
        shield_a12.sanitize("hello")
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            shield_a12.verify_audit(legacy_canonical=False)
        deprecations = [x for x in w
                        if issubclass(x.category, DeprecationWarning)
                        and "legacy_canonical" in str(x.message)]
        assert len(deprecations) == 0


# ---------------------------------------------------------------------------
# C7.1-5: Shield.analyze() default flip
# ---------------------------------------------------------------------------


class TestAnalyzeDefaultFlip:
    def test_default_is_now_redact_true(self, shield_a12):
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            result = shield_a12.analyze("Email john@example.com")
        deprecations = [x for x in w if issubclass(x.category, DeprecationWarning)]
        # No deprecation warnings: the F4 sentinel + warning are gone.
        assert len(deprecations) == 0, (
            f"unexpected deprecations: {[str(x.message) for x in deprecations]}"
        )
        # Default behavior is now redacted.
        if result["entity_count"]:
            for ent in result["entities"]:
                assert ent["text"] == "[redacted]"

    def test_explicit_false_still_works(self, shield_a12):
        result = shield_a12.analyze("Email john@example.com", redact_values=False)
        assert result["entity_count"] >= 1
        # Raw PII present when explicitly disabled
        assert any("john@example.com" in ent["text"] for ent in result["entities"])

    def test_explicit_true_redacts(self, shield_a12):
        result = shield_a12.analyze("Email john@example.com", redact_values=True)
        if result["entity_count"]:
            for ent in result["entities"]:
                assert ent["text"] == "[redacted]"


# ---------------------------------------------------------------------------
# Backward compat: v0.7.0 fixtures still verify under v0.7.1
# ---------------------------------------------------------------------------


class TestBackwardCompat:
    """v0.7.0 audit entries lack decision_id + system_version_pin fields.
    They must still verify under v0.7.1's verify_chain."""

    def test_synth_v070_entry_without_new_fields_verifies(self, tmp_path):
        import hashlib
        from cloakllm._canonical import canonical_json

        # Simulate a v0.7.0 entry: NO decision_id, NO system_version_pin.
        entry = {
            "seq": 0,
            "event_id": "old-id",
            "timestamp": "2026-05-19T00:00:00+00:00",
            "event_type": "sanitize",
            "model": None, "provider": None,
            "entity_count": 0, "categories": {}, "tokens_used": [],
            "prompt_hash": "a"*64, "sanitized_hash": "b"*64,
            "latency_ms": 0, "mode": "tokenize",
            "entity_details": [], "timing": None,
            "certificate_hash": None, "key_id": None,
            "prev_hash": "0"*64,
            "metadata": {}, "risk_assessment": None,
        }
        h = hashlib.sha256(canonical_json(entry).encode("utf-8")).hexdigest()
        entry["entry_hash"] = h

        log_dir = tmp_path / "audit"
        log_dir.mkdir()
        (log_dir / "audit_2026-05-19.jsonl").write_text(
            json.dumps(entry, separators=(",", ":")) + "\n",
            encoding="utf-8",
        )
        cfg = ShieldConfig(log_dir=str(log_dir), audit_enabled=False)
        shield = Shield(config=cfg)
        ok, errors, _ = shield.audit.verify_chain()
        assert ok, f"v0.7.0 shape failed under v0.7.1: {errors}"
