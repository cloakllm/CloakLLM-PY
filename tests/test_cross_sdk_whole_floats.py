"""v0.12.2 XS-1: whole-valued floats must never reach a hashed audit entry.

Python writes 0.0 as "0.0"; JavaScript writes it as "0". Same number,
different canonical bytes, different SHA-256 -- so a Python-written chain was
reported as TAMPERED by the JS verifier.

The "producers pass int 0, not float 0.0" convention already existed and was
followed at the Article 4a bias sites, but not on the core log() path, where
`latency_ms` DEFAULTS to 0.0 and timing values round to 0.0 for any
sub-millisecond operation. In a five-entry end-to-end run, four entries were
unverifiable in JS. These tests pin the fix at the write boundary so no future
producer can reintroduce it.
"""
import json

import pytest

from cloakllm.audit import AuditLogger, _collapse_whole_floats
from cloakllm.config import ShieldConfig


class TestCollapseWholeFloats:
    def test_whole_floats_become_ints(self):
        assert _collapse_whole_floats(0.0) == 0
        assert isinstance(_collapse_whole_floats(0.0), int)
        assert isinstance(_collapse_whole_floats(5.0), int)
        assert isinstance(_collapse_whole_floats(-3.0), int)

    def test_fractional_floats_are_untouched(self):
        # These already serialise identically in both SDKs.
        assert _collapse_whole_floats(0.95) == 0.95
        assert isinstance(_collapse_whole_floats(0.95), float)
        assert isinstance(_collapse_whole_floats(5.5), float)

    def test_bools_survive(self):
        # bool subclasses int, so a careless isinstance(x, int) check would
        # rewrite True as 1 and corrupt the schema's boolean fields.
        for value in (True, False):
            out = _collapse_whole_floats(value)
            assert out is value
            assert isinstance(out, bool)

    def test_ints_and_strings_survive(self):
        assert _collapse_whole_floats(7) == 7
        assert _collapse_whole_floats("0.0") == "0.0"
        assert _collapse_whole_floats(None) is None

    def test_recurses_into_nested_structures(self):
        got = _collapse_whole_floats({
            "timing": {"total_ms": 0.0, "regex_ms": 1.25},
            "entity_details": [{"confidence": 1.0, "start": 0}],
            "deep": [[{"x": 2.0}]],
        })
        assert isinstance(got["timing"]["total_ms"], int)
        assert isinstance(got["timing"]["regex_ms"], float)
        assert isinstance(got["entity_details"][0]["confidence"], int)
        assert isinstance(got["deep"][0][0]["x"], int)


class TestWrittenEntriesAreJsCompatible:
    def _entries(self, tmp_path):
        out = []
        for jf in sorted(tmp_path.glob("audit_*.jsonl")):
            for line in jf.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    out.append((line, json.loads(line)))
        return out

    def test_no_whole_float_is_written_to_the_log(self, tmp_path):
        logger = AuditLogger(ShieldConfig(
            log_dir=str(tmp_path), audit_enabled=True,
            compliance_mode="eu_ai_act_article12"))
        # latency_ms defaults to 0.0; timing lands on 0.0 sub-millisecond;
        # a confidence of exactly 1.0 is the entity_details case.
        logger.log(
            event_type="sanitize",
            original_text="a@b.com",
            sanitized_text="[EMAIL_0]",
            entity_count=1,
            categories={"EMAIL": 1},
            entity_details=[{"category": "EMAIL", "start": 0, "end": 7,
                             "length": 7, "confidence": 1.0, "token": "[EMAIL_0]"}],
            timing={"total_ms": 0.0, "regex_ms": 0.0, "ner_ms": 2.5},
        )

        lines = self._entries(tmp_path)
        assert lines, "nothing was written"
        for raw, _ in lines:
            # A literal "N.0" anywhere in the serialised entry is the defect.
            assert ".0" not in raw.replace('"', ""), (
                "whole-valued float written verbatim: %s" % raw)

    def test_the_chain_still_verifies_in_python(self, tmp_path):
        logger = AuditLogger(ShieldConfig(
            log_dir=str(tmp_path), audit_enabled=True,
            compliance_mode="eu_ai_act_article12"))
        for _ in range(3):
            logger.log(event_type="sanitize", original_text="x@y.com",
                       sanitized_text="[EMAIL_0]", entity_count=1,
                       timing={"total_ms": 0.0})
        valid, errors, _ = logger.verify_chain()
        assert valid, errors

    def test_fractional_timing_survives_the_round_trip(self, tmp_path):
        # The fix must not flatten real measurements.
        logger = AuditLogger(ShieldConfig(log_dir=str(tmp_path), audit_enabled=True))
        logger.log(event_type="sanitize", original_text="x@y.com",
                   sanitized_text="[EMAIL_0]", timing={"regex_ms": 1.25})
        _, entry = self._entries(tmp_path)[0]
        assert entry["timing"]["regex_ms"] == 1.25

    @pytest.mark.parametrize("latency", [0.0, 5.0, 12.0])
    def test_whole_latency_is_written_as_an_int(self, tmp_path, latency):
        logger = AuditLogger(ShieldConfig(log_dir=str(tmp_path), audit_enabled=True))
        logger.log(event_type="sanitize", original_text="x@y.com",
                   sanitized_text="[E]", latency_ms=latency)
        _, entry = self._entries(tmp_path)[0]
        assert isinstance(entry["latency_ms"], int), entry["latency_ms"]
        assert entry["latency_ms"] == int(latency)
