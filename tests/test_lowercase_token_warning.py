"""v0.6.3 I5 — lowercase-token warning during detokenize.

When an LLM produces a case-variant of a canonical token (e.g., `[email_0]`
instead of `[EMAIL_0]`), case-insensitive matching still substitutes the
PII correctly — but operators previously had no signal that their LLM is
producing malformed tokens. v0.6.3 logs a one-time warning per process
when the first case-variant substitution occurs.
"""

from __future__ import annotations

import logging
import unittest

import cloakllm.tokenizer as tokmod
from cloakllm import Shield, ShieldConfig


class TestLowercaseTokenWarning(unittest.TestCase):
    """Detokenize logs a one-time warning when LLM lowercases a token."""

    def setUp(self):
        # Reset the process-level warning gate before each test so we can
        # observe the first-time-warning behaviour deterministically.
        tokmod._CASE_MISMATCH_WARNED = False
        self.shield = Shield(ShieldConfig(audit_enabled=False))

    def test_lowercase_token_substitutes_and_warns(self):
        # Sanitize gives us a canonical [EMAIL_0] for the user's email.
        original = "Contact john@example.com please"
        sanitized, tm = self.shield.sanitize(original)
        self.assertIn("[EMAIL_0]", sanitized)
        # Simulate LLM lowercasing the token in its response.
        llm_response = "I'll reach out to [email_0] today."

        with self.assertLogs("cloakllm.tokenizer", level="WARNING") as cm:
            result = self.shield.desanitize(llm_response, tm)

        # Substitution still succeeded — backwards-compatible behaviour.
        self.assertIn("john@example.com", result)
        # Warning fired with the lowercase variant referenced.
        self.assertTrue(any("lowercase" in m or "case-variant" in m for m in cm.output))
        self.assertTrue(any("[email_0]" in m for m in cm.output))

    def test_canonical_case_does_not_warn(self):
        # No case mismatch → no warning. Use assertNoLogs (3.10+) emulation
        # by capturing and asserting empty.
        original = "Contact alice@example.com please"
        _, tm = self.shield.sanitize(original)
        llm_response = "Reach out to [EMAIL_0] now."

        # Capture WARNING-level messages on the tokenizer logger.
        logger = logging.getLogger("cloakllm.tokenizer")
        records: list[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = records.append
        handler.setLevel(logging.WARNING)
        logger.addHandler(handler)
        try:
            result = self.shield.desanitize(llm_response, tm)
        finally:
            logger.removeHandler(handler)

        self.assertIn("alice@example.com", result)
        # Filter to records that came from the warning we care about.
        case_records = [
            r for r in records
            if "lowercase" in r.getMessage() or "case-variant" in r.getMessage()
        ]
        self.assertEqual(case_records, [])

    def test_warning_fires_only_once_per_process(self):
        # First call warns; second call is silent.
        original = "Contact bob@example.com please"
        _, tm = self.shield.sanitize(original)

        with self.assertLogs("cloakllm.tokenizer", level="WARNING") as cm:
            self.shield.desanitize("send to [email_0] now", tm)
        self.assertTrue(any("case-variant" in m for m in cm.output))

        # Second call — even though it again substitutes a lowercase token,
        # no NEW warning should fire.
        logger = logging.getLogger("cloakllm.tokenizer")
        records: list[logging.LogRecord] = []
        handler = logging.Handler()
        handler.emit = records.append
        handler.setLevel(logging.WARNING)
        logger.addHandler(handler)
        try:
            result = self.shield.desanitize("again to [email_0] please", tm)
        finally:
            logger.removeHandler(handler)
        self.assertIn("bob@example.com", result)
        case_records = [
            r for r in records if "case-variant" in r.getMessage()
        ]
        self.assertEqual(case_records, [], "warning should not fire twice")

    def test_mixed_case_token_warns(self):
        # `[Email_0]` (TitleCase) is also a case variant — should warn.
        original = "Contact carol@example.com please"
        _, tm = self.shield.sanitize(original)
        with self.assertLogs("cloakllm.tokenizer", level="WARNING") as cm:
            result = self.shield.desanitize("Let's reach [Email_0] today", tm)
        self.assertIn("carol@example.com", result)
        self.assertTrue(any("case-variant" in m for m in cm.output))


class TestLowercaseTokenWarningInStreamDesanitizer(unittest.TestCase):
    """v0.6.3 G3: streaming path must also fire the case-variant warning.

    Streaming is the dominant production path under v0.6.3 — without this
    wiring, streaming users get no signal that their LLM is producing
    malformed tokens. The shared `_warn_case_mismatch_once` gate is the
    same one batched detokenize uses, so streaming + batched contribute
    to a single per-process warning.
    """

    def setUp(self):
        tokmod._CASE_MISMATCH_WARNED = False
        from cloakllm.stream import StreamDesanitizer
        from cloakllm.tokenizer import TokenMap
        # Build a token map by hand so we can control the canonical case.
        self._TokenMap = TokenMap
        self._StreamDesanitizer = StreamDesanitizer

    def _make_map(self):
        tm = self._TokenMap()
        tm.reverse["[EMAIL_0]"] = "alice@example.com"
        return tm

    def test_lowercase_token_in_stream_chunk_warns(self):
        tm = self._make_map()
        desan = self._StreamDesanitizer(tm)
        with self.assertLogs("cloakllm.tokenizer", level="WARNING") as cm:
            out = desan.feed("Reach out to [email_0] today")
        self.assertIn("alice@example.com", out)
        self.assertTrue(any("case-variant" in m for m in cm.output))
        self.assertTrue(any("[email_0]" in m for m in cm.output))

    def test_canonical_token_in_stream_chunk_does_not_warn(self):
        tm = self._make_map()
        desan = self._StreamDesanitizer(tm)
        logger = logging.getLogger("cloakllm.tokenizer")
        records: list[logging.LogRecord] = []
        h = logging.Handler()
        h.emit = records.append
        h.setLevel(logging.WARNING)
        logger.addHandler(h)
        try:
            out = desan.feed("Reach out to [EMAIL_0] today")
        finally:
            logger.removeHandler(h)
        self.assertIn("alice@example.com", out)
        case_records = [r for r in records if "case-variant" in r.getMessage()]
        self.assertEqual(case_records, [])

    def test_streaming_and_batched_share_one_warning(self):
        # First call (streaming) fires the warning; subsequent batched
        # call must NOT fire a second warning — same process gate.
        tm = self._make_map()
        desan = self._StreamDesanitizer(tm)
        with self.assertLogs("cloakllm.tokenizer", level="WARNING") as cm1:
            desan.feed("Reach [email_0]")
        self.assertTrue(any("case-variant" in m for m in cm1.output))

        # Now run a batched detokenize that ALSO has a case mismatch.
        # The shared gate should suppress the second warning.
        from cloakllm import Shield, ShieldConfig
        from cloakllm.tokenizer import Tokenizer
        shield = Shield(ShieldConfig(audit_enabled=False))
        # Sanitize to populate a real TokenMap with [EMAIL_0]
        _, real_tm = shield.sanitize("Contact bob@example.com")
        logger = logging.getLogger("cloakllm.tokenizer")
        records: list[logging.LogRecord] = []
        h = logging.Handler()
        h.emit = records.append
        h.setLevel(logging.WARNING)
        logger.addHandler(h)
        try:
            shield.desanitize("ping [email_0]", real_tm)
        finally:
            logger.removeHandler(h)
        case_records = [r for r in records if "case-variant" in r.getMessage()]
        self.assertEqual(
            case_records, [],
            "second warning should be gated by the shared process flag"
        )

    def test_token_split_across_chunks_still_warns(self):
        # The whole point of streaming: tokens may arrive across chunk
        # boundaries. Case-variant detection must work after reassembly.
        tm = self._make_map()
        desan = self._StreamDesanitizer(tm)
        with self.assertLogs("cloakllm.tokenizer", level="WARNING") as cm:
            out1 = desan.feed("Reach out to [emai")
            out2 = desan.feed("l_0] today")
        full = out1 + out2
        self.assertIn("alice@example.com", full)
        self.assertTrue(any("case-variant" in m for m in cm.output))


if __name__ == "__main__":
    unittest.main()
