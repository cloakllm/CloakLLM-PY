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


if __name__ == "__main__":
    unittest.main()
