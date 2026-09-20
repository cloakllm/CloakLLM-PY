"""
RegexBackend -- regex-based PII detection.

Handles custom patterns, locale patterns, and built-in patterns.
This is always the first pass in the default detection pipeline.
"""

from __future__ import annotations

import re
import warnings
from typing import TYPE_CHECKING

from cloakllm.backends.base import DetectorBackend
from cloakllm.detector import Detection, PATTERNS, luhn_valid
from cloakllm.locale_patterns import LOCALE_PATTERNS

if TYPE_CHECKING:
    from cloakllm.config import ShieldConfig


class RegexBackend(DetectorBackend):
    """Regex-based PII detection backend."""

    def __init__(self, config: ShieldConfig):
        self.config = config
        self._compiled_patterns: list[tuple[str, re.Pattern]] = []
        self._build_patterns()

    @property
    def name(self) -> str:
        return "regex"

    @staticmethod
    def _test_regex_safety(regex: re.Pattern) -> bool:
        """Test if a regex is safe from catastrophic backtracking.

        v0.6.1 H1.2: expanded corpus to exercise the patterns most prone to
        nested-quantifier blowup (long digit runs, mixed alphanumeric, IBAN-
        and JWT-style strings). Threshold raised from 20ms to 100ms because
        the corpus is bigger.

        v0.12.3: measured in CPU time, not wall clock. Catastrophic
        backtracking is CPU burn, so CPU time is what actually characterises
        it; wall clock additionally measures whatever else the machine is
        doing. That mattered because failing this check SKIPS the pattern --
        detection for that category is silently switched off -- so on a
        wall-clock threshold a busy machine could quietly stop detecting.

        It was not theoretical. EMAIL sat at ~17ms against the 100ms limit,
        roughly 6x of headroom where every other pattern had 100x-1300x, and
        a test run under heavy load duly dropped EMAIL detection and failed
        four assertions with no sign of why.
        """
        import time
        test_inputs = [
            'a' * 25 + '!',
            '1' * 25 + '!',
            ' ' * 25 + '!',
            ('a1 ' * 8) + '!',
            '@' * 25 + '!',
            # v0.6.1: pathological inputs for the previously-skipped built-ins
            '1' * 5000,                    # PHONE / locale phones
            'A1' * 2500,                   # API_KEY / IBAN
            'AAAA' * 100,                  # IBAN
            ('1234-' * 1000),              # PHONE separators
            'sk_' + 'a' * 1000,            # API_KEY long bearer
        ]
        for test_input in test_inputs:
            start = time.process_time()
            regex.search(test_input)
            if (time.process_time() - start) >= 0.1:
                return False
        return True

    def _build_patterns(self):
        """Compile regex patterns based on config."""
        pattern_map = {
            "EMAIL": self.config.detect_emails,
            "SSN": self.config.detect_ssns,
            "CREDIT_CARD": self.config.detect_credit_cards,
            "PHONE": self.config.detect_phones,
            "IP_ADDRESS": self.config.detect_ip_addresses,
            "API_KEY": self.config.detect_api_keys,
            "AWS_KEY": self.config.detect_api_keys,
            "JWT": self.config.detect_api_keys,
            "IBAN": self.config.detect_iban,
            "IL_ID": False,
        }

        # Custom patterns first
        for name, pattern in self.config.custom_patterns:
            try:
                compiled = re.compile(pattern)
                if not self._test_regex_safety(compiled):
                    warnings.warn(
                        f"CloakLLM: Custom pattern '{name}' failed safety check "
                        f"(potential ReDoS) -- skipped",
                        RuntimeWarning,
                        stacklevel=2,
                    )
                    continue
                self._compiled_patterns.append((name, compiled))
            except re.error:
                warnings.warn(
                    f"Invalid custom regex pattern for '{name}': {pattern!r}",
                    RuntimeWarning,
                    stacklevel=2,
                )

        # Locale patterns second
        locale = getattr(self.config, 'locale', 'en')
        for category, _hint, pattern_str in LOCALE_PATTERNS.get(locale, []):
            try:
                compiled = re.compile(pattern_str)
                if self._test_regex_safety(compiled):
                    self._compiled_patterns.append((category, compiled))
            except re.error:
                pass

        # Built-in patterns third.
        # v0.6.1 H1.1: built-in patterns are now also gated by the safety check
        # (previously skipped). This caught real bugs in PHONE/IBAN that had
        # been shipping since v0.1.0.
        for name, (_, pattern) in PATTERNS.items():
            if not pattern_map.get(name, True):
                continue
            try:
                compiled = re.compile(pattern)
            except re.error as e:
                warnings.warn(
                    f"CloakLLM: built-in pattern '{name}' failed to compile: {e}",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue
            if not self._test_regex_safety(compiled):
                warnings.warn(
                    f"CloakLLM: built-in pattern '{name}' failed ReDoS safety check "
                    f"(potential catastrophic backtracking) -- skipped. This indicates "
                    f"a regression. Please file a bug.",
                    RuntimeWarning,
                    stacklevel=2,
                )
                continue
            self._compiled_patterns.append((name, compiled))

    def detect(
        self, text: str, covered_spans: list[tuple[int, int]]
    ) -> list[Detection]:
        detections: list[Detection] = []

        for name, pattern in self._compiled_patterns:
            for match in pattern.finditer(text):
                start, end = match.start(), match.end()
                if any(start < e and end > s for s, e in covered_spans):
                    continue
                if name == "PHONE" and len(match.group().replace("-", "").replace(" ", "").replace(".", "")) < 7:
                    continue
                # v0.12.3: prefix alone is not enough. Rejecting here rather
                # than in the regex also leaves the span UNCOVERED, so a
                # number that merely looked like a card stays available to
                # the patterns that follow.
                if name == "CREDIT_CARD" and not luhn_valid(match.group()):
                    continue
                detections.append(Detection(
                    text=match.group(),
                    category=name,
                    start=start,
                    end=end,
                    confidence=0.95,
                    source="regex",
                ))
                covered_spans.append((start, end))

        return detections
