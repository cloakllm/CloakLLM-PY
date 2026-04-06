"""
RegexBackend — regex-based PII detection.

Handles custom patterns, locale patterns, and built-in patterns.
This is always the first pass in the default detection pipeline.
"""

from __future__ import annotations

import re
import warnings
from typing import TYPE_CHECKING

from cloakllm.backends.base import DetectorBackend
from cloakllm.detector import Detection, PATTERNS
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
        """Test if a regex is safe from catastrophic backtracking."""
        import time
        test_inputs = [
            'a' * 25 + '!',
            '1' * 25 + '!',
            ' ' * 25 + '!',
            ('a1 ' * 8) + '!',
            '@' * 25 + '!',
        ]
        for test_input in test_inputs:
            start = time.monotonic()
            regex.search(test_input)
            if (time.monotonic() - start) >= 0.02:
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
                        f"(potential ReDoS) — skipped",
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

        # Built-in patterns third (hardcoded, pre-validated — no safety check needed)
        for name, (_, pattern) in PATTERNS.items():
            if pattern_map.get(name, True):
                self._compiled_patterns.append(
                    (name, re.compile(pattern))
                )

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
