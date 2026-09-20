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
from cloakllm.detector import (
    Detection, PATTERNS, has_phone_context, luhn_valid,
)
from cloakllm.locale_patterns import LOCALE_PATTERNS

if TYPE_CHECKING:
    from cloakllm.config import ShieldConfig


class PatternSafetyError(RuntimeError):
    """A BUILT-IN pattern failed the ReDoS safety check.

    Raised rather than skipped. A built-in failing here cannot be caused by
    user input -- it means one of our own patterns regressed -- and the
    alternative is to carry on with that category's detection silently
    switched off, which in a PII tool is the worst available outcome.

    Custom and locale patterns are still skipped with a warning: a user's
    own regex should not be able to stop the SDK from starting.
    """


class RegexBackend(DetectorBackend):
    """Regex-based PII detection backend."""

    # v0.6.1 H1.2: inputs chosen to provoke nested-quantifier blowup.
    _SAFETY_PROBES = (
        'a' * 25 + '!',
        '1' * 25 + '!',
        ' ' * 25 + '!',
        ('a1 ' * 8) + '!',
        '@' * 25 + '!',
        '1' * 5000,                    # PHONE / locale phones
        'A1' * 2500,                   # API_KEY / IBAN
        'AAAA' * 100,                  # IBAN
        ('1234-' * 1000),              # PHONE separators
        'sk_' + 'a' * 1000,            # API_KEY long bearer
    )
    # CPU-seconds, not wall clock (v0.12.3).
    #
    # Two budgets, because the check means two different things (v0.12.4).
    # For a CUSTOM or locale pattern it is a real boundary against a regex
    # we did not write, so it stays tight.
    #
    # For a BUILT-IN it is a regression canary, not a defence -- a user
    # cannot change our patterns. And since a failing built-in now RAISES,
    # a tight budget would turn a merely slow machine into one where the
    # SDK refuses to start: EMAIL costs ~16ms of CPU here, so a host 6x
    # slower would have crossed 100ms. Catastrophic backtracking is
    # exponential and blows past a second on these probes, so a 1s budget
    # still catches the thing this is for while leaving room for slow
    # hardware.
    _SAFETY_BUDGET = 0.1
    _BUILTIN_SAFETY_BUDGET = 1.0

    def __init__(self, config: ShieldConfig):
        self.config = config
        self._compiled_patterns: list[tuple[str, re.Pattern]] = []
        self._build_patterns()

    @property
    def name(self) -> str:
        return "regex"

    @staticmethod
    def _measure_regex_safety(regex: re.Pattern) -> float:
        """Worst CPU-seconds any probe input costs this pattern."""
        import time
        worst = 0.0
        for test_input in RegexBackend._SAFETY_PROBES:
            start = time.process_time()
            regex.search(test_input)
            worst = max(worst, time.process_time() - start)
        return worst

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
        return RegexBackend._measure_regex_safety(regex) < RegexBackend._SAFETY_BUDGET

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
                else:
                    # v0.12.4: this branch used to be silent, which is the
                    # same fail-open with the volume turned all the way
                    # down -- a locale's detection would just quietly not
                    # happen. Not raised, because a locale pack is data
                    # rather than core code, but no longer invisible.
                    warnings.warn(
                        f"CloakLLM: locale pattern '{category}' for locale "
                        f"'{locale}' failed the ReDoS safety check -- skipped. "
                        f"That category will NOT be detected.",
                        RuntimeWarning,
                        stacklevel=2,
                    )
            except re.error as exc:
                warnings.warn(
                    f"CloakLLM: locale pattern '{category}' for locale "
                    f"'{locale}' failed to compile ({exc}) -- skipped. That "
                    f"category will NOT be detected.",
                    RuntimeWarning,
                    stacklevel=2,
                )

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
            # v0.12.4: RAISE, do not skip. Skipping left the process running
            # with this category's detection silently switched off, which is
            # fail-open in a tool whose entire job is not to miss things. A
            # built-in failing here cannot be provoked by user input -- it is
            # our own regression, exactly as the message has always said --
            # so refusing to start is the honest response and CI will catch
            # it long before a user does.
            worst = self._measure_regex_safety(compiled)
            if worst >= self._BUILTIN_SAFETY_BUDGET:
                raise PatternSafetyError(
                    f"CloakLLM: built-in pattern '{name}' failed the ReDoS "
                    f"safety check ({worst * 1000:.0f} ms of CPU against a "
                    f"{self._BUILTIN_SAFETY_BUDGET * 1000:.0f} ms budget). This is a "
                    f"regression in CloakLLM, not in your input. Refusing to "
                    f"start rather than run with '{name}' detection silently "
                    f"disabled. Please file a bug."
                )
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
                # v0.12.4: a CONTIGUOUS digit run is only a phone number if
                # something nearby says so. Separated forms and E.164 have
                # already declared themselves and are not gated. Verified
                # purely additive: the only all-digit match the previous
                # pattern made anywhere in the corpora was "14159265", the
                # digits of pi, which was itself a false positive.
                if (name == "PHONE" and match.group().isdigit()
                        and not has_phone_context(text, start)):
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
