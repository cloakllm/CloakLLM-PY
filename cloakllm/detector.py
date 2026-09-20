"""
PII Detection Engine.

Orchestrates a pipeline of DetectorBackend instances for comprehensive
sensitive data detection. Default pipeline: regex -> NER -> LLM.

Custom backends can be injected via the `backends` parameter.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass

from cloakllm.config import ShieldConfig

ALLOWED_SPACY_MODELS = frozenset({
    "en_core_web_sm", "en_core_web_md", "en_core_web_lg", "en_core_web_trf",
    "xx_ent_wiki_sm",
    "de_core_news_sm", "de_core_news_md", "de_core_news_lg",
    "fr_core_news_sm", "fr_core_news_md", "fr_core_news_lg",
    "es_core_news_sm", "es_core_news_md", "es_core_news_lg",
    "nl_core_news_sm", "nl_core_news_md", "nl_core_news_lg",
    "zh_core_web_sm", "zh_core_web_md", "zh_core_web_lg", "zh_core_web_trf",
    "ja_core_news_sm", "ja_core_news_md", "ja_core_news_lg",
    "ru_core_news_sm", "ru_core_news_md", "ru_core_news_lg",
    "ko_core_news_sm", "ko_core_news_md", "ko_core_news_lg",
    "it_core_news_sm", "it_core_news_md", "it_core_news_lg",
    "pl_core_news_sm", "pl_core_news_md", "pl_core_news_lg",
    "pt_core_news_sm", "pt_core_news_md", "pt_core_news_lg",
})

# Map raw NER labels from different label schemes to CloakLLM canonical categories
_NER_LABEL_MAP = {
    # OntoNotes labels pass through (en, nl, zh, ja)
    "PERSON": "PERSON",
    "ORG": "ORG",
    "GPE": "GPE",
    "FAC": "FAC",
    "NORP": "NORP",
    "LOC": "GPE",       # Both WikiNER LOC and OntoNotes LOC -> GPE
    # WikiNER (de, fr, es, it, pt, ru)
    "PER": "PERSON",
    "MISC": "MISC",
    # Korean (KLUE)
    "PS": "PERSON",
    "LC": "GPE",
    "OG": "ORG",
    # Polish (NKJP corpus)
    "persName": "PERSON",
    "placeName": "GPE",
    "geogName": "GPE",
    "orgName": "ORG",
}


@dataclass(frozen=True)
class Detection:
    """A detected sensitive entity."""
    text: str          # The original text matched
    category: str      # e.g., "PERSON", "EMAIL", "SSN", "API_KEY"
    start: int         # Start character offset in original string
    end: int           # End character offset in original string
    confidence: float  # 0.0-1.0 confidence score
    source: str        # "regex", "ner", or "llm"


# v0.12.4: a bare digit run only counts as a phone number when something
# nearby says so. Anchored to the end of the preceding window, so "call
# about order 9876543210" does NOT qualify -- the keyword has to be next to
# the number, not merely in the sentence.
PHONE_CONTEXT_RE = re.compile(
    r"(?:call(?:ed|ing)?|phone|telephone|tel|mobile|cell|fax|contact|"
    r"reach|dial|ring|whatsapp|sms|text)"
    # Up to two short filler words may sit between the keyword and the
    # number, because "reach me on", "call him at" and "contact us on" are
    # how people write. The 4-character cap is what keeps it honest: it
    # admits me/him/her/us/at/on/is, and refuses "about", "order",
    # "invoice", "ticket" and "reference". "number" is allowed explicitly
    # -- "phone number is X" is too common to miss -- and is safe because
    # it is only ever reached AFTER a phone keyword, so "order number X"
    # and "reference number X" still have nothing to open the gate.
    r"(?:\W+(?:\w{1,4}|numbers?)){0,2}"
    r"\W{0,4}$",
    re.IGNORECASE,
)
PHONE_CONTEXT_WINDOW = 28


def has_phone_context(text: str, start: int) -> bool:
    """Does a phone keyword sit immediately before this position?

    Only consulted for CONTIGUOUS digit runs. A number written with
    separators, or with a leading +, has already declared itself.
    """
    return bool(PHONE_CONTEXT_RE.search(
        text[max(0, start - PHONE_CONTEXT_WINDOW):start]))


def luhn_valid(number: str) -> bool:
    """Does this digit run pass the Luhn checksum every card issuer uses?

    Applied to CREDIT_CARD matches so that a number which merely looks like
    a card is not reported as one. Without it the standard test Visa with a
    deliberately broken check digit (4111111111111112) was flagged, and the
    first modal that fires on something obviously not a card is what makes
    a user stop believing the next one.

    Separators are ignored, so it works on "4111 1111 1111 1111" as written.
    """
    digits = [int(c) for c in number if c.isdigit()]
    if len(digits) < 12:
        return False
    # Double every second digit counting from the RIGHT. Indexing from the
    # left instead, that is every index congruent to len % 2.
    parity = len(digits) % 2
    total = 0
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        total += digit
    return total % 10 == 0


# --- Regex patterns ---
# Ordered by specificity (most specific first to avoid false positives)

PATTERNS: dict[str, tuple[str, str]] = {
    # Emails
    "EMAIL": (
        r"email",
        r"\b[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}\b"
    ),
    # US Social Security Numbers
    "SSN": (
        r"ssn",
        r"\b(?!000|666|9\d{2})\d{3}[-\s]?(?!00)\d{2}[-\s]?(?!0000)\d{4}\b"
    ),
    # Credit card numbers.
    # v0.11.2: detect SPACE/DASH-grouped forms (how cards are normally written),
    # not just contiguous digits. Before this, "4111 1111 1111 1111" was missed
    # by CC and partially eaten by PHONE, leaking the trailing group into the
    # log. A backreferenced separator (\1 / \2) keeps grouping consistent and
    # avoids matching arbitrary digit runs. Must precede PHONE (it does) so the
    # full card span is claimed first via covered_spans.
    #
    # v0.12.3: the issuer list had stopped at Visa / 5-series Mastercard /
    # Amex / Discover, so Luhn-valid cards on three live ranges were MISSED
    # ENTIRELY -- a leak, not a false positive:
    #   * Mastercard 2-series (2221-2720), issued since 2017
    #   * JCB (3528-3589)
    #   * UnionPay (62), the largest network in the world by volume
    # Discover's 644-649 range was missing too. The recall benchmark could
    # not have caught any of it: its corpus only held Visa, 5-series
    # Mastercard and Amex.
    #
    # The prefixes stay explicit rather than becoming "any 13-19 digit run
    # validated by Luhn". Luhn alone passes one in ten random digit runs,
    # which on a developer's order ids and timestamps is a false-positive
    # engine -- and in a warn-UI a false positive costs a person's attention.
    # Prefix AND checksum, not either alone.
    # Maestro (50, 56-69, 12-19 digits) is deliberately NOT covered. Its
    # range is so broad it overlaps most of the others and a great many
    # ordinary numbers, and Luhn alone admits one in ten candidates -- so
    # adding it would buy a little recall for a lot of false positives.
    # test_credit_card.py asserts the gap so it stays a decision.
    "CREDIT_CARD": (
        r"credit_card",
        r"(?<!\d)(?:(?:4\d{3}|5[1-5]\d{2}"
        r"|222[1-9]|22[3-9]\d|2[3-6]\d{2}|27[01]\d|2720"   # Mastercard 2-series
        r"|352[89]|35[3-8]\d"                              # JCB
        r"|6011|62\d{2}|64[4-9]\d|65\d{2}"                 # Discover, UnionPay
        r")([ -]?)\d{4}\1\d{4}\1\d{4}"                     # 16 digits, 4-4-4-4
        r"|3[47]\d{2}([ -]?)\d{6}\2\d{5}"                  # Amex, 15, 4-6-5
        r"|3(?:0[0-5]\d|6\d{2}|8\d{2})([ -]?)\d{6}\3\d{4}"  # Diners, 14, 4-6-4
        r"|62\d{15,17})(?!\d)"                             # UnionPay, 17-19
    ),
    # IBAN -- MUST precede PHONE (v0.11.2). In the old order IBAN came AFTER
    # PHONE, so PHONE's finditer claimed the IBAN digit groups first (via
    # covered_spans), fragmenting "DE89 3704 0044 0532 0130 00" into PHONE
    # tokens + a leaked country code. Ordering it before PHONE lets IBAN claim
    # the whole span. The regex already matches compact + spaced forms.
    "IBAN": (
        r"iban",
        r"\b[A-Z]{2}\d{2}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b"
    ),
    # Phone numbers (international + US formats)
    # v0.6.1 H1.3: tightened from `(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b`
    # which had three optional adjacent digit groups -> ambiguous parses on long
    # digit runs. The new pattern:
    #   - replaces `\b` boundaries with `(?<!\d)` / `(?!\d)` lookarounds (digit-only),
    #   - makes parenthesized area code REQUIRE both parens, and bare area code
    #     REQUIRE a trailing separator, eliminating the ambiguity that allowed
    #     a long digit run to be parsed as area+rest in many ways.
    "PHONE": (
        r"phone",
        # v0.12.1: the prior pattern assumed 3-4 digit groups, so all-2-digit-
        # grouped numbers (e.g. French/European "06 12 34 56 78", 8-10 digits)
        # leaked verbatim on the default (non-locale) config. Added a second
        # alternative for that shape (a leading 2-digit pair + 3-4 separated
        # 2-digit groups, separators REQUIRED so arbitrary digit runs don't match).
        #
        # v0.12.4: contiguous numbers -- no separators at all -- were
        # COMPLETELY undetected, including every bare US 10-digit number.
        # Two alternatives close that, and they are gated very differently:
        #
        #   E.164 (+4420...) needs no gate. A leading "+" is the writer
        #   declaring this is a phone number; nothing else is shaped that way.
        #
        #   A bare NANP-shaped run does. "2026091912" is a plausible
        #   Washington DC number AND a plausible invoice id, and roughly 64%
        #   of random 10-digit ids satisfy the shape, so shape alone is a
        #   false-positive engine. detect() therefore additionally requires a
        #   phone keyword nearby -- regex proposes, code disposes, the same
        #   split the Luhn check uses.
        #
        # NANP structure is real and does some of the work: area code and
        # exchange both start 2-9 and neither may be N11 (411, 911, ...),
        # which alone rejects every unix timestamp in seconds.
        r"(?<!\d)(?:"
        r"(?:\+\d{1,3}[-.\s])?(?:\(\d{2,4}\)[-.\s]?|\d{2,4}[-.\s])?\d{3,4}[-.\s]?\d{3,4}"
        r"|\d{2}(?:[-.\s]\d{2}){3,4}"
        r")(?!\d)"
        r"|(?<![\d+])\+[1-9]\d{7,14}(?!\d)"
        r"|(?<!\d)1?[2-9](?:0[1-9]|[1-9]\d)[2-9](?:0[1-9]|[1-9]\d)\d{4}(?!\d)"
    ),
    # IP addresses (IPv4 + IPv6). v0.11.2: IPv6 was entirely undetected before,
    # so a whole address (e.g. 2001:db8:85a3::8a2e:370:7334) leaked verbatim.
    # The IPv6 alternation is the standard fully-bounded form (no nested
    # unbounded quantifiers -> ReDoS-safe), gated by non-word/non-colon
    # lookarounds so it doesn't grab fragments of other tokens.
    "IP_ADDRESS": (
        r"ip_address",
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
        r"|(?<![\w:])(?:"
        r"(?:[A-Fa-f0-9]{1,4}:){7}[A-Fa-f0-9]{1,4}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,7}:"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,6}:[A-Fa-f0-9]{1,4}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,5}(?::[A-Fa-f0-9]{1,4}){1,2}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,4}(?::[A-Fa-f0-9]{1,4}){1,3}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,3}(?::[A-Fa-f0-9]{1,4}){1,4}"
        r"|(?:[A-Fa-f0-9]{1,4}:){1,2}(?::[A-Fa-f0-9]{1,4}){1,5}"
        r"|[A-Fa-f0-9]{1,4}:(?::[A-Fa-f0-9]{1,4}){1,6}"
        r"|:(?::[A-Fa-f0-9]{1,4}){1,7}"
        r")(?![\w:])"
    ),
    # API keys / tokens (high-entropy strings, common patterns)
    # v0.6.1 F1: bounded upper at 512 to limit ReDoS exposure. Body now
    # includes `-` and `_` so multi-segment keys (Anthropic sk-ant-api03-...,
    # GitHub fine-grained github_pat_X_Y, AWS session tokens) are detected.
    # Bounded character class -- no backtracking risk despite broader match.
    "API_KEY": (
        r"api_key",
        r"\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[a-zA-Z0-9_-]{20,512}\b"
    ),
    # AWS access keys
    "AWS_KEY": (
        r"api_key",
        r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b"
    ),
    # JWT tokens
    "JWT": (
        r"api_key",
        r"\beyJ[a-zA-Z0-9_-]{10,}\.eyJ[a-zA-Z0-9_-]{10,}\.[a-zA-Z0-9_-]{10,}\b"
    ),
    # Israeli ID number (9 digits)
    "IL_ID": (
        r"national_id",
        r"\b\d{9}\b"
    ),
}


class DetectionEngine:
    """Orchestrates a pipeline of detection backends."""

    def __init__(self, config: ShieldConfig, backends: list | None = None):
        self.config = config
        self._backends: list = []

        if backends is not None:
            # Custom pipeline -- use provided backends as-is
            self._backends = list(backends)
        else:
            # Default pipeline: regex -> NER -> LLM
            self._build_default_pipeline()

    def _build_default_pipeline(self):
        """Build the default 3-pass detection pipeline."""
        from cloakllm.backends.regex import RegexBackend
        from cloakllm.backends.ner import NerBackend
        from cloakllm.backends.llm import LlmBackend

        # Pass 1: Regex (always)
        self._backends.append(RegexBackend(self.config))

        # Pass 2: NER (always -- lazy-loads spaCy)
        ner_backend = NerBackend(self.config)
        self._backends.append(ner_backend)

        # Pass 3: LLM (opt-in)
        if self.config.llm_detection:
            llm_backend = LlmBackend(self.config)
            self._backends.append(llm_backend)

    # --- Backward compatibility properties ---

    @property
    def _nlp(self):
        """Backward compat: access the spaCy model from NerBackend."""
        for backend in self._backends:
            if hasattr(backend, 'nlp'):
                return backend.nlp
        return None

    @property
    def nlp(self):
        """Backward compat: access the spaCy model from NerBackend."""
        return self._nlp

    @property
    def _compiled_patterns(self):
        """Backward compat: access compiled patterns from RegexBackend."""
        for backend in self._backends:
            if hasattr(backend, '_compiled_patterns'):
                return backend._compiled_patterns
        return []

    @property
    def _llm_detector(self):
        """Backward compat: access the LLM detector."""
        for backend in self._backends:
            if hasattr(backend, '_detector') and backend.name == "llm":
                return backend._detector
        return None

    @staticmethod
    def _test_regex_safety(regex: re.Pattern) -> bool:
        """Backward compat: delegates to RegexBackend._test_regex_safety."""
        from cloakllm.backends.regex import RegexBackend
        return RegexBackend._test_regex_safety(regex)

    def detect(self, text: str) -> tuple[list[Detection], dict[str, float]]:
        """
        Detect all sensitive entities in text.
        Returns (detections, timing) where detections are sorted by start
        position and timing contains per-backend millisecond breakdowns.
        """
        detections: list[Detection] = []
        covered_spans: list[tuple[int, int]] = []
        timing: dict[str, float] = {}

        for backend in self._backends:
            t0 = time.perf_counter()
            backend_detections = backend.detect(text, covered_spans)
            timing[f"{backend.name}_ms"] = round(
                (time.perf_counter() - t0) * 1000, 2
            )
            detections.extend(backend_detections)

        # Sort by start position (important for tokenization)
        detections.sort(key=lambda d: d.start)
        return detections, timing
