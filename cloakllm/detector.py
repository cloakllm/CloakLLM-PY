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
    "LOC": "GPE",       # Both WikiNER LOC and OntoNotes LOC → GPE
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
    # Credit card numbers (Visa, MC, Amex, Discover)
    "CREDIT_CARD": (
        r"credit_card",
        r"\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})\b"
    ),
    # Phone numbers (international + US formats)
    # v0.6.1 H1.3: tightened from `(?:\(?\d{2,4}\)?[-.\s]?)?\d{3,4}[-.\s]?\d{3,4}\b`
    # which had three optional adjacent digit groups → ambiguous parses on long
    # digit runs. The new pattern:
    #   - replaces `\b` boundaries with `(?<!\d)` / `(?!\d)` lookarounds (digit-only),
    #   - makes parenthesized area code REQUIRE both parens, and bare area code
    #     REQUIRE a trailing separator, eliminating the ambiguity that allowed
    #     a long digit run to be parsed as area+rest in many ways.
    "PHONE": (
        r"phone",
        r"(?<!\d)(?:\+\d{1,3}[-.\s])?(?:\(\d{2,4}\)[-.\s]?|\d{2,4}[-.\s])?\d{3,4}[-.\s]?\d{3,4}(?!\d)"
    ),
    # IP addresses (IPv4)
    "IP_ADDRESS": (
        r"ip_address",
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    # API keys / tokens (high-entropy strings, common patterns)
    # v0.6.1 F1: bounded upper at 512 to limit ReDoS exposure. Body now
    # includes `-` and `_` so multi-segment keys (Anthropic sk-ant-api03-...,
    # GitHub fine-grained github_pat_X_Y, AWS session tokens) are detected.
    # Bounded character class — no backtracking risk despite broader match.
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
    # IBAN (International Bank Account Number)
    # v0.6.1 H1.3: tightened from `[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){2,7}[\dA-Z]{1,4}`
    # which had trailing-separator ambiguity → catastrophic backtracking on
    # long alpha-numeric strings. Now: separator moved BEFORE each 4-char
    # group, eliminating split ambiguity. Matches both compact (DE89370400440532013000)
    # and spaced (DE89 3704 0044 0532 0130 00) forms.
    "IBAN": (
        r"iban",
        r"\b[A-Z]{2}\d{2}(?:[\s]?[\dA-Z]{4}){2,7}(?:[\s]?[\dA-Z]{1,4})?\b"
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
            # Custom pipeline — use provided backends as-is
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

        # Pass 2: NER (always — lazy-loads spaCy)
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
