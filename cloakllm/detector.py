"""
PII Detection Engine.

Combines spaCy NER with regex patterns for comprehensive sensitive data detection.
Designed for speed: regex runs first (fast), NER runs second (accurate).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from cloakllm.config import ShieldConfig


@dataclass(frozen=True)
class Detection:
    """A detected sensitive entity."""
    text: str          # The original text matched
    category: str      # e.g., "PERSON", "EMAIL", "SSN", "API_KEY"
    start: int         # Start character offset in original string
    end: int           # End character offset in original string
    confidence: float  # 0.0-1.0 confidence score
    source: str        # "ner" or "regex"


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
    "PHONE": (
        r"phone",
        r"(?:\+?\d{1,3}[-.\s]?)?\(?\d{2,4}\)?[-.\s]?\d{3,4}[-.\s]?\d{3,4}\b"
    ),
    # IP addresses (IPv4)
    "IP_ADDRESS": (
        r"ip_address",
        r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b"
    ),
    # API keys / tokens (high-entropy strings, common patterns)
    "API_KEY": (
        r"api_key",
        r"\b(?:sk|pk|api|key|token|secret|bearer)[-_]?[a-zA-Z0-9]{20,}\b"
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
    "IBAN": (
        r"iban",
        r"\b[A-Z]{2}\d{2}[\s]?[\dA-Z]{4}[\s]?(?:[\dA-Z]{4}[\s]?){2,7}[\dA-Z]{1,4}\b"
    ),
    # Israeli ID number (9 digits)
    "IL_ID": (
        r"national_id",
        r"\b\d{9}\b"
    ),
}


class DetectionEngine:
    """Detects PII and sensitive data in text using NER + regex."""

    def __init__(self, config: ShieldConfig):
        self.config = config
        self._nlp = None
        self._compiled_patterns: list[tuple[str, re.Pattern]] = []
        self._build_patterns()

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
            "IL_ID": False,  # High false-positive rate, disabled by default
        }

        for name, (_, pattern) in PATTERNS.items():
            if pattern_map.get(name, True):
                self._compiled_patterns.append(
                    (name, re.compile(pattern))
                )

        # Add custom patterns
        for name, pattern in self.config.custom_patterns:
            try:
                self._compiled_patterns.append(
                    (name, re.compile(pattern))
                )
            except re.error:
                import warnings
                warnings.warn(
                    f"Invalid custom regex pattern for '{name}': {pattern!r}",
                    RuntimeWarning,
                    stacklevel=2,
                )

    @property
    def nlp(self):
        """Lazy-load spaCy model. Falls back to blank model if not installed."""
        if self._nlp is None:
            try:
                import spacy
                try:
                    self._nlp = spacy.load(self.config.spacy_model)
                except OSError:
                    # Model not installed — try downloading it
                    try:
                        import subprocess
                        import sys
                        subprocess.check_call(
                            [sys.executable, "-m", "spacy", "download",
                             self.config.spacy_model],
                            timeout=60,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL,
                        )
                        self._nlp = spacy.load(self.config.spacy_model)
                    except Exception:
                        # Download failed — use blank model (regex still works)
                        import warnings
                        warnings.warn(
                            f"spaCy model '{self.config.spacy_model}' not available. "
                            f"NER detection disabled. Regex patterns still active. "
                            f"Install with: python -m spacy download {self.config.spacy_model}",
                            RuntimeWarning,
                            stacklevel=2,
                        )
                        self._nlp = spacy.blank("en")
            except ImportError:
                raise ImportError(
                    "spaCy is required: pip install spacy"
                )
        return self._nlp

    def detect(self, text: str) -> list[Detection]:
        """
        Detect all sensitive entities in text.
        Returns detections sorted by start position (earliest first).
        """
        detections: list[Detection] = []
        covered_spans: list[tuple[int, int]] = []

        # --- Pass 1: Regex (fast, high precision for structured data) ---
        for name, pattern in self._compiled_patterns:
            for match in pattern.finditer(text):
                start, end = match.start(), match.end()
                # Skip if overlapping with existing detection
                if any(start < e and end > s for s, e in covered_spans):
                    continue
                # Validate: skip short phone-like matches that are likely just numbers
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

        # --- Pass 2: spaCy NER (slower, catches names/orgs/locations) ---
        doc = self.nlp(text)
        for ent in doc.ents:
            if ent.label_ not in self.config.ner_entity_types:
                continue
            start, end = ent.start_char, ent.end_char
            # Skip if already detected by regex
            if any(start < e and end > s for s, e in covered_spans):
                continue
            # Skip very short entities (likely false positives)
            if len(ent.text.strip()) < 2:
                continue
            detections.append(Detection(
                text=ent.text,
                category=ent.label_,
                start=start,
                end=end,
                confidence=0.85,
                source="ner",
            ))
            covered_spans.append((start, end))

        # Sort by start position (important for tokenization)
        detections.sort(key=lambda d: d.start)
        return detections
