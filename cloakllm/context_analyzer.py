"""
Context-Based PII Leakage Risk Analyzer.

Analyzes sanitized text to detect when surrounding context could
re-identify a person even after tokenization. For example:
"The CEO of [ORG_0], who founded it in 2003, lives in [GPE_0]"
could be de-anonymized via public records.

Three heuristic signals:
1. Token density — ratio of tokens to total words
2. Identifying descriptors — words like "CEO", "founder" near tokens
3. Relationship edges — phrases like "works at" connecting two tokens
"""

from __future__ import annotations

import math
import re
from dataclasses import dataclass


def _round3_canonical(x: float):
    """v0.10.3 HIGH-4: cross-SDK-identical 3dp rounding for the risk-assessment
    floats that land in the audit hash chain.

    Python `round(x, 3)` uses banker's rounding (half-even) and emits a float
    even when whole (`0.0`, `1.0`), while JS `Math.round(x*1000)/1000` rounds
    half-up and emits an int (`0`, `1`). The same logical risk_assessment thus
    hashed to different bytes in the two SDKs. This helper uses half-up integer
    flooring (`floor(x*1000 + 0.5)/1000`, identical in both SDKs since it is
    pure IEEE-754 ops) and returns an int when the value is whole -- so the
    canonical bytes match JS exactly. Returns int 0 for 0.0.
    """
    r = math.floor(x * 1000 + 0.5) / 1000
    if r == int(r):
        return int(r)
    return r


TOKEN_RE = re.compile(r"\[[A-Z][A-Z0-9_]*_(?:\d+|REDACTED)\]", re.IGNORECASE)

IDENTIFYING_DESCRIPTORS = {
    "ceo", "president", "founder", "director", "chairman", "chairwoman",
    "wife", "husband", "daughter", "son", "mother", "father",
    "only", "tallest", "youngest", "oldest", "first", "last",
    "sole", "chief", "head", "lead", "senior", "junior",
}

RELATIONSHIP_WORDS = {
    "married", "divorced", "works at", "employed by", "lives in",
    "born in", "graduated from", "founded", "owns", "manages",
    "reports to", "hired by", "sister of", "brother of",
    "daughter of", "son of", "wife of", "husband of",
}


@dataclass
class RiskAssessment:
    """Result of context-based PII leakage analysis."""
    token_density: float
    identifying_descriptors: int
    relationship_edges: int
    risk_score: float
    risk_level: str  # "low", "medium", "high"
    warnings: list[str]

    def to_dict(self) -> dict:
        return {
            "token_density": self.token_density,
            "identifying_descriptors": self.identifying_descriptors,
            "relationship_edges": self.relationship_edges,
            "risk_score": self.risk_score,
            "risk_level": self.risk_level,
            "warnings": self.warnings,
        }


class ContextAnalyzer:
    """Analyzes sanitized text for context-based PII leakage risk."""

    def analyze(self, sanitized_text: str) -> RiskAssessment:
        """
        Analyze sanitized text for context-based PII leakage risk.

        Args:
            sanitized_text: Text after PII tokenization (containing [CATEGORY_N] tokens)

        Returns:
            RiskAssessment with score, level, and specific warnings
        """
        if not sanitized_text or not sanitized_text.strip():
            return RiskAssessment(
                token_density=_round3_canonical(0.0),
                identifying_descriptors=0,
                relationship_edges=0,
                risk_score=_round3_canonical(0.0),
                risk_level="low",
                warnings=[],
            )

        words = sanitized_text.lower().split()
        total_words = max(len(words), 1)
        tokens = TOKEN_RE.findall(sanitized_text)
        token_density = len(tokens) / total_words

        # Signal 1: Identifying descriptors near tokens (5-word window)
        descriptor_count = 0
        warnings = []
        for i, word in enumerate(words):
            clean_word = word.strip(".,;:!?\"'()[]")
            if clean_word in IDENTIFYING_DESCRIPTORS:
                window = " ".join(words[max(0, i - 5):i + 6])
                if TOKEN_RE.search(window):
                    descriptor_count += 1
                    warnings.append(f"Identifying descriptor '{clean_word}' near a token")

        # Signal 2: Relationship phrases connecting two tokens (50-char window)
        relationship_count = 0
        text_lower = sanitized_text.lower()
        for rel in RELATIONSHIP_WORDS:
            if rel in text_lower:
                for m in re.finditer(re.escape(rel), text_lower):
                    before = text_lower[max(0, m.start() - 50):m.start()]
                    after = text_lower[m.end():m.end() + 50]
                    if TOKEN_RE.findall(before) and TOKEN_RE.findall(after):
                        relationship_count += 1
                        warnings.append(f"Relationship '{rel}' connects tokens")

        # Composite score
        risk_score = min(1.0, token_density * 1.5 + descriptor_count * 0.15 + relationship_count * 0.2)
        risk_level = "high" if risk_score > 0.7 else "medium" if risk_score > 0.3 else "low"

        return RiskAssessment(
            token_density=_round3_canonical(token_density),
            identifying_descriptors=descriptor_count,
            relationship_edges=relationship_count,
            risk_score=_round3_canonical(risk_score),
            risk_level=risk_level,
            warnings=warnings[:5],
        )
