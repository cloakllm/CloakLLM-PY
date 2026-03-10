"""
Deterministic Tokenizer.

Replaces sensitive entities with consistent, reversible tokens.
Same input always produces the same token within a session.
Tokens are descriptive by default: [PERSON_0], [EMAIL_1], etc.
"""

from __future__ import annotations

import hashlib
import hmac
import re
from dataclasses import dataclass, field
from typing import Optional

from cloakllm.config import ShieldConfig
from cloakllm.detector import Detection

_TOKEN_PATTERN = re.compile(r"\[([A-Z_]+_\d+)\]")
_ESCAPED_OPEN = "\uFF3B"
_ESCAPED_CLOSE = "\uFF3D"
_ESCAPED_PATTERN = re.compile(
    rf"{re.escape(_ESCAPED_OPEN)}([A-Z_]+_\d+){re.escape(_ESCAPED_CLOSE)}"
)


@dataclass
class TokenMap:
    """
    Bidirectional map between original values and tokens.
    One TokenMap per request/session. Ephemeral by default.
    """
    # original_value -> token
    forward: dict[str, str] = field(default_factory=dict)
    # token -> original_value
    reverse: dict[str, str] = field(default_factory=dict)
    # category -> counter (for generating sequential tokens)
    _counters: dict[str, int] = field(default_factory=dict)
    # All detections that were tokenized
    detections: list[Detection] = field(default_factory=list)
    # Mode: "tokenize" or "redact"
    mode: str = "tokenize"
    # Entity hashing
    entity_hashing: bool = False
    entity_hash_key: str = ""

    def _compute_entity_hash(self, category: str, original_text: str) -> str:
        """Compute HMAC-SHA256 hash for an entity: HMAC(key, "CATEGORY:normalized")."""
        normalized = original_text.strip().lower()
        message = f"{category}:{normalized}"
        return hmac.new(
            self.entity_hash_key.encode("utf-8"),
            message.encode("utf-8"),
            hashlib.sha256,
        ).hexdigest()

    def get_or_create(self, original: str, category: str) -> str:
        """Get existing token for value, or create a new one."""
        if self.mode == "redact":
            return f"[{category}_REDACTED]"

        # Normalize: strip whitespace for consistent matching
        key = original.strip()
        if key in self.forward:
            return self.forward[key]

        # Create new token
        idx = self._counters.get(category, 0)
        self._counters[category] = idx + 1
        token = f"[{category}_{idx}]"

        self.forward[key] = token
        self.reverse[token] = key
        return token

    @property
    def entity_count(self) -> int:
        return len(self.forward)

    @property
    def categories(self) -> dict[str, int]:
        """Count of entities per category."""
        counts: dict[str, int] = {}
        for det in self.detections:
            counts[det.category] = counts.get(det.category, 0) + 1
        return counts

    @property
    def entity_details(self) -> list[dict]:
        """Per-entity metadata list (PII-safe — no original text)."""
        details = []
        for det in self.detections:
            # Look up the token assigned to this detection
            if self.mode == "redact":
                token = f"[{det.category}_REDACTED]"
            else:
                key = det.text.strip()
                token = self.forward.get(key, "")
            detail = {
                "category": det.category,
                "start": det.start,
                "end": det.end,
                "length": det.end - det.start,
                "confidence": det.confidence,
                "source": det.source,
                "token": token,
            }
            if self.entity_hashing and self.entity_hash_key:
                detail["entity_hash"] = self._compute_entity_hash(det.category, det.text)
            details.append(detail)
        details.sort(key=lambda d: d["start"])
        return details

    def to_summary(self) -> dict:
        """Non-sensitive summary for logging (no original values)."""
        return {
            "entity_count": self.entity_count,
            "categories": self.categories,
            "tokens": list(self.reverse.keys()),
        }

    def to_report(self) -> dict:
        """Extended summary with per-entity details (PII-safe)."""
        return {
            "entity_count": self.entity_count,
            "categories": self.categories,
            "tokens": list(self.reverse.keys()),
            "mode": self.mode,
            "entity_details": self.entity_details,
        }


class Tokenizer:
    """Replaces detected entities with deterministic tokens."""

    def __init__(self, config: ShieldConfig):
        self.config = config

    def _escape_existing_tokens(self, text: str) -> str:
        return _TOKEN_PATTERN.sub(
            lambda m: f"{_ESCAPED_OPEN}{m.group(1)}{_ESCAPED_CLOSE}", text
        )

    def _unescape_tokens(self, text: str) -> str:
        return _ESCAPED_PATTERN.sub(lambda m: f"[{m.group(1)}]", text)

    def tokenize(
        self,
        text: str,
        detections: list[Detection],
        token_map: Optional[TokenMap] = None,
    ) -> tuple[str, TokenMap]:
        """
        Replace all detected entities in text with tokens.

        Args:
            text: Original text with sensitive data
            detections: List of Detection objects (must be sorted by start position)
            token_map: Existing TokenMap to reuse (for multi-turn conversations)

        Returns:
            (sanitized_text, token_map)
        """
        if token_map is None:
            token_map = TokenMap()

        # Escape any existing token-like patterns to prevent fake token injection
        result = self._escape_existing_tokens(text)
        for det in reversed(detections):
            token = token_map.get_or_create(det.text, det.category)
            result = result[:det.start] + token + result[det.end:]
            token_map.detections.append(det)

        return result, token_map

    def detokenize(self, text: str, token_map: TokenMap) -> str:
        """
        Replace all tokens in text with their original values.

        Handles:
        - Exact token matches: [PERSON_0] -> John Smith
        - Case variations of tokens
        - Tokens appearing multiple times
        """
        result = text

        # Sort tokens by length (longest first) to avoid partial replacements
        sorted_tokens = sorted(
            token_map.reverse.items(),
            key=lambda x: len(x[0]),
            reverse=True,
        )

        for token, original in sorted_tokens:
            result = re.sub(re.escape(token), lambda m: original, result, flags=re.IGNORECASE)

        # Restore any escaped token-like patterns from the original input
        result = self._unescape_tokens(result)

        return result
