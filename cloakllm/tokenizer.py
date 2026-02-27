"""
Deterministic Tokenizer.

Replaces sensitive entities with consistent, reversible tokens.
Same input always produces the same token within a session.
Tokens are descriptive by default: [PERSON_0], [EMAIL_1], etc.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Optional

from cloakllm.config import ShieldConfig
from cloakllm.detector import Detection


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

    def get_or_create(self, original: str, category: str) -> str:
        """Get existing token for value, or create a new one."""
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

    def to_summary(self) -> dict:
        """Non-sensitive summary for logging (no original values)."""
        return {
            "entity_count": self.entity_count,
            "categories": self.categories,
            "tokens": list(self.reverse.keys()),
        }


class Tokenizer:
    """Replaces detected entities with deterministic tokens."""

    def __init__(self, config: ShieldConfig):
        self.config = config

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

        # Build the sanitized string by replacing detections back-to-front
        # (so character offsets remain valid)
        result = text
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
            result = re.sub(re.escape(token), original, result, flags=re.IGNORECASE)

        return result
