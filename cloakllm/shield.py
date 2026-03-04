"""
Shield — the main CloakLLM engine.

Ties together detection, tokenization, and audit logging into a single interface.
Can be used standalone or via the LiteLLM middleware integration.
"""

from __future__ import annotations

import time
from typing import Any, Optional

from cloakllm.audit import AuditLogger
from cloakllm.config import ShieldConfig
from cloakllm.detector import DetectionEngine
from cloakllm.tokenizer import TokenMap, Tokenizer


class Shield:
    """
    Main CloakLLM engine.

    Usage:
        shield = Shield()

        # Sanitize a prompt
        sanitized, token_map = shield.sanitize("Email john@acme.com about the deal")
        # sanitized: "Email [EMAIL_0] about the deal"

        # Send sanitized to LLM, get response...

        # Desanitize the response
        clean_response = shield.desanitize(response_text, token_map)
    """

    def __init__(self, config: Optional[ShieldConfig] = None):
        self.config = config or ShieldConfig()
        self.detector = DetectionEngine(self.config)
        self.tokenizer = Tokenizer(self.config)
        self.audit = AuditLogger(self.config)

    def sanitize(
        self,
        text: str,
        token_map: Optional[TokenMap] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> tuple[str, TokenMap]:
        """
        Detect and replace sensitive entities in text.

        Args:
            text: Text potentially containing sensitive data
            token_map: Existing TokenMap for multi-turn conversations
            model: LLM model name (for audit logging)
            provider: LLM provider name (for audit logging)
            metadata: Additional context to log

        Returns:
            (sanitized_text, token_map)
        """
        start_time = time.perf_counter()

        # Detect sensitive entities
        detections = self.detector.detect(text)

        # Ensure token_map has the correct mode
        if token_map is None:
            token_map = TokenMap(mode=self.config.mode)

        # Tokenize (replace with tokens)
        sanitized, token_map = self.tokenizer.tokenize(text, detections, token_map)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Build tokens_used list — in redact mode, collect from detections
        if self.config.mode == "redact":
            tokens_used = list({f"[{d.category}_REDACTED]" for d in detections})
        else:
            tokens_used = list(token_map.reverse.keys())

        # Audit log
        self.audit.log(
            event_type="sanitize",
            original_text=text,
            sanitized_text=sanitized,
            model=model,
            provider=provider,
            entity_count=len(detections),
            categories=token_map.categories,
            tokens_used=tokens_used,
            latency_ms=elapsed_ms,
            mode=self.config.mode,
            metadata=metadata,
        )

        return sanitized, token_map

    def desanitize(
        self,
        text: str,
        token_map: TokenMap,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> str:
        """
        Replace tokens in LLM response with original values.

        Args:
            text: LLM response containing tokens
            token_map: TokenMap from the sanitize step
            model: LLM model name (for audit logging)
            provider: LLM provider name (for audit logging)
            metadata: Additional context to log

        Returns:
            Desanitized text with original values restored
        """
        start_time = time.perf_counter()

        result = self.tokenizer.detokenize(text, token_map)

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Audit log
        self.audit.log(
            event_type="desanitize",
            original_text=text,
            sanitized_text=result,
            model=model,
            provider=provider,
            entity_count=token_map.entity_count,
            categories=token_map.categories,
            tokens_used=list(token_map.reverse.keys()),
            latency_ms=elapsed_ms,
            mode=self.config.mode,
            metadata=metadata,
        )

        return result

    def analyze(self, text: str) -> dict:
        """
        Analyze text for sensitive data without modifying it.
        Useful for previewing what would be detected.

        Returns a summary dict.
        """
        detections = self.detector.detect(text)
        return {
            "entity_count": len(detections),
            "entities": [
                {
                    "text": d.text,
                    "category": d.category,
                    "start": d.start,
                    "end": d.end,
                    "confidence": d.confidence,
                    "source": d.source,
                }
                for d in detections
            ],
        }

    def verify_audit(self) -> tuple[bool, list[str]]:
        """Verify the integrity of all audit logs."""
        return self.audit.verify_chain()

    def audit_stats(self) -> dict:
        """Get aggregate audit statistics."""
        return self.audit.get_stats()
