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
            entity_details=token_map.entity_details,
            metadata=metadata,
        )

        return sanitized, token_map

    def sanitize_batch(
        self,
        texts: list[str],
        token_map: Optional[TokenMap] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> tuple[list[str], TokenMap]:
        """
        Sanitize multiple texts with a shared token map and single audit entry.

        Args:
            texts: List of texts potentially containing sensitive data
            token_map: Existing TokenMap for multi-turn conversations
            model: LLM model name (for audit logging)
            provider: LLM provider name (for audit logging)
            metadata: Additional context to log

        Returns:
            (list_of_sanitized_texts, token_map)
        """
        start_time = time.perf_counter()

        if token_map is None:
            token_map = TokenMap(mode=self.config.mode)

        sanitized_texts = []
        all_entity_details = []
        total_detections = 0

        for text_index, text in enumerate(texts):
            detections = self.detector.detect(text)
            sanitized, token_map = self.tokenizer.tokenize(text, detections, token_map)
            sanitized_texts.append(sanitized)
            total_detections += len(detections)

            # Build entity details with text_index
            for det in detections:
                if self.config.mode == "redact":
                    token = f"[{det.category}_REDACTED]"
                else:
                    key = det.text.strip()
                    token = token_map.forward.get(key, "")
                all_entity_details.append({
                    "category": det.category,
                    "start": det.start,
                    "end": det.end,
                    "length": det.end - det.start,
                    "confidence": det.confidence,
                    "source": det.source,
                    "token": token,
                    "text_index": text_index,
                })

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Build tokens_used list
        if self.config.mode == "redact":
            tokens_used = list({d["token"] for d in all_entity_details})
        else:
            tokens_used = list(token_map.reverse.keys())

        # Build per-text hashes for audit metadata
        import hashlib
        audit_metadata = dict(metadata) if metadata else {}
        audit_metadata["prompt_hashes"] = [
            hashlib.sha256(t.encode()).hexdigest() for t in texts
        ]
        audit_metadata["sanitized_hashes"] = [
            hashlib.sha256(t.encode()).hexdigest() for t in sanitized_texts
        ]

        self.audit.log(
            event_type="sanitize_batch",
            original_text="",
            sanitized_text="",
            model=model,
            provider=provider,
            entity_count=total_detections,
            categories=token_map.categories,
            tokens_used=tokens_used,
            latency_ms=elapsed_ms,
            mode=self.config.mode,
            entity_details=all_entity_details,
            metadata=audit_metadata,
        )

        return sanitized_texts, token_map

    def desanitize_batch(
        self,
        texts: list[str],
        token_map: TokenMap,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> list[str]:
        """
        Desanitize multiple texts using a shared token map.

        Args:
            texts: List of texts containing tokens to restore
            token_map: TokenMap from the sanitize step
            model: LLM model name (for audit logging)
            provider: LLM provider name (for audit logging)
            metadata: Additional context to log

        Returns:
            List of desanitized texts with original values restored
        """
        start_time = time.perf_counter()

        results = [self.tokenizer.detokenize(text, token_map) for text in texts]

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        self.audit.log(
            event_type="desanitize_batch",
            original_text="",
            sanitized_text="",
            model=model,
            provider=provider,
            entity_count=token_map.entity_count,
            categories=token_map.categories,
            tokens_used=list(token_map.reverse.keys()),
            latency_ms=elapsed_ms,
            mode=self.config.mode,
            entity_details=token_map.entity_details,
            metadata=metadata,
        )

        return results

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
            entity_details=token_map.entity_details,
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
