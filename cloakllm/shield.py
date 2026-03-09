"""
Shield — the main CloakLLM engine.

Ties together detection, tokenization, and audit logging into a single interface.
Can be used standalone or via the LiteLLM middleware integration.
"""

from __future__ import annotations

import hashlib
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
        self._metrics: dict[str, Any] = self._empty_metrics()

    @staticmethod
    def _empty_metrics() -> dict[str, Any]:
        return {
            "calls": {"sanitize": 0, "desanitize": 0, "sanitize_batch": 0, "desanitize_batch": 0},
            "total_ms": 0.0,
            "detection": {"regex_ms": 0.0, "ner_ms": 0.0, "llm_ms": 0.0},
            "tokenization_ms": 0.0,
            "entities_detected": 0,
            "categories": {},
        }

    def _accumulate_metrics(self, call_type: str, total_ms: float,
                            detection_timing: dict[str, float],
                            tokenization_ms: float, entity_count: int,
                            categories: dict[str, int]) -> None:
        self._metrics["calls"][call_type] += 1
        self._metrics["total_ms"] += total_ms
        for key in ("regex_ms", "ner_ms", "llm_ms"):
            self._metrics["detection"][key] += detection_timing.get(key, 0.0)
        self._metrics["tokenization_ms"] += tokenization_ms
        self._metrics["entities_detected"] += entity_count
        for cat, count in categories.items():
            self._metrics["categories"][cat] = self._metrics["categories"].get(cat, 0) + count

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
        t0 = time.perf_counter()
        detections, detection_timing = self.detector.detect(text)
        detection_ms = (time.perf_counter() - t0) * 1000

        # Ensure token_map has the correct mode
        if token_map is None:
            token_map = TokenMap(mode=self.config.mode)

        # Tokenize (replace with tokens)
        t0 = time.perf_counter()
        sanitized, token_map = self.tokenizer.tokenize(text, detections, token_map)
        tokenization_ms = (time.perf_counter() - t0) * 1000

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # Build timing breakdown
        timing = {
            "total_ms": round(elapsed_ms, 2),
            "detection_ms": round(detection_ms, 2),
            **{k: v for k, v in detection_timing.items()},
            "tokenization_ms": round(tokenization_ms, 2),
        }

        # Build tokens_used list — in redact mode, collect from detections
        if self.config.mode == "redact":
            tokens_used = list({f"[{d.category}_REDACTED]" for d in detections})
        else:
            tokens_used = list(token_map.reverse.keys())

        # Accumulate metrics
        self._accumulate_metrics(
            "sanitize", elapsed_ms, detection_timing,
            tokenization_ms, len(detections), token_map.categories,
        )

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
            timing=timing,
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
        combined_detection_timing: dict[str, float] = {"regex_ms": 0.0, "ner_ms": 0.0, "llm_ms": 0.0}
        total_detection_ms = 0.0
        total_tokenization_ms = 0.0

        for text_index, text in enumerate(texts):
            t0 = time.perf_counter()
            detections, detection_timing = self.detector.detect(text)
            total_detection_ms += (time.perf_counter() - t0) * 1000
            for key in ("regex_ms", "ner_ms", "llm_ms"):
                combined_detection_timing[key] += detection_timing.get(key, 0.0)

            t0 = time.perf_counter()
            sanitized, token_map = self.tokenizer.tokenize(text, detections, token_map)
            total_tokenization_ms += (time.perf_counter() - t0) * 1000

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

        # Build timing breakdown
        timing = {
            "total_ms": round(elapsed_ms, 2),
            "detection_ms": round(total_detection_ms, 2),
            **{k: round(v, 2) for k, v in combined_detection_timing.items()},
            "tokenization_ms": round(total_tokenization_ms, 2),
        }

        # Build tokens_used list
        if self.config.mode == "redact":
            tokens_used = list({d["token"] for d in all_entity_details})
        else:
            tokens_used = list(token_map.reverse.keys())

        # Accumulate metrics
        self._accumulate_metrics(
            "sanitize_batch", elapsed_ms, combined_detection_timing,
            total_tokenization_ms, total_detections, token_map.categories,
        )

        # Build per-text hashes for audit metadata
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
            timing=timing,
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

        t0 = time.perf_counter()
        results = [self.tokenizer.detokenize(text, token_map) for text in texts]
        tokenization_ms = (time.perf_counter() - t0) * 1000

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        timing = {
            "total_ms": round(elapsed_ms, 2),
            "tokenization_ms": round(tokenization_ms, 2),
        }

        # Accumulate metrics
        self._metrics["calls"]["desanitize_batch"] += 1
        self._metrics["total_ms"] += elapsed_ms
        self._metrics["tokenization_ms"] += tokenization_ms

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
            timing=timing,
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

        t0 = time.perf_counter()
        result = self.tokenizer.detokenize(text, token_map)
        tokenization_ms = (time.perf_counter() - t0) * 1000

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        timing = {
            "total_ms": round(elapsed_ms, 2),
            "tokenization_ms": round(tokenization_ms, 2),
        }

        # Accumulate metrics
        self._metrics["calls"]["desanitize"] += 1
        self._metrics["total_ms"] += elapsed_ms
        self._metrics["tokenization_ms"] += tokenization_ms

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
            timing=timing,
            metadata=metadata,
        )

        return result

    def analyze(self, text: str) -> dict:
        """
        Analyze text for sensitive data without modifying it.
        Useful for previewing what would be detected.

        Returns a summary dict.
        """
        detections, _ = self.detector.detect(text)
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

    def metrics(self) -> dict:
        """Return accumulated performance metrics for this Shield instance."""
        total_calls = sum(self._metrics["calls"].values())
        return {
            "calls": dict(self._metrics["calls"]),
            "total_ms": round(self._metrics["total_ms"], 2),
            "avg_ms": round(self._metrics["total_ms"] / total_calls, 2) if total_calls else 0.0,
            "detection": {k: round(v, 2) for k, v in self._metrics["detection"].items()},
            "tokenization_ms": round(self._metrics["tokenization_ms"], 2),
            "entities_detected": self._metrics["entities_detected"],
            "categories": dict(self._metrics["categories"]),
        }

    def reset_metrics(self) -> None:
        """Reset accumulated performance metrics."""
        self._metrics = self._empty_metrics()

    def verify_audit(self) -> tuple[bool, list[str]]:
        """Verify the integrity of all audit logs."""
        return self.audit.verify_chain()

    def audit_stats(self) -> dict:
        """Get aggregate audit statistics."""
        return self.audit.get_stats()
