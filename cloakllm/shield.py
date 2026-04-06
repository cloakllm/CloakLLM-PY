"""
Shield — the main CloakLLM engine.

Ties together detection, tokenization, and audit logging into a single interface.
Can be used standalone or via the LiteLLM middleware integration.
"""

from __future__ import annotations

import hashlib
import secrets
import threading
import time
from typing import Any, Optional

from cloakllm.audit import AuditLogger
from cloakllm.config import ShieldConfig
from cloakllm.detector import DetectionEngine
from cloakllm.tokenizer import TokenMap, Tokenizer
from cloakllm.attestation import (
    DeploymentKeyPair,
    MerkleTree,
    SanitizationCertificate,
)
from cloakllm.context_analyzer import ContextAnalyzer


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

    def __init__(self, config: Optional[ShieldConfig] = None, backends: Optional[list] = None):
        self.config = config or ShieldConfig()
        self.detector = DetectionEngine(self.config, backends=backends)
        self.tokenizer = Tokenizer(self.config)
        self.audit = AuditLogger(self.config)
        self._metrics: dict[str, Any] = self._empty_metrics()
        self._metrics_lock = threading.Lock()
        # Resolve entity hash key once (auto-generate if needed)
        if self.config.entity_hashing and not self.config.entity_hash_key:
            self.config.entity_hash_key = secrets.token_hex(32)

        # Load attestation keypair (from config object or file path)
        self._attestation_key: Optional[DeploymentKeyPair] = None
        if self.config.attestation_key is not None:
            self._attestation_key = self.config.attestation_key
        elif self.config.attestation_key_path:
            from pathlib import Path
            self._attestation_key = DeploymentKeyPair.from_file(
                Path(self.config.attestation_key_path)
            )

        # Context analyzer (opt-in)
        self._context_analyzer = ContextAnalyzer() if self.config.context_analysis else None

    def _empty_metrics(self) -> dict[str, Any]:
        backends = getattr(self, 'detector', None)
        detection_keys = {f"{b.name}_ms": 0.0 for b in (backends._backends if backends else [])}
        if not detection_keys:
            detection_keys = {"regex_ms": 0.0, "ner_ms": 0.0, "llm_ms": 0.0}
        return {
            "calls": {"sanitize": 0, "desanitize": 0, "sanitize_batch": 0, "desanitize_batch": 0},
            "total_ms": 0.0,
            "detection": detection_keys,
            "tokenization_ms": 0.0,
            "entities_detected": 0,
            "categories": {},
        }

    def _accumulate_metrics(self, call_type: str, total_ms: float,
                            detection_timing: dict[str, float],
                            tokenization_ms: float, entity_count: int,
                            categories: dict[str, int]) -> None:
        with self._metrics_lock:
            self._metrics["calls"][call_type] += 1
            self._metrics["total_ms"] += total_ms
            for key, value in detection_timing.items():
                if key not in self._metrics["detection"]:
                    self._metrics["detection"][key] = 0.0
                self._metrics["detection"][key] += value
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
            token_map = TokenMap(
                mode=self.config.mode,
                entity_hashing=self.config.entity_hashing,
                entity_hash_key=self.config.entity_hash_key,
            )

        # Clear per-call metadata (preserves forward/reverse maps for multi-turn)
        token_map.detections.clear()

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

        # Create attestation certificate if signing key is configured
        cert_hash = None
        cert_key_id = None
        if self._attestation_key is not None:
            detection_passes = [b.name for b in self.detector._backends]
            cert = SanitizationCertificate.create(
                original_text=text,
                sanitized_text=sanitized,
                entity_count=len(detections),
                categories=token_map.categories,
                detection_passes=detection_passes,
                mode=self.config.mode,
                keypair=self._attestation_key,
            )
            token_map.certificate = cert
            cert_hash = hashlib.sha256(cert.signature.encode()).hexdigest()
            cert_key_id = cert.key_id

        # Context risk analysis (opt-in)
        risk_assessment = None
        if self._context_analyzer is not None:
            import logging as _logging
            risk = self._context_analyzer.analyze(sanitized)
            risk_assessment = risk.to_dict()
            token_map.risk_assessment = risk_assessment
            if risk.risk_score > self.config.context_risk_threshold:
                _logging.getLogger("cloakllm").warning(
                    "Context risk %.2f (%s) exceeds threshold %.2f",
                    risk.risk_score, risk.risk_level, self.config.context_risk_threshold,
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
            certificate_hash=cert_hash,
            key_id=cert_key_id,
            risk_assessment=risk_assessment,
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
            token_map = TokenMap(
                mode=self.config.mode,
                entity_hashing=self.config.entity_hashing,
                entity_hash_key=self.config.entity_hash_key,
            )

        # Clear per-call metadata (preserves forward/reverse maps for multi-turn)
        token_map.detections.clear()

        sanitized_texts = []
        all_entity_details = []
        total_detections = 0
        combined_detection_timing: dict[str, float] = {}
        total_detection_ms = 0.0
        total_tokenization_ms = 0.0

        for text_index, text in enumerate(texts):
            t0 = time.perf_counter()
            detections, detection_timing = self.detector.detect(text)
            total_detection_ms += (time.perf_counter() - t0) * 1000
            for key, value in detection_timing.items():
                combined_detection_timing[key] = combined_detection_timing.get(key, 0.0) + value

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
                detail = {
                    "category": det.category,
                    "start": det.start,
                    "end": det.end,
                    "length": det.end - det.start,
                    "confidence": det.confidence,
                    "source": det.source,
                    "token": token,
                    "text_index": text_index,
                }
                if token_map.entity_hashing and token_map.entity_hash_key:
                    detail["entity_hash"] = token_map._compute_entity_hash(det.category, det.text)
                all_entity_details.append(detail)

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

        # Create batch attestation certificate with Merkle roots
        cert_hash = None
        cert_key_id = None
        if self._attestation_key is not None:
            input_hashes = [hashlib.sha256(t.encode()).hexdigest() for t in texts]
            output_hashes = [hashlib.sha256(t.encode()).hexdigest() for t in sanitized_texts]
            input_tree = MerkleTree(input_hashes)
            output_tree = MerkleTree(output_hashes)

            detection_passes = [b.name for b in self.detector._backends]

            cert = SanitizationCertificate.create(
                original_text=None,
                sanitized_text=None,
                entity_count=total_detections,
                categories=token_map.categories,
                detection_passes=detection_passes,
                mode=self.config.mode,
                keypair=self._attestation_key,
                input_merkle_root=input_tree.root,
                output_merkle_root=output_tree.root,
            )
            token_map.certificate = cert
            token_map.batch_certificate = cert
            token_map.merkle_tree = {
                "input": input_tree,
                "output": output_tree,
            }
            cert_hash = hashlib.sha256(cert.signature.encode()).hexdigest()
            cert_key_id = cert.key_id

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
            certificate_hash=cert_hash,
            key_id=cert_key_id,
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
        self._accumulate_metrics("desanitize_batch", elapsed_ms, {}, tokenization_ms, 0, {})

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
        self._accumulate_metrics("desanitize", elapsed_ms, {}, tokenization_ms, 0, {})

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

    def analyze(self, text: str, redact_values: bool = False) -> dict:
        """
        Analyze text for sensitive data without modifying it.

        WARNING: By default, the return value contains raw PII in the 'text'
        field of each entity. Set redact_values=True to replace with '[redacted]'.
        Never log or transmit the output of this method without redaction.
        """
        detections, _ = self.detector.detect(text)
        return {
            "entity_count": len(detections),
            "entities": [
                {
                    "text": "[redacted]" if redact_values else d.text,
                    "category": d.category,
                    "start": d.start,
                    "end": d.end,
                    "confidence": d.confidence,
                    "source": d.source,
                }
                for d in detections
            ],
        }

    def analyze_context_risk(self, sanitized_text: str) -> dict:
        """
        Analyze sanitized text for context-based PII leakage risk.

        This is a standalone method that can be called on any sanitized text,
        regardless of the context_analysis config flag.

        Args:
            sanitized_text: Text containing [CATEGORY_N] tokens

        Returns:
            dict with token_density, identifying_descriptors, relationship_edges,
            risk_score, risk_level, and warnings
        """
        analyzer = ContextAnalyzer()
        return analyzer.analyze(sanitized_text).to_dict()

    def metrics(self) -> dict:
        """Return accumulated performance metrics for this Shield instance."""
        with self._metrics_lock:
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
        with self._metrics_lock:
            self._metrics = self._empty_metrics()

    def verify_audit(self) -> dict:
        """Verify the integrity of all audit logs.

        Returns a dict with 'valid' (bool), 'errors' (list[str]), and 'final_seq' (int).
        """
        is_valid, errors, final_seq = self.audit.verify_chain()
        return {"valid": is_valid, "errors": errors, "final_seq": final_seq}

    def audit_stats(self) -> dict:
        """Get aggregate audit statistics."""
        return self.audit.get_stats()

    def verify_certificate(
        self,
        certificate: Any,
        public_key: Optional[bytes] = None,
    ) -> bool:
        """
        Verify a sanitization certificate's signature.

        Args:
            certificate: A SanitizationCertificate instance (or dict from cert.to_dict())
            public_key: Ed25519 public key bytes. If None, uses the Shield's attestation key.

        Returns:
            True if signature is valid, False otherwise.
        """
        if isinstance(certificate, dict):
            certificate = SanitizationCertificate.from_dict(certificate)
        if public_key is None:
            if self._attestation_key is not None:
                public_key = self._attestation_key.public_key
            else:
                raise ValueError("No public key provided and no attestation key configured")
        return certificate.verify(public_key)

    @staticmethod
    def generate_attestation_key() -> DeploymentKeyPair:
        """Generate a new Ed25519 deployment keypair for attestation."""
        return DeploymentKeyPair.generate()
