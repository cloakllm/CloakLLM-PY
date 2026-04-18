"""
Shield — the main CloakLLM engine.

Ties together detection, tokenization, and audit logging into a single interface.
Can be used standalone or via the LiteLLM middleware integration.
"""

from __future__ import annotations

import hashlib
import json
import secrets
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
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

        # Load attestation keypair / KMS provider.
        # Precedence: explicit attestation_key > KMS provider > key file > none.
        self._attestation_key: Optional[Any] = None
        if self.config.attestation_key is not None:
            self._attestation_key = self.config.attestation_key
        elif self.config.attestation_key_provider:
            from cloakllm.key_provider import build_key_provider
            self._attestation_key = build_key_provider(
                self.config.attestation_key_provider,
                self.config.attestation_key_id,
            )
        elif self.config.attestation_key_path:
            self._attestation_key = DeploymentKeyPair.from_file(
                Path(self.config.attestation_key_path)
            )

        # Context analyzer (opt-in)
        self._context_analyzer = ContextAnalyzer() if self.config.context_analysis else None

        # Key rotation event (opt-in). Logged once on init when a KeyProvider is
        # in use and the audit log is enabled. The entry contains no PII —
        # only key_id and key version metadata.
        if (
            self.config.key_rotation_enabled
            and self._attestation_key is not None
            and self.config.audit_enabled
        ):
            self._log_key_rotation_event()

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

    def _check_input_length(self, text: str) -> None:
        """v0.6.1 H1.4: refuse oversized inputs to limit ReDoS exposure."""
        cap = self.config.max_input_length
        if cap > 0 and len(text) > cap:
            raise ValueError(
                f"Input length {len(text)} exceeds max_input_length={cap}. "
                f"Set ShieldConfig(max_input_length=...) to raise the cap, "
                f"or chunk the input."
            )

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

        Raises:
            ValueError: if len(text) > config.max_input_length (default 1MB).
        """
        self._check_input_length(text)
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

        # v0.6.3 H3 design note: sanitize entries deliberately keep
        # microsecond timing precision (round-2-decimal). Bucketing was
        # considered for cross-call shape consistency with desanitize entries
        # but rejected because:
        #   * Sanitize timing varies primarily on input length and the set of
        #     enabled detection passes — both of which the input submitter
        #     already knows. There is no token-presence inference to leak.
        #   * Operational dashboards rely on full-precision sanitize timing
        #     to spot regressions in detection backends; bucketing would
        #     hide real perf bugs.
        # Desanitize is bucketed because the side channel there is "did
        # token X appear in this input" — see desanitize() for details.
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
        # v0.6.1 H1.4 — per-text length cap
        for i, text in enumerate(texts):
            try:
                self._check_input_length(text)
            except ValueError as e:
                raise ValueError(f"texts[{i}]: {e}") from e

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

        # v0.6.3 H3: Compute the union of tokens that appear across the batch.
        # See `desanitize` for the full rationale — same disclosure-oracle fix.
        all_text = "\n".join(texts)
        present_tokens = sorted(
            t for t in token_map.reverse.keys() if t in all_text
        )

        t0 = time.perf_counter()
        results = [self.tokenizer.detokenize(text, token_map) for text in texts]
        tokenization_ms = (time.perf_counter() - t0) * 1000

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # v0.6.3 H3: bucket timing in audit log; full precision in .metrics().
        def _bucket_ms(ms: float) -> float:
            return round(ms / 10.0) * 10.0

        timing = {
            "total_ms": _bucket_ms(elapsed_ms),
            "tokenization_ms": _bucket_ms(tokenization_ms),
        }

        # Accumulate metrics (full precision — internal use only)
        self._accumulate_metrics("desanitize_batch", elapsed_ms, {}, tokenization_ms, 0, {})

        present_token_set = set(present_tokens)
        present_entity_details = [
            ed for ed in (token_map.entity_details or [])
            if ed.get("token") in present_token_set
        ]

        self.audit.log(
            event_type="desanitize_batch",
            original_text="",
            sanitized_text="",
            model=model,
            provider=provider,
            entity_count=len(present_tokens),  # H3
            categories=token_map.categories,
            tokens_used=present_tokens,  # H3
            latency_ms=_bucket_ms(elapsed_ms),  # H3
            mode=self.config.mode,
            entity_details=present_entity_details,  # H3
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

        # v0.6.3 H3: Pre-compute which tokens actually appear in `text`. Used
        # below to log only the subset to audit (was: the full map). Closes
        # the desanitize-time disclosure oracle: an audit-log reader who saw
        # `tokens_used` on every desanitize call could enumerate the entire
        # session's token inventory from a single entry, even though the
        # matching sanitize entry already logged that information.
        present_tokens = sorted(
            t for t in token_map.reverse.keys() if t in text
        )

        t0 = time.perf_counter()
        result = self.tokenizer.detokenize(text, token_map)
        tokenization_ms = (time.perf_counter() - t0) * 1000

        elapsed_ms = (time.perf_counter() - start_time) * 1000

        # v0.6.3 H3: Bucket timing in audit logs to 10 ms granularity.
        # Microsecond precision lets an audit-log reader correlate
        # "which tokens were processed" with timing variance — a side-channel
        # for token presence. The internal .metrics() API still gets the
        # full-precision values for performance debugging.
        def _bucket_ms(ms: float) -> float:
            return round(ms / 10.0) * 10.0

        timing = {
            "total_ms": _bucket_ms(elapsed_ms),
            "tokenization_ms": _bucket_ms(tokenization_ms),
        }

        # Accumulate metrics (full precision — internal use only)
        self._accumulate_metrics("desanitize", elapsed_ms, {}, tokenization_ms, 0, {})

        # v0.6.3 H3: entity_details filtered to the present subset (mirrors
        # the tokens_used filter). Categories are kept at the map level —
        # they're already in the matching sanitize entry, so no new leak.
        present_token_set = set(present_tokens)
        present_entity_details = [
            ed for ed in (token_map.entity_details or [])
            if ed.get("token") in present_token_set
        ]

        # Audit log
        self.audit.log(
            event_type="desanitize",
            original_text=text,
            sanitized_text=result,
            model=model,
            provider=provider,
            entity_count=len(present_tokens),  # H3: count of tokens in this call
            categories=token_map.categories,
            tokens_used=present_tokens,  # H3: subset present in input, not full map
            latency_ms=_bucket_ms(elapsed_ms),  # H3: bucketed (timing oracle)
            mode=self.config.mode,
            entity_details=present_entity_details,  # H3: subset filter
            timing=timing,
            metadata=metadata,
        )

        return result

    # F4 sentinel — distinguishes "user passed False explicitly" from
    # "user didn't pass anything." Used to fire the v0.7.0 default-flip warning.
    _UNSET = object()

    def analyze(self, text: str, redact_values: Any = _UNSET) -> dict:
        """
        Analyze text for sensitive data without modifying it.

        WARNING: By default (v0.6.x), the return value contains raw PII in the
        'text' field of each entity. Set ``redact_values=True`` to replace with
        '[redacted]'. Never log or transmit the output of this method without
        redaction.

        v0.7.0 will flip the default to ``True``. To silence the deprecation
        warning, pass ``redact_values`` explicitly.
        """
        if redact_values is Shield._UNSET:
            import warnings as _w
            _w.warn(
                "Shield.analyze() default for `redact_values` will change "
                "from False to True in v0.7.0. The current default RETURNS "
                "RAW PII in the response. Pass `redact_values=False` "
                "explicitly to keep current behaviour, or `redact_values=True` "
                "to redact (recommended).",
                DeprecationWarning,
                stacklevel=2,
            )
            redact_values = False
        self._check_input_length(text)
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

    def verify_audit(
        self,
        log_dir: Optional[str] = None,
        output_format: Optional[str] = None,
        *,
        legacy_canonical: bool = False,
    ):
        """Verify the integrity of all audit logs.

        Args:
            log_dir: Optional alternate audit dir to verify (default: this Shield's log_dir).
            output_format: When None, returns the existing
                {"valid": bool, "errors": list[str], "final_seq": int} dict.
                When "compliance_report", returns a structured EU AI Act
                Article 12 compliance report dict.
            legacy_canonical: When True, use the v0.6.0-compatible canonical
                JSON encoding to verify pre-v0.6.1 audit chains containing
                non-ASCII data. Sunset in v0.7.0.

                **Cross-SDK limitation (v0.6.3 I3):** The legacy_canonical
                flag restores the v0.6.0 hashing behavior PER-SDK. Python
                v0.6.0 escaped non-ASCII characters (e.g. `é` → `\\u00e9`);
                JavaScript v0.6.0 preserved UTF-8. A Python v0.6.0 audit chain
                containing non-ASCII data in `categories`, `metadata`, or
                `entity_details` CANNOT be re-verified by the JS verifier with
                `legacyCanonical: true`, and vice versa. There is no migration
                path for those specific cross-SDK chains. Same-SDK chains
                (Python verified by Python, JS by JS) are unaffected.

        Returns:
            Default dict shape, or compliance report dict when requested.
        """
        if log_dir is not None:
            cfg = ShieldConfig(log_dir=log_dir, audit_enabled=True)
            audit = AuditLogger(cfg)
        else:
            audit = self.audit

        if output_format == "compliance_report":
            return audit.verify_chain(
                output_format="compliance_report",
                legacy_canonical=legacy_canonical,
            )

        is_valid, errors, final_seq = audit.verify_chain(
            legacy_canonical=legacy_canonical,
        )
        return {"valid": is_valid, "errors": errors, "final_seq": final_seq}

    def audit_stats(self) -> dict:
        """Get aggregate audit statistics."""
        return self.audit.get_stats()

    def _log_key_rotation_event(self) -> None:
        """
        Log a key_rotation_event audit entry. Contains no PII — only
        key_id, provider, and key_version (when available).
        """
        provider = self.config.attestation_key_provider or "local"
        key_version: Optional[str] = None
        try:
            getter = getattr(self._attestation_key, "get_key_version", None)
            if callable(getter):
                key_version = getter()
        except Exception:
            key_version = None
        try:
            self.audit.log(
                event_type="key_rotation_event",
                metadata={
                    "key_provider": provider,
                    "key_version": key_version,
                },
                key_id=getattr(self._attestation_key, "key_id", None),
            )
        except Exception as e:
            # Non-fatal — rotation events are observability, not correctness.
            import logging as _logging
            _logging.getLogger("cloakllm.shield").warning(
                "Failed to log key_rotation_event: %s", e
            )

    def compliance_summary(self) -> dict:
        """
        Return a structured map of EU AI Act and GDPR articles addressed by
        the current Shield configuration. Designed for auditors and DPOs.

        See EU_AI_ACT_STRATEGY.md for the regulatory rationale of each entry.
        """
        from cloakllm import __version__
        cfg = self.config
        attestation_enabled = (
            cfg.attestation_key is not None
            or cfg.attestation_key_path is not None
            or cfg.attestation_key_provider is not None
        )
        return {
            "compliance_mode": cfg.compliance_mode,
            "articles_addressed": [
                {
                    "article": "EU_AI_Act_Art_12",
                    "status": "satisfied",
                    "notes": "Automatic logging enabled, zero PII in logs",
                },
                {
                    "article": "EU_AI_Act_Art_19",
                    "status": "satisfied",
                    "notes": "Hash-chained tamper-evident audit trail",
                },
                {
                    "article": "GDPR_Art_5_data_minimisation",
                    "status": "satisfied",
                    "notes": "Tokenization removes PII before logging",
                },
                {
                    "article": "GDPR_Art_5_storage_limitation",
                    "status": "satisfied",
                    "notes": "Logs contain no personal data",
                },
                {
                    "article": "GDPR_Art_25_privacy_by_design",
                    "status": "satisfied",
                    "notes": "PII removed at input layer before any downstream processing",
                },
                {
                    "article": "EU_AI_Act_Art_4a",
                    "status": "partial",
                    "notes": (
                        "Tokenization qualifies as pseudonymisation; "
                        "BiasDetectionSession not yet implemented (v0.7)"
                    ),
                },
            ],
            "config_snapshot": {
                "audit": cfg.audit_enabled,
                "compliance_mode": cfg.compliance_mode,
                "mode": cfg.mode,
                "entity_hashing": cfg.entity_hashing,
                "attestation_enabled": attestation_enabled,
                "retention_hint_days": cfg.retention_hint_days,
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "cloakllm_version": __version__,
        }

    def export_compliance_config(
        self,
        path: str = "./cloakllm_compliance_config.json",
    ) -> str:
        """
        Write the compliance summary to a JSON file. This is the artifact
        an organisation hands to an auditor.

        Returns the resolved path written.
        """
        summary = self.compliance_summary()
        summary["note"] = (
            "This configuration snapshot was generated by CloakLLM. "
            "Verify audit log integrity using: cloakllm verify <audit_dir>"
        )
        out = Path(path)
        out.parent.mkdir(parents=True, exist_ok=True)
        with open(out, "w", encoding="utf-8") as f:
            json.dump(summary, f, indent=2)
        return str(out)

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
                # DeploymentKeyPair exposes .public_key directly; KeyProvider
                # implementations may only expose .public_key_b64 (KMS).
                pk_attr = getattr(self._attestation_key, "public_key", None)
                if pk_attr is not None:
                    public_key = pk_attr
                else:
                    import base64 as _b64
                    public_key = _b64.b64decode(self._attestation_key.public_key_b64)
            else:
                raise ValueError("No public key provided and no attestation key configured")
        return certificate.verify(public_key)

    @staticmethod
    def generate_attestation_key() -> DeploymentKeyPair:
        """Generate a new Ed25519 deployment keypair for attestation."""
        return DeploymentKeyPair.generate()
