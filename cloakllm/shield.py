"""
Shield — the main CloakLLM engine.

Ties together detection, tokenization, and audit logging into a single interface.
Can be used standalone or via the LiteLLM middleware integration.
"""

from __future__ import annotations

import hashlib
import json
import os
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
from cloakllm._ulid import generate_ulid


def _compose_system_version_pin(
    model: Optional[str],
    deployment_version: Optional[str],
    instruction_version: Optional[str],
) -> Optional[str]:
    """v0.7.1 C7.1-2: compose system_version_pin from three components.

    Returns the composed string (`<model>@<deployment>/<instruction>`) only
    when all three components are present. Partial pins are returned as None
    so deployer can't accidentally publish a half-specified version pin and
    have it be mistaken for a complete record.
    """
    if not model or not deployment_version or not instruction_version:
        return None
    return f"{model}@{deployment_version}/{instruction_version}"


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

        # v0.9.0 RV-3 (Open Q3 locked): fail-hard when this Shield's OWN
        # signing key appears in the configured revocation list. Signing
        # with a revoked key is always a mistake -- the v0.8.2 "don't
        # surprise the deployer" doctrine. Runs BEFORE key_registered
        # emission so a revoked key never gets re-registered either.
        if (
            self._attestation_key is not None
            and self.config.revocation_list_path
        ):
            self._check_own_key_not_revoked()

        # v0.8.1 KM-3: emit a key_registered event once on init when the
        # deployer has set deployer_id (the trigger for the externally-
        # verifiable provenance flow). Allow-duplicate emission: concurrent
        # Shield inits with the same key both emit; verifier dedups by
        # manifest_hash. See PLAN_v081.md Decision 3.
        if (
            self._attestation_key is not None
            and self.config.audit_enabled
            and self.config.deployer_id
        ):
            self._emit_key_registered_event()

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
        decision_id: Optional[str] = None,
    ) -> tuple[str, TokenMap]:
        """
        Detect and replace sensitive entities in text.

        Args:
            text: Text potentially containing sensitive data
            token_map: Existing TokenMap for multi-turn conversations
            model: LLM model name (for audit logging)
            provider: LLM provider name (for audit logging)
            metadata: Additional context to log
            decision_id: Optional per-inference audit anchor. If omitted, a
                fresh ULID is auto-generated. All audit entries for a single
                user-facing AI decision should share this ID; pass it through
                from sanitize() to the matching desanitize() so both entries
                are reconciled in compliance reports. v0.7.1.

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

        # v0.7.1 C7.1-1: decision_id resolution.
        #   - Caller-supplied wins
        #   - Otherwise: auto-generate a fresh ULID
        # Store on token_map so the matching desanitize() can read it back
        # without the caller having to thread the ID through their LLM call.
        resolved_decision_id = decision_id or generate_ulid()
        token_map.decision_id = resolved_decision_id

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
            # v0.7.1 C7.1-1 / C7.1-2: compliance-schema extensions
            decision_id=resolved_decision_id,
            system_version_pin=_compose_system_version_pin(
                model, self.config.deployment_version, self.config.instruction_version,
            ),
        )

        return sanitized, token_map

    def sanitize_batch(
        self,
        texts: list[str],
        token_map: Optional[TokenMap] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        decision_id: Optional[str] = None,
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

        # v0.7.1 C7.1-1: same decision_id resolution as sanitize().
        resolved_decision_id = decision_id or generate_ulid()
        token_map.decision_id = resolved_decision_id

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
            # v0.7.1 C7.1-1 / C7.1-2
            decision_id=resolved_decision_id,
            system_version_pin=_compose_system_version_pin(
                model, self.config.deployment_version, self.config.instruction_version,
            ),
        )

        return sanitized_texts, token_map

    def desanitize_batch(
        self,
        texts: list[str],
        token_map: TokenMap,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        decision_id: Optional[str] = None,
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

        # v0.7.1 C7.1-1: same decision_id resolution as desanitize().
        resolved_decision_id = decision_id or getattr(token_map, "decision_id", None)

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
            # v0.7.1 C7.1-1 / C7.1-2
            decision_id=resolved_decision_id,
            system_version_pin=_compose_system_version_pin(
                model, self.config.deployment_version, self.config.instruction_version,
            ),
        )

        return results

    def desanitize(
        self,
        text: str,
        token_map: TokenMap,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        metadata: Optional[dict[str, Any]] = None,
        decision_id: Optional[str] = None,
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

        # v0.6.3 G2 (PII hash oracle fix): pass `text` (the tokenized input)
        # for BOTH original_text AND sanitized_text. Previously sanitized_text
        # was `result` — the restored PII — and `sanitized_hash` therefore
        # equaled sha256(restored_PII). An attacker with audit log read access
        # could hash candidate PII (sha256("123-45-6789") for SSNs, common
        # email formats) and confirm matches against `sanitized_hash`. This
        # is a direct PII oracle in production audit logs.
        #
        # New semantics for desanitize entries:
        #   prompt_hash    = sha256(tokenized_input_text)
        #   sanitized_hash = sha256(tokenized_input_text)  (same as prompt_hash)
        #
        # The `result` (restored PII) is NEVER hashed and NEVER in the log.
        # Pre-v0.6.3 chains can be re-verified with
        #   shield.verify_audit(legacy_desanitize_hash=True)
        # See verify_chain() for the deprecation path (sunset v0.7.0).
        # v0.7.1 C7.1-1: decision_id propagation. Caller override wins;
        # otherwise inherit from token_map (set during the matching sanitize).
        resolved_decision_id = decision_id or getattr(token_map, "decision_id", None)

        self.audit.log(
            event_type="desanitize",
            original_text=text,
            sanitized_text=text,  # G2: was `result` (the oracle); now tokenized input
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
            # v0.7.1 C7.1-1 / C7.1-2
            decision_id=resolved_decision_id,
            system_version_pin=_compose_system_version_pin(
                model, self.config.deployment_version, self.config.instruction_version,
            ),
        )

        return result

    def analyze(self, text: str, redact_values: bool = True) -> dict:
        """
        Analyze text for sensitive data without modifying it.

        Returns detected entities with category / position / confidence /
        detection source. By default, the per-entity `text` field is replaced
        with ``"[redacted]"`` so the analysis output is itself PII-free.

        v0.7.1 C7.1-5: the default for ``redact_values`` flipped from False
        to True. The F4 deprecation warning has been in place since v0.6.1;
        callers who relied on the old default (raw PII in the response) must
        now pass ``redact_values=False`` explicitly. No warning is emitted
        when the value is explicit -- only the old default path is gone.
        """
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
            legacy_canonical: REMOVED in v0.9.0 (LC-1 phase 2). The kwarg
                remains in the signature for one more cycle so operators
                get an actionable ValueError (raised by verify_chain)
                instead of a bare TypeError. Hard-deleted in v1.0.
                Pre-v0.6.1 chains must be re-archived under a
                v0.6.1..v0.8.x release.

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

    def generate_compliance_report(
        self,
        period_from: Optional[str] = None,
        period_to: Optional[str] = None,
        articles: Optional[list[str]] = None,
        format: str = "json",
        out_path: Optional[str] = None,
        include_decisions: bool = False,
        revocation_list_path: Optional[str] = None,
    ) -> Any:
        """v0.8.0 CR8-1: produce a structured regulatory-output compliance
        report from this Shield's audit log.

        The report conforms to `examples/compliance_report_schema.json`. It
        aggregates evidence per EU AI Act article, computes per-decision_id
        rollups (optional), summarises certificate attestation, and emits a
        COMPLIANT / NON_COMPLIANT verdict with explicit reasons.

        Args:
            period_from: ISO 8601 UTC start (inclusive). None = unbounded.
            period_to: ISO 8601 UTC end (inclusive). None = unbounded.
            articles: optional whitelist (e.g. ["EU_AI_Act_Art_12",
                "EU_AI_Act_Art_4a"]). None = all articles found in the chain.
            format: "json" (returns dict), "markdown" (returns str), "pdf"
                (writes to out_path, requires `pip install cloakllm[reporting]`).
            out_path: when set, the report is also written to this path.
                Required for format="pdf".
            include_decisions: when True, the report includes a per-decision_id
                rollup (potentially large on high-volume chains).

        Returns:
            * format="json": the report dict (also writes to out_path if set)
            * format="markdown": the rendered Markdown string
            * format="pdf": the resolved out_path (file is written; nothing returned)

        Raises:
            ValueError: format unknown, or pdf format without out_path
            RuntimeError: pdf format requested but `reportlab` not installed
        """
        from cloakllm import __version__
        from cloakllm.compliance_report import (
            ReportPeriod, build_report,
        )

        if format not in ("json", "markdown", "pdf"):
            raise ValueError(
                f"Unknown report format {format!r}. Expected "
                f"'json' | 'markdown' | 'pdf'."
            )

        # v0.10.3 CRITICAL-1 fix: ACTUALLY verify the hash chain before
        # building the report. Previously this method loaded raw entries and
        # presumed the chain valid (build_report hardcoded chain_valid=True),
        # so a tampered audit log produced a regulator-facing "verified /
        # COMPLIANT" verdict -- the exact failure Article 19 attestation
        # exists to prevent. Now we run verify_chain and thread its real
        # verdict + anomalies into build_report.
        is_valid, chain_errors, _final_seq = self.audit.verify_chain()

        # Load entries from this Shield's audit log directory.
        entries = []
        log_dir = Path(self.config.log_dir)
        if log_dir.exists():
            for fp in sorted(log_dir.glob("audit_*.jsonl")):
                with open(fp, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            entries.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue  # mirrors verify_chain's tolerance

        # v0.9.0 RV-4: load the revocation list. Explicit arg wins; falls
        # back to config.revocation_list_path. None -> revocation fields
        # keep their false/null defaults (pre-v0.9.0 behavior).
        revocation_list = None
        rl_path = revocation_list_path or self.config.revocation_list_path
        if rl_path:
            from cloakllm.attestation import RevocationList
            try:
                rl_data = json.loads(
                    Path(rl_path).read_text(encoding="utf-8")
                )
                revocation_list = RevocationList.from_dict(rl_data)
            except Exception as e:
                raise RuntimeError(
                    f"generate_compliance_report: revocation list at "
                    f"{rl_path} could not be loaded "
                    f"({type(e).__name__}: {e})."
                ) from e

        # v0.11.0 TS-5: load deployer-supplied TSA trust anchors (PEM) so the
        # report's checkpoint verification can also confirm the chain-to-anchor.
        timestamp_trusted_certs = None
        tc_path = self.config.timestamp_trusted_certs_path
        if tc_path:
            try:
                pem_text = Path(tc_path).read_text(encoding="utf-8")
                # split a bundle into individual PEM certs
                import re as _re
                timestamp_trusted_certs = _re.findall(
                    r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                    pem_text, _re.DOTALL,
                ) or [pem_text]
            except Exception as e:
                raise RuntimeError(
                    f"generate_compliance_report: timestamp_trusted_certs_path "
                    f"at {tc_path} could not be loaded ({type(e).__name__}: {e})."
                ) from e

        report = build_report(
            audit_entries=entries,
            period=ReportPeriod(from_ts=period_from, to_ts=period_to),
            articles=articles,
            cloakllm_version=__version__,
            audit_dir=str(log_dir),
            include_decisions=include_decisions,
            revocation_list=revocation_list,
            chain_valid=is_valid,
            chain_anomalies=chain_errors,
            timestamp_trusted_certs=timestamp_trusted_certs,
        )

        # Render + optional write
        if format == "json":
            if out_path:
                Path(out_path).write_text(
                    json.dumps(report, indent=2) + "\n", encoding="utf-8",
                )
            return report

        if format == "markdown":
            from cloakllm.compliance_report import render_markdown
            md = render_markdown(report)
            if out_path:
                Path(out_path).write_text(md, encoding="utf-8")
            return md

        # format == "pdf"
        if not out_path:
            raise ValueError("format='pdf' requires out_path.")
        try:
            from cloakllm.compliance_report import render_pdf
        except ImportError as e:
            raise RuntimeError(
                "PDF output requires reportlab. Install with: "
                "pip install cloakllm[reporting]"
            ) from e
        render_pdf(report, out_path)
        return out_path

    def _check_own_key_not_revoked(self) -> None:
        """v0.9.0 RV-3 (Open Q3): raise RuntimeError if this Shield's own
        signing key appears in the configured revocation list with a
        revoked_at at or before now.

        Defensive on the list itself: an unreadable or tampered list raises
        too (a deployer who CONFIGURED revocation checking must not run
        blind when the check can't actually run -- same doctrine as the
        v0.8.2 Ed25519-backend fail-hard).
        """
        import json as _json
        from cloakllm.attestation import RevocationList

        key_id = getattr(self._attestation_key, "key_id", None)
        if not key_id:
            return  # KMS providers without a local key_id surface: skip.

        path = Path(self.config.revocation_list_path)
        try:
            data = _json.loads(path.read_text(encoding="utf-8"))
            rl = RevocationList.from_dict(data)
        except Exception as e:
            raise RuntimeError(
                f"Shield.__init__: revocation_list_path is set but the list "
                f"at {path} could not be loaded ({type(e).__name__}: {e}). "
                "Fix or unset CLOAKLLM_REVOCATION_LIST / "
                "ShieldConfig.revocation_list_path."
            ) from e

        entry = rl.find_entry(key_id)
        if entry is not None:
            now_iso = datetime.now(timezone.utc).isoformat()
            if entry.revoked_at <= now_iso:
                raise RuntimeError(
                    f"Shield.__init__: this Shield's signing key "
                    f"({key_id}) was REVOKED at {entry.revoked_at} "
                    f"(reason: {entry.reason}) per the revocation list at "
                    f"{path}. Signing with a revoked key is always a "
                    "mistake. Generate a new keypair, publish a new "
                    "KeyManifest, and update the deployment."
                )

    def checkpoint(self, tsa_url: Optional[str] = None) -> Optional[dict]:
        """v0.11.0 TS-3: stamp the audit chain's latest entry_hash at an RFC
        3161 Time-Stamp Authority and append a chain_checkpoint event.

        One checkpoint proves "every entry up to seq N existed no later than
        the TSA's genTime" -- by hash-chain induction it covers the whole
        chain before it. The TSA only ever receives the entry_hash (a hash of
        a no-PII entry); no content or PII leaves.

        Args:
            tsa_url: the TSA endpoint. Falls back to
                ShieldConfig.timestamp_authority_url / CLOAKLLM_TSA_URL.

        Returns:
            The written checkpoint_context dict, or None when no TSA is
            configured / there is nothing to stamp (empty chain).

        Raises:
            RuntimeError on a TSA/network failure (an EXPLICIT checkpoint call
            surfaces errors; the opt-in auto-cadence swallows them instead).
        """
        url = tsa_url or self.config.timestamp_authority_url
        if not url:
            return None
        if not self.config.audit_enabled:
            return None
        from cloakllm.audit import GENESIS_HASH
        # Ensure the audit logger has recovered its chain state from disk
        # (it is lazy-initialized on first write; checkpoint() may be the
        # first operation in a fresh process, e.g. the CLI).
        with self.audit._lock:
            self.audit._ensure_init()
        entry_hash = getattr(self.audit, "_prev_hash", GENESIS_HASH)
        if entry_hash == GENESIS_HASH:
            return None  # nothing written yet -> nothing to stamp
        stamped_seq = max(0, getattr(self.audit, "_seq", 1) - 1)

        from cloakllm.timestamping import request_timestamp
        try:
            digest = bytes.fromhex(entry_hash)  # entry_hash is sha256 hex
        except ValueError as e:
            raise RuntimeError(f"checkpoint: entry_hash is not hex: {e}") from e
        try:
            tst_token_b64 = request_timestamp(url, digest, "sha256")
        except Exception as e:
            raise RuntimeError(
                f"checkpoint: TSA request to {url} failed "
                f"({type(e).__name__}: {e})."
            ) from e

        checkpoint_context = {
            "stamped_entry_hash": entry_hash,
            "tsa_url": url,
            "tst_token_b64": tst_token_b64,
            "hash_algorithm": "sha256",
            "stamped_seq": stamped_seq,
        }
        self.audit.log(
            event_type="chain_checkpoint",
            checkpoint_context=checkpoint_context,
        )
        return checkpoint_context

    def record_content_generation(
        self,
        *,
        modality: str,
        synthetic: bool = True,
        labeled: bool = False,
        disclosure_method: str = "none",
        deepfake: bool = False,
        c2pa_manifest_hash: Optional[str] = None,
        content_hash: Optional[str] = None,
        model: Optional[str] = None,
        provider: Optional[str] = None,
        decision_id: Optional[str] = None,
    ) -> None:
        """v0.10.0 A50-2: write a content_generation audit event for EU AI
        Act Article 50 transparency record-keeping.

        Records that a synthetic-content generation occurred, by which
        system, and whether a machine-readable AI-generation label /
        deep-fake disclosure was applied -- WITHOUT the content ever
        entering CloakLLM. The caller hashes their own bytes and passes the
        digest as `content_hash`; CloakLLM never sees the asset (the
        no-content-in-logs invariant -- the Article 12 guarantee extended to
        Article 50). The event additionally satisfies Article 12 / 19
        record-keeping (article_ref=[Art_12,Art_19,Art_50] in compliance
        mode), so one compliance report proves them together.

        Args:
            modality: text | image | audio | video.
            synthetic: True if the output is artificially generated.
            labeled: True if a machine-readable AI-generation label was applied.
            disclosure_method: c2pa | watermark | metadata | visible_notice | none.
            deepfake: True for Article 50(4) deep-fake disclosure trigger.
            c2pa_manifest_hash: optional hash of a downstream C2PA manifest
                (forward-compat hook; pass None in v0.10.0 unless you embed one).
            content_hash: optional SHA-256 of the generated asset, computed
                caller-side. PII-safe (hash only, never the content).
            model: optional model identifier that generated the content.
            provider: optional provider (anthropic, openai, etc.).
            decision_id: optional per-inference audit anchor (threads through
                to reconcile this generation with other events for the same
                user-facing decision). Default: a fresh ULID.

        Raises:
            ValueError: on an invalid modality or disclosure_method (the
                audit-write boundary also re-validates via _validate_content_context).
        """
        from cloakllm.audit import (
            _CONTENT_MODALITY_WHITELIST, _CONTENT_DISCLOSURE_WHITELIST,
        )
        if modality not in _CONTENT_MODALITY_WHITELIST:
            raise ValueError(
                f"modality must be one of {sorted(_CONTENT_MODALITY_WHITELIST)} "
                f"(got {modality!r})"
            )
        if disclosure_method not in _CONTENT_DISCLOSURE_WHITELIST:
            raise ValueError(
                f"disclosure_method must be one of "
                f"{sorted(_CONTENT_DISCLOSURE_WHITELIST)} (got {disclosure_method!r})"
            )
        resolved_decision_id = decision_id or generate_ulid()
        content_context = {
            "modality": modality,
            "synthetic": bool(synthetic),
            "labeled": bool(labeled),
            "disclosure_method": disclosure_method,
            "deepfake": bool(deepfake),
            "c2pa_manifest_hash": c2pa_manifest_hash,
            "content_hash": content_hash,
        }
        self.audit.log(
            event_type="content_generation",
            model=model,
            provider=provider,
            content_context=content_context,
            decision_id=resolved_decision_id,
            system_version_pin=_compose_system_version_pin(
                model, self.config.deployment_version, self.config.instruction_version,
            ),
        )

    def record_key_revocation(
        self,
        key_id: str,
        reason: str,
        revoked_at: Optional[str] = None,
    ) -> None:
        """v0.9.0 RV-3: write an ADVISORY key_revoked event to the audit
        chain.

        This is the honest-deployer convenience record -- timeline
        visibility in compliance reports. It is explicitly NOT the
        security boundary: a compromised runtime would simply not call
        this. The boundary is the root-signed out-of-band RevocationList
        (see PLAN_v090.md Design Decision 1 / COMPLIANCE.md).

        Args:
            key_id: the revoked key's id (1..64 chars).
            reason: one of compromised | superseded | ceased_operation |
                unspecified (same whitelist as RevocationList entries).
            revoked_at: ISO 8601 UTC. Default: now.
        """
        from cloakllm.attestation import (
            _REVOCATION_REASON_WHITELIST, _validate_iso8601_utc,
        )
        if not isinstance(key_id, str) or not key_id or len(key_id) > 64:
            raise ValueError("key_id must be a non-empty string <= 64 chars")
        if reason not in _REVOCATION_REASON_WHITELIST:
            raise ValueError(
                f"reason must be one of {sorted(_REVOCATION_REASON_WHITELIST)}"
            )
        if revoked_at is None:
            revoked_at = datetime.now(timezone.utc).isoformat()
        _validate_iso8601_utc(revoked_at, "revoked_at")
        self.audit.log(
            event_type="key_revoked",
            key_id=key_id,
            metadata={
                "revoked_at": revoked_at,
                "reason": reason,
                "advisory": True,  # NOT the security boundary
            },
        )

    def _emit_key_registered_event(self) -> None:
        """v0.8.1 KM-3: emit a key_registered audit event binding the
        signing key to a KeyManifest.

        v0.8.2 fail-hard hardening: if the deployer explicitly opted in to
        KeyManifest (by setting deployer_id) but the Ed25519 backend is
        not installed, raise RuntimeError NOW instead of silently
        swallowing the ImportError and skipping the event. Silent
        degradation here undermines the entire externally-verifiable
        value proposition -- the deployer thinks they're emitting
        key_registered events but they aren't.

        Allow-duplicate emission policy (Decision 3 in PLAN_v081.md): two
        Shield processes starting concurrently with the same key both emit
        identical key_registered events. Verifier dedups by manifest_hash.
        No locking, no race window, audit chain stays append-only.

        Triggered on Shield.__init__ when ALL of:
          - audit logging is enabled
          - an attestation key is configured (key_path, kms provider, or explicit)
          - config.deployer_id is set
        """
        from cloakllm.attestation import (
            derive_key_manifest, _ed25519_backend_available,
            _ED25519_BACKEND_MISSING_MSG,
        )

        keypair = self._attestation_key
        if keypair is None:
            return  # No signing key -> nothing to bind a manifest to.

        # v0.8.2 fail-hard: detect backend-missing case BEFORE entering
        # the try/except. The deployer set deployer_id explicitly; failing
        # silently here means key_registered events never make it to the
        # chain and the auditor can't verify provenance later.
        #
        # KMS-backed keys (DeploymentKeyPair via KeyProvider) don't need
        # local pynacl/cryptography because signing happens server-side --
        # detect that case by checking for a `sign` callable that doesn't
        # route through the local Ed25519 backend.
        is_kms_keypair = (
            self.config.attestation_key_provider is not None
            and not isinstance(keypair, DeploymentKeyPair)
        )
        if not is_kms_keypair and not _ed25519_backend_available():
            raise RuntimeError(
                "Shield.__init__ failed to emit key_registered event: "
                + _ED25519_BACKEND_MISSING_MSG
                + " (Triggered by ShieldConfig.deployer_id being set; "
                "without a backend the key_registered event cannot be "
                "signed and auditors cannot externally verify your audit "
                "chain. To disable KeyManifest emission, unset deployer_id.)"
            )

        try:
            # Build the manifest using the keypair's own metadata (key_id /
            # public_key) plus the deployer's identity from config. The
            # callback hook for offline root signing is NOT exercised here
            # -- root_signature is set via the CLI ceremony (KM-4 / KM-5).
            manifest = derive_key_manifest(
                keypair,
                deployer_id=self.config.deployer_id,
                valid_from=self.config.key_valid_from,
                valid_until=self.config.key_valid_until,
            )
            self.audit.log(
                event_type="key_registered",
                key_id=manifest.key_id,
                key_manifest=manifest.to_dict(),
            )
        except Exception as e:
            # Non-fatal for unexpected errors (filesystem, audit write, etc.)
            # -- key_registered is observability + attestation
            # provenance, not a correctness invariant for sanitize/desanitize.
            import logging as _logging
            _logging.getLogger("cloakllm.shield").warning(
                "Failed to emit key_registered event: %s", e
            )

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
                    "status": "satisfied",
                    "notes": (
                        "BiasDetectionSession (v0.7.0+) implements all six "
                        "Article 4a safeguards: necessity_justification, "
                        "pseudonymisation, in-memory-only token map, "
                        "categories_allowed scope cap, max_lifetime + auto-wipe, "
                        "and audit-chain recording."
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
                # v0.8.0 CR8-9: v0.7.1 compliance-schema extensions
                "decision_id_enabled": True,  # always-on since v0.7.1
                "system_version_pin_configured": bool(
                    cfg.deployment_version and cfg.instruction_version
                ),
                # v0.8.0 headline: compliance-reporting API availability
                "compliance_reporting_available": True,
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

        v0.6.3 G1: the `path` argument is validated through the same
        helper that protects `log_dir` at config time
        (`config.validate_filesystem_path`). Always rejects symlinks and
        NUL bytes; honors `audit_strict_paths` for outside-CWD writes.

        On POSIX, the file is opened with `O_NOFOLLOW` (best-effort —
        the symlink check above already covers the common case; this
        defends against a symlink swap between check and open).

        Returns the resolved path written.
        """
        from cloakllm.config import validate_filesystem_path
        out = Path(path)
        # G1: validate at runtime — same rules as ShieldConfig.log_dir.
        validate_filesystem_path(
            out, "export_compliance_config(path)", is_dir=False,
            strict_paths=getattr(self.config, "audit_strict_paths", False),
        )
        summary = self.compliance_summary()
        summary["note"] = (
            "This configuration snapshot was generated by CloakLLM. "
            "Verify audit log integrity using: cloakllm verify <audit_dir>"
        )
        out.parent.mkdir(parents=True, exist_ok=True)
        # G1: prefer os.open with O_NOFOLLOW + 0o600 on POSIX. Windows
        # doesn't define O_NOFOLLOW; getattr fallback gracefully degrades
        # to open() semantics there.
        flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_NOFOLLOW", 0)
        try:
            fd = os.open(out, flags, 0o600)
        except OSError as exc:
            # ELOOP fires if the path is (now) a symlink — race window after
            # validate_filesystem_path. Re-raise with a clearer message.
            import errno
            if exc.errno == errno.ELOOP:
                raise ValueError(
                    f"CloakLLM: export_compliance_config(path) refused — "
                    f"target {out!s} became a symlink between validation "
                    f"and open. Possible TOCTOU attack."
                ) from exc
            raise
        with os.fdopen(fd, "w", encoding="utf-8") as f:
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
