"""
Tamper-Evident Audit Logger.

Implements a hash-chained append-only log for EU AI Act Article 12 compliance.
Each entry's hash includes the previous entry's hash, creating an unbreakable chain.
Any modification to a single entry invalidates all subsequent entries.

Verification: O(n) full chain audit, O(1) per-entry check.
Storage: JSONL (one JSON object per line) for easy parsing and streaming.
"""

from __future__ import annotations

import hashlib
import json
import threading
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cloakllm.config import ShieldConfig


GENESIS_HASH = "0" * 64  # SHA-256 of nothing — the chain anchor


_PII_FORBIDDEN_KEYS = ("original_value", "original_text", "raw_text", "plain_text", "value")


def _assert_no_pii_in_entry(entry_data: dict) -> None:
    """
    Runtime invariant guard for compliance mode.

    Asserts that no entity-level fields contain raw/original PII text.
    Raises RuntimeError if violated. This is the structural enforcement
    of the "audit logs must contain zero original PII" invariant.
    """
    details = entry_data.get("entity_details") or []
    for i, detail in enumerate(details):
        if not isinstance(detail, dict):
            continue
        for forbidden in _PII_FORBIDDEN_KEYS:
            if forbidden in detail:
                raise RuntimeError(
                    f"COMPLIANCE VIOLATION: entity_details[{i}] contains forbidden "
                    f"field '{forbidden}'. Audit logs must not contain original PII."
                )


@dataclass
class AuditEntry:
    """A single entry in the tamper-evident audit log."""
    seq: int                    # Sequential entry number
    event_id: str               # Unique event ID (UUID4)
    timestamp: str              # ISO 8601 UTC timestamp
    event_type: str             # "sanitize" | "desanitize" | "request" | "response" | "error"
    model: Optional[str]        # LLM model used
    provider: Optional[str]     # LLM provider (anthropic, openai, etc.)
    entity_count: int           # Number of entities detected
    categories: dict[str, int]  # Entity counts by category
    tokens_used: list[str]      # List of tokens (no original values)
    prompt_hash: str            # SHA-256 of original prompt (for verification without storing content)
    sanitized_hash: str         # SHA-256 of sanitized prompt
    latency_ms: float           # Processing time in milliseconds
    mode: Optional[str]         # "tokenize" or "redact" (None for legacy entries)
    entity_details: list[dict]  # Per-entity metadata (PII-safe)
    timing: Optional[dict[str, float]]  # Per-pass timing breakdown (ms)
    certificate_hash: Optional[str]  # SHA-256 of certificate signature (for cross-referencing)
    key_id: Optional[str]       # Key ID of the signing keypair (for key rotation)
    prev_hash: str              # Hash of previous entry (chain link)
    entry_hash: str             # Hash of this entry (computed from all fields + prev_hash)
    metadata: dict[str, Any]    # Additional context (user_id, session_id, etc.)
    risk_assessment: Optional[dict]  # Context-based PII leakage risk (when context_analysis enabled)
    # --- Compliance Mode (v0.6.0) — only populated when config.compliance_mode is set ---
    compliance_version: Optional[str] = None      # e.g. "eu_ai_act_article12_v1"
    article_ref: Optional[list[str]] = None       # Articles satisfied, e.g. ["EU_AI_Act_Art_12", ...]
    retention_hint_days: Optional[int] = None     # Recommended log retention period
    pii_in_log: Optional[bool] = None             # Always False in compliance mode (asserted)


class AuditLogger:
    """
    Append-only, hash-chained audit logger.

    Creates one log file per day in the configured log directory.
    Each entry is cryptographically linked to the previous entry.
    """

    def __init__(self, config: ShieldConfig):
        self.config = config
        self._seq = 0
        self._prev_hash = GENESIS_HASH
        self._log_dir = config.log_dir
        self._current_file: Optional[Path] = None
        self._initialized = False
        self._lock = threading.Lock()

    def _ensure_init(self):
        """Initialize log directory and recover chain state from existing logs."""
        if self._initialized:
            return

        self._log_dir.mkdir(parents=True, exist_ok=True)

        # Recover chain state from most recent non-empty log file
        log_files = sorted(self._log_dir.glob("audit_*.jsonl"))
        for log_file in reversed(log_files):
            try:
                last_line = ""
                with open(log_file, "r") as f:
                    for line in f:
                        if line.strip():
                            last_line = line.strip()
                if last_line:
                    entry = json.loads(last_line)
                    self._seq = entry["seq"] + 1
                    self._prev_hash = entry["entry_hash"]
                    break
            except (json.JSONDecodeError, KeyError):
                continue  # Try older file if this one is corrupted

        self._initialized = True

    def _get_log_file(self) -> Path:
        """Get today's log file path."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self._log_dir / f"audit_{today}.jsonl"

    def _write_with_lock(self, log_file: Path, data: str) -> None:
        """Write to audit log with cross-process file locking."""
        import sys
        with open(log_file, "a") as f:
            if sys.platform == "win32":
                import msvcrt
                try:
                    msvcrt.locking(f.fileno(), msvcrt.LK_LOCK, 1)
                    f.write(data)
                finally:
                    try:
                        f.seek(0, 2)
                        msvcrt.locking(f.fileno(), msvcrt.LK_UNLCK, 1)
                    except OSError:
                        pass
            else:
                import fcntl
                fcntl.flock(f.fileno(), fcntl.LOCK_EX)
                try:
                    f.write(data)
                finally:
                    fcntl.flock(f.fileno(), fcntl.LOCK_UN)

    @staticmethod
    def _compute_hash(data: dict) -> str:
        """Compute SHA-256 hash of entry data."""
        # Deterministic serialization: sort keys, no spaces
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(canonical.encode("utf-8")).hexdigest()

    def log(
        self,
        event_type: str,
        original_text: str = "",
        sanitized_text: str = "",
        model: Optional[str] = None,
        provider: Optional[str] = None,
        entity_count: int = 0,
        categories: Optional[dict[str, int]] = None,
        tokens_used: Optional[list[str]] = None,
        latency_ms: float = 0.0,
        mode: Optional[str] = None,
        entity_details: Optional[list[dict]] = None,
        timing: Optional[dict[str, float]] = None,
        metadata: Optional[dict[str, Any]] = None,
        certificate_hash: Optional[str] = None,
        key_id: Optional[str] = None,
        risk_assessment: Optional[dict] = None,
    ) -> Optional[AuditEntry]:
        """
        Append a new entry to the audit log.

        Returns the created AuditEntry.
        """
        if not self.config.audit_enabled:
            return None

        with self._lock:
            self._ensure_init()

            # Build entry data (without entry_hash — we compute that last)
            entry_data = {
                "seq": self._seq,
                "event_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "model": model,
                "provider": provider,
                "entity_count": entity_count,
                "categories": categories or {},
                "tokens_used": tokens_used or [],
                "prompt_hash": hashlib.sha256(original_text.encode()).hexdigest() if original_text else "",
                "sanitized_hash": hashlib.sha256(sanitized_text.encode()).hexdigest() if sanitized_text else "",
                "latency_ms": round(latency_ms, 2),
                "mode": mode,
                "entity_details": entity_details or [],
                "timing": timing,
                "certificate_hash": certificate_hash,
                "key_id": key_id,
                "prev_hash": self._prev_hash,
                "metadata": metadata or {},
                "risk_assessment": risk_assessment,
            }

            # Compliance mode injection (v0.6.0) — fields are part of the hash chain.
            if self.config.compliance_mode == "eu_ai_act_article12":
                entry_data["compliance_version"] = "eu_ai_act_article12_v1"
                entry_data["article_ref"] = ["EU_AI_Act_Art_12", "EU_AI_Act_Art_19"]
                entry_data["retention_hint_days"] = self.config.retention_hint_days
                entry_data["pii_in_log"] = False
                # Runtime invariant: no PII may leak into entity_details
                _assert_no_pii_in_entry(entry_data)

            # Compute entry hash (includes prev_hash for chain integrity)
            entry_hash = self._compute_hash(entry_data)
            entry_data["entry_hash"] = entry_hash

            # Write to log file
            log_file = self._get_log_file()
            self._write_with_lock(log_file, json.dumps(entry_data, separators=(",", ":")) + "\n")

            # Update chain state
            self._prev_hash = entry_hash
            self._seq += 1

            return AuditEntry(**entry_data)

    def verify_chain(
        self,
        log_file: Optional[Path] = None,
        output_format: Optional[str] = None,
    ):
        """
        Verify the integrity of the entire audit chain.

        Args:
            log_file: Specific log file to verify. If None, all files in log_dir.
            output_format: When None (default), returns the existing
                (is_valid, errors, final_seq) tuple — backward compatible.
                When "compliance_report", returns a structured dict with
                period, totals, category aggregates, and verdict.

        Returns (is_valid, errors, final_seq) by default, or a dict
        when output_format="compliance_report".
        """
        errors: list[str] = []
        final_seq = 0

        # Compliance-report aggregates (only populated when requested)
        report_enabled = output_format == "compliance_report"
        first_ts: Optional[str] = None
        last_ts: Optional[str] = None
        total_entries = 0
        compliance_mode_entries = 0
        non_compliance_mode_entries = 0
        certificates_present = 0
        pii_categories_detected: dict[str, int] = {}
        pii_in_logs = False

        if log_file:
            files = [log_file]
        else:
            files = sorted(self._log_dir.glob("audit_*.jsonl"))

        if not files:
            if report_enabled:
                return self._build_compliance_report(
                    audit_dir=str(self._log_dir),
                    first_ts=None,
                    last_ts=None,
                    total_entries=0,
                    compliance_mode_entries=0,
                    non_compliance_mode_entries=0,
                    certificates_present=0,
                    pii_categories_detected={},
                    pii_in_logs=False,
                    chain_valid=True,
                    anomalies=[],
                )
            return True, [], 0

        prev_hash = GENESIS_HASH

        for fpath in files:
            with open(fpath, "r") as f:
                for line_num, line in enumerate(f, 1):
                    line = line.strip()
                    if not line:
                        continue

                    try:
                        entry = json.loads(line)
                    except json.JSONDecodeError:
                        errors.append(f"{fpath.name}:{line_num} — Invalid JSON")
                        continue

                    # Track the last seq number seen
                    entry_seq = entry.get("seq", 0)
                    if entry_seq >= final_seq:
                        final_seq = entry_seq

                    # Check chain link
                    if entry.get("prev_hash") != prev_hash:
                        errors.append(
                            f"{fpath.name}:{line_num} seq={entry.get('seq')} — "
                            f"Chain broken: expected prev_hash={prev_hash[:16]}..., "
                            f"got {entry.get('prev_hash', 'MISSING')[:16]}..."
                        )

                    # Compliance-report aggregation (before pop'ing entry_hash)
                    if report_enabled:
                        total_entries += 1
                        ts = entry.get("timestamp")
                        if ts:
                            if first_ts is None or ts < first_ts:
                                first_ts = ts
                            if last_ts is None or ts > last_ts:
                                last_ts = ts
                        if entry.get("compliance_version"):
                            compliance_mode_entries += 1
                            # Hard check: pii_in_log must be False in compliance mode
                            if entry.get("pii_in_log") is True:
                                pii_in_logs = True
                                errors.append(
                                    f"{fpath.name}:{line_num} seq={entry.get('seq')} — "
                                    f"COMPLIANCE VIOLATION: pii_in_log=true"
                                )
                        else:
                            non_compliance_mode_entries += 1
                        if entry.get("certificate_hash"):
                            certificates_present += 1
                        for cat, count in (entry.get("categories") or {}).items():
                            pii_categories_detected[cat] = (
                                pii_categories_detected.get(cat, 0) + count
                            )

                    # Recompute entry hash
                    stored_hash = entry.pop("entry_hash", "")
                    recomputed = self._compute_hash(entry)
                    if stored_hash != recomputed:
                        errors.append(
                            f"{fpath.name}:{line_num} seq={entry.get('seq')} — "
                            f"Entry tampered: stored_hash={stored_hash[:16]}..., "
                            f"recomputed={recomputed[:16]}..."
                        )

                    prev_hash = stored_hash

        chain_valid = len(errors) == 0

        if report_enabled:
            return self._build_compliance_report(
                audit_dir=str(self._log_dir),
                first_ts=first_ts,
                last_ts=last_ts,
                total_entries=total_entries,
                compliance_mode_entries=compliance_mode_entries,
                non_compliance_mode_entries=non_compliance_mode_entries,
                certificates_present=certificates_present,
                pii_categories_detected=pii_categories_detected,
                pii_in_logs=pii_in_logs,
                chain_valid=chain_valid,
                anomalies=errors,
            )

        return chain_valid, errors, final_seq

    @staticmethod
    def _build_compliance_report(
        *,
        audit_dir: str,
        first_ts: Optional[str],
        last_ts: Optional[str],
        total_entries: int,
        compliance_mode_entries: int,
        non_compliance_mode_entries: int,
        certificates_present: int,
        pii_categories_detected: dict[str, int],
        pii_in_logs: bool,
        chain_valid: bool,
        anomalies: list[str],
    ) -> dict:
        verdict = "COMPLIANT" if (chain_valid and not pii_in_logs) else "NON_COMPLIANT"
        return {
            "audit_dir": audit_dir,
            "period": {"from": first_ts, "to": last_ts},
            "total_entries": total_entries,
            "chain_integrity": "verified" if chain_valid else "broken",
            "pii_in_logs": pii_in_logs,
            "compliance_mode_entries": compliance_mode_entries,
            "non_compliance_mode_entries": non_compliance_mode_entries,
            "pii_categories_detected": pii_categories_detected,
            "certificates_present": certificates_present,
            "anomalies": anomalies,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "verdict": verdict,
        }

    def get_stats(self) -> dict:
        """Get aggregate statistics from audit logs."""
        self._ensure_init()
        stats = {
            "total_events": 0,
            "total_entities_detected": 0,
            "categories": {},
            "models_used": set(),
            "log_files": [],
        }

        for fpath in sorted(self._log_dir.glob("audit_*.jsonl")):
            stats["log_files"].append(str(fpath.name))
            with open(fpath, "r") as f:
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entry = json.loads(line)
                        stats["total_events"] += 1
                        stats["total_entities_detected"] += entry.get("entity_count", 0)
                        for cat, count in entry.get("categories", {}).items():
                            stats["categories"][cat] = stats["categories"].get(cat, 0) + count
                        if entry.get("model"):
                            stats["models_used"].add(entry["model"])
                    except json.JSONDecodeError:
                        continue

        stats["models_used"] = list(stats["models_used"])
        return stats
