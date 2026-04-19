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

from cloakllm._canonical import canonical_json, _legacy_canonical_json
from cloakllm.config import ShieldConfig


GENESIS_HASH = "0" * 64  # SHA-256 of nothing — the chain anchor


_PII_FORBIDDEN_KEYS = ("original_value", "original_text", "raw_text", "plain_text", "value")


# v0.6.1 B3: allow-list schema validator. Always-on (not gated on compliance_mode).
# The CLAUDE.md invariant — "CloakLLM audit logs must contain zero original PII" —
# is a project-wide guarantee. Gating it on a flag would collapse the Article 12
# Paradox positioning into "CloakLLM resolves the paradox if you turn on the right flag."
# Users putting raw PII into metadata were always violating the contract.

# Allow-list of top-level audit-entry keys, mirrored from AuditEntry dataclass.
_ENTRY_ALLOWED_KEYS = frozenset({
    "seq", "event_id", "timestamp", "event_type", "model", "provider",
    "entity_count", "categories", "tokens_used", "prompt_hash", "sanitized_hash",
    "latency_ms", "mode", "entity_details", "timing", "certificate_hash",
    "key_id", "prev_hash", "entry_hash", "metadata", "risk_assessment",
    # v0.6.0 compliance-mode fields
    "compliance_version", "article_ref", "retention_hint_days", "pii_in_log",
})

# Allow-list of entity_details element keys. **Verified against actual code emission**
# (cloakllm-py F3 audit, 2026-04-16): tokenizer.py emits 7 keys, plus entity_hash
# (when entity_hashing enabled), plus text_index (added by Shield.sanitize_batch).
_ENTITY_DETAIL_ALLOWED_KEYS = frozenset({
    "category", "start", "end", "length", "confidence",
    "source", "token", "entity_hash", "text_index",
})

# Allowed scalar value types in metadata. Strict whitelist; nested arbitrary
# objects are rejected to limit attack surface.
_METADATA_ALLOWED_SCALAR_TYPES = (str, int, float, bool, type(None))
_METADATA_MAX_VALUE_LEN = 256
_METADATA_MAX_DEPTH = 3


def _validate_metadata_value(value, depth=0, path=""):
    """Recursively validate a metadata value against the strict schema."""
    if depth > _METADATA_MAX_DEPTH:
        raise RuntimeError(
            f"AUDIT SCHEMA VIOLATION: metadata{path} exceeds max nesting depth "
            f"of {_METADATA_MAX_DEPTH}."
        )
    if isinstance(value, _METADATA_ALLOWED_SCALAR_TYPES):
        if isinstance(value, str) and len(value) > _METADATA_MAX_VALUE_LEN:
            raise RuntimeError(
                f"AUDIT SCHEMA VIOLATION: metadata{path} string exceeds "
                f"{_METADATA_MAX_VALUE_LEN} chars (got {len(value)}). "
                f"Long strings risk leaking PII into audit logs."
            )
        return
    if isinstance(value, list):
        for i, item in enumerate(value):
            _validate_metadata_value(item, depth + 1, f"{path}[{i}]")
        return
    if isinstance(value, dict):
        for k, v in value.items():
            if not isinstance(k, str):
                raise RuntimeError(
                    f"AUDIT SCHEMA VIOLATION: metadata{path} key {k!r} is not a string."
                )
            _validate_metadata_value(v, depth + 1, f"{path}.{k}")
        return
    raise RuntimeError(
        f"AUDIT SCHEMA VIOLATION: metadata{path} has disallowed type "
        f"{type(value).__name__}. Allowed: str, int, float, bool, None, "
        f"list of those, dict of those."
    )


def _validate_audit_entry_schema(entry_data: dict) -> None:
    """
    Always-on allow-list validator for audit entries.

    v0.6.1 B3: replaces the v0.6.0 deny-list `_assert_no_pii_in_entry`.
    Asserts that:
      - Top-level keys are a subset of the allow-list (rejects unknown fields).
      - entity_details elements have only the 9 verified-allowed keys.
      - metadata values are strict-typed and bounded (rejects arbitrary objects,
        long strings, deep nesting).

    Raises RuntimeError if violated. This is the structural enforcement of the
    "audit logs must contain zero original PII" invariant.
    """
    # Top-level keys
    for k in entry_data:
        if k not in _ENTRY_ALLOWED_KEYS:
            raise RuntimeError(
                f"AUDIT SCHEMA VIOLATION: top-level key {k!r} is not in the "
                f"allow-list. This guard prevents arbitrary keys (which may "
                f"contain PII) from being written to audit logs."
            )

    # entity_details
    details = entry_data.get("entity_details") or []
    for i, detail in enumerate(details):
        if not isinstance(detail, dict):
            raise RuntimeError(
                f"AUDIT SCHEMA VIOLATION: entity_details[{i}] is not a dict "
                f"(got {type(detail).__name__})."
            )
        # Check the legacy denylist FIRST so known-PII keys produce the
        # recognizable "COMPLIANCE VIOLATION" error message before falling
        # through to the more general allow-list rejection.
        for forbidden in _PII_FORBIDDEN_KEYS:
            if forbidden in detail:
                raise RuntimeError(
                    f"COMPLIANCE VIOLATION: entity_details[{i}] contains "
                    f"forbidden field {forbidden!r}. Audit logs must not "
                    f"contain original PII."
                )
        for k in detail:
            if k not in _ENTITY_DETAIL_ALLOWED_KEYS:
                raise RuntimeError(
                    f"AUDIT SCHEMA VIOLATION: entity_details[{i}] contains "
                    f"disallowed key {k!r}. Allowed keys: "
                    f"{sorted(_ENTITY_DETAIL_ALLOWED_KEYS)}."
                )

    # metadata
    metadata = entry_data.get("metadata") or {}
    if metadata:
        if not isinstance(metadata, dict):
            raise RuntimeError(
                f"AUDIT SCHEMA VIOLATION: metadata must be a dict "
                f"(got {type(metadata).__name__})."
            )
        for k, v in metadata.items():
            if not isinstance(k, str):
                raise RuntimeError(
                    f"AUDIT SCHEMA VIOLATION: metadata key {k!r} must be a string."
                )
            _validate_metadata_value(v, depth=1, path=f".{k}")


def _assert_no_pii_in_entry(entry_data: dict) -> None:
    """
    Deprecated (v0.6.1): kept as an alias for backward compat.
    Use `_validate_audit_entry_schema` instead.
    """
    _validate_audit_entry_schema(entry_data)


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
        # v0.6.3 H4: RLock (was Lock) so _ensure_init can acquire the lock
        # for double-checked locking even when called from inside log()'s
        # critical section. Lock would deadlock; RLock allows re-entry by
        # the same thread.
        self._lock = threading.RLock()
        # v0.6.3 H4: When True, the next write prepends a `\n`. Set during
        # init recovery if the target log file exists and ends mid-line
        # (e.g., a previous process crashed mid-write before the trailing
        # newline). Without this, the new entry concatenates to the partial
        # line and is itself unparseable, hiding the new entry from the
        # chain on next recovery.
        self._needs_leading_newline = False

    @staticmethod
    def _scan_for_last_valid_entry(log_files):
        """v0.6.3 H4: Scan backward through the most-recent log file to find
        the last well-formed entry (with both `seq` and `entry_hash`). If the
        most-recent file has no valid entries at all, walk to the older file.

        Replaces the old behaviour of reading only the trailing line and
        falling through to the previous file when that line was corrupt —
        that silently rolled the chain back over any valid entries written
        between the previous file and the corruption point, leaving them
        stranded relative to the next entry.

        Returns the parsed entry dict, or None if no valid entry is found
        across all files.
        """
        for log_file in reversed(log_files):
            try:
                with open(log_file, "r") as f:
                    lines = [ln.strip() for ln in f if ln.strip()]
            except OSError:
                continue
            for line in reversed(lines):
                try:
                    entry = json.loads(line)
                except json.JSONDecodeError:
                    continue  # corrupt line — keep scanning backward in this file
                if "seq" in entry and "entry_hash" in entry:
                    return entry
            # this file had no valid entries at all — try the next-older one
        return None

    def _ensure_init(self):
        """Initialize log directory and recover chain state from existing logs.

        v0.6.3 H4 changes:
          * Double-checked locking — concurrent first callers can't both
            run init and overwrite each other's state mid-flight.
          * Backward scan via `_scan_for_last_valid_entry` — partial-write
            corruption at the tail of the log no longer strands earlier
            valid entries from the chain.
          * Strict mode (config.audit_strict_chain): if log files exist
            on disk but recovery returns None, raise instead of silently
            restarting from GENESIS. Closes the "attacker corrupts logs to
            mask tampering as restart" surface for compliance deployments.
        """
        if self._initialized:
            return
        with self._lock:
            if self._initialized:
                return  # double-checked: another thread won the race
            # v0.6.3 G7: create the audit dir with mode 0o700 so other system
            # users cannot list audit log filenames. Default Linux umask
            # would otherwise leave the dir 0o755 (world-readable directory
            # entries reveal which days have audit activity). On Windows the
            # mode arg is largely ignored — operators must rely on NTFS ACLs.
            self._log_dir.mkdir(parents=True, exist_ok=True, mode=0o700)
            # If the directory already existed with looser permissions, tighten
            # it. POSIX-only; Windows chmod is a no-op for these bits.
            try:
                import sys as _sys
                if _sys.platform != "win32":
                    import os as _os
                    _os.chmod(self._log_dir, 0o700)
            except OSError:
                pass
            log_files = sorted(self._log_dir.glob("audit_*.jsonl"))
            # v0.6.3 H4: Detect partial-write tail on the file we're about to
            # write into. If today's log file exists and doesn't end with
            # `\n`, the next write must prepend `\n` to avoid concatenating
            # the new entry onto the truncation.
            today_file = self._get_log_file()
            if today_file.exists() and today_file.stat().st_size > 0:
                try:
                    with open(today_file, "rb") as _f:
                        _f.seek(-1, 2)
                        if _f.read(1) != b"\n":
                            self._needs_leading_newline = True
                except OSError:
                    pass
            last_entry = self._scan_for_last_valid_entry(log_files)
            if last_entry is not None:
                self._seq = last_entry["seq"] + 1
                self._prev_hash = last_entry["entry_hash"]
            elif log_files and getattr(self.config, "audit_strict_chain", False):
                raise RuntimeError(
                    f"CloakLLM audit chain recovery failed: log dir "
                    f"{self._log_dir!s} contains {len(log_files)} file(s) but "
                    f"none have a recoverable trailing entry. Refusing to "
                    f"silently restart from GENESIS (audit_strict_chain=True). "
                    f"Inspect the files for corruption — a silent restart "
                    f"would let an attacker mask tampering as a normal restart."
                )
            # else: log_files empty (truly first run) OR all files empty AND
            # strict mode off → start from GENESIS (back-compat default).
            self._initialized = True

    def _get_log_file(self) -> Path:
        """Get today's log file path."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self._log_dir / f"audit_{today}.jsonl"

    def _write_with_lock(self, log_file: Path, data: str) -> None:
        """Write to audit log with cross-process file locking.

        v0.6.3 G7: opens with `os.open(..., O_WRONLY|O_CREAT|O_APPEND, 0o600)`
        on POSIX so other system users cannot read audit log contents (entity
        hashes, token counts, categories, timing). Default umask would leave
        the file 0o644 — readable by every user on the host. On Windows the
        mode arg is largely a no-op; operators must rely on NTFS ACLs.
        Existing files keep their current mode (we don't tighten on every
        write — only the audit dir is chmod'd defensively at init).
        """
        import sys
        import os as _os
        # Open with explicit 0o600 mode. On POSIX this is the file-creation
        # mode (umask still applies, so the effective bits may be tighter
        # but never looser).
        flags = _os.O_WRONLY | _os.O_CREAT | _os.O_APPEND
        fd = _os.open(log_file, flags, 0o600)
        with _os.fdopen(fd, "a") as f:
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
    def _compute_hash(data: dict, *, legacy_canonical: bool = False) -> str:
        """
        Compute SHA-256 hash of entry data.

        Args:
            data: The audit-entry dict to hash.
            legacy_canonical: When True, use the v0.6.0-compatible canonicalizer
                (ensure_ascii=True). Used ONLY by verify_chain when the caller
                opts in to verifying a pre-v0.6.1 chain. Sunset in v0.7.0.
        """
        encoder = _legacy_canonical_json if legacy_canonical else canonical_json
        canonical = encoder(data)
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

            # v0.6.1 B3: ALWAYS-ON allow-list schema validation. The no-PII-in-logs
            # invariant is a project-wide guarantee, not a compliance-mode feature.
            _validate_audit_entry_schema(entry_data)

            # Compute entry hash (includes prev_hash for chain integrity)
            entry_hash = self._compute_hash(entry_data)
            entry_data["entry_hash"] = entry_hash

            # Write to log file
            log_file = self._get_log_file()
            payload = json.dumps(entry_data, separators=(",", ":")) + "\n"
            # v0.6.3 H4: prepend `\n` if recovery detected the target file
            # ends mid-line (partial-write tail from a prior crash). The flag
            # is one-shot — clear after first use.
            if self._needs_leading_newline:
                payload = "\n" + payload
                self._needs_leading_newline = False
            self._write_with_lock(log_file, payload)

            # Update chain state
            self._prev_hash = entry_hash
            self._seq += 1

            return AuditEntry(**entry_data)

    def verify_chain(
        self,
        log_file: Optional[Path] = None,
        output_format: Optional[str] = None,
        *,
        legacy_canonical: bool = False,
    ):
        """
        Verify the integrity of the entire audit chain.

        Args:
            log_file: Specific log file to verify. If None, all files in log_dir.
            output_format: When None (default), returns the existing
                (is_valid, errors, final_seq) tuple — backward compatible.
                When "compliance_report", returns a structured dict with
                period, totals, category aggregates, and verdict.
            legacy_canonical: When True, recompute hashes using the v0.6.0
                canonicalizer (`ensure_ascii=True`). Use this to verify audit
                chains written by CloakLLM v0.5.x or v0.6.0 that contain
                non-ASCII characters. Sunset in v0.7.0.

        Returns (is_valid, errors, final_seq) by default, or a dict
        when output_format="compliance_report".
        """
        if legacy_canonical:
            import warnings as _w
            _w.warn(
                "legacy_canonical=True is a backward-compat shim for v0.5.x / "
                "v0.6.0 audit chains and will be removed in v0.7.0.",
                DeprecationWarning,
                stacklevel=2,
            )
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

                    # Recompute entry hash (legacy_canonical thread-through)
                    stored_hash = entry.pop("entry_hash", "")
                    recomputed = self._compute_hash(entry, legacy_canonical=legacy_canonical)
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
