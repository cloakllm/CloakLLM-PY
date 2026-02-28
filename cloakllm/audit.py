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
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from cloakllm.config import ShieldConfig


GENESIS_HASH = "0" * 64  # SHA-256 of nothing — the chain anchor


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
    prev_hash: str              # Hash of previous entry (chain link)
    entry_hash: str             # Hash of this entry (computed from all fields + prev_hash)
    metadata: dict[str, Any]    # Additional context (user_id, session_id, etc.)


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

    def _ensure_init(self):
        """Initialize log directory and recover chain state from existing logs."""
        if self._initialized:
            return

        self._log_dir.mkdir(parents=True, exist_ok=True)

        # Recover chain state from most recent log file
        log_files = sorted(self._log_dir.glob("audit_*.jsonl"))
        if log_files:
            last_file = log_files[-1]
            try:
                last_line = ""
                with open(last_file, "r") as f:
                    for line in f:
                        if line.strip():
                            last_line = line.strip()
                if last_line:
                    entry = json.loads(last_line)
                    self._seq = entry["seq"] + 1
                    self._prev_hash = entry["entry_hash"]
            except (json.JSONDecodeError, KeyError):
                pass  # Start fresh if log is corrupted

        self._initialized = True

    def _get_log_file(self) -> Path:
        """Get today's log file path."""
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        return self._log_dir / f"audit_{today}.jsonl"

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
        metadata: Optional[dict[str, Any]] = None,
    ) -> Optional[AuditEntry]:
        """
        Append a new entry to the audit log.

        Returns the created AuditEntry.
        """
        if not self.config.audit_enabled:
            return None

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
            "prev_hash": self._prev_hash,
            "metadata": metadata or {},
        }

        # Compute entry hash (includes prev_hash for chain integrity)
        entry_hash = self._compute_hash(entry_data)
        entry_data["entry_hash"] = entry_hash

        # Write to log file
        log_file = self._get_log_file()
        with open(log_file, "a") as f:
            f.write(json.dumps(entry_data, separators=(",", ":")) + "\n")

        # Update chain state
        self._prev_hash = entry_hash
        self._seq += 1

        return AuditEntry(**entry_data)

    def verify_chain(self, log_file: Optional[Path] = None) -> tuple[bool, list[str]]:
        """
        Verify the integrity of the entire audit chain.

        Returns (is_valid, list_of_errors).
        """
        errors: list[str] = []

        if log_file:
            files = [log_file]
        else:
            files = sorted(self._log_dir.glob("audit_*.jsonl"))

        if not files:
            return True, []

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

                    # Check chain link
                    if entry.get("prev_hash") != prev_hash:
                        errors.append(
                            f"{fpath.name}:{line_num} seq={entry.get('seq')} — "
                            f"Chain broken: expected prev_hash={prev_hash[:16]}..., "
                            f"got {entry.get('prev_hash', 'MISSING')[:16]}..."
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

        return len(errors) == 0, errors

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
