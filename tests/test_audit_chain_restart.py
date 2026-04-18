"""v0.6.3 H4 — audit chain restart / corruption recovery tests.

Closes two bugs in the v0.6.x recovery path:
  1. Corrupt trailing line strands earlier valid entries — the old
     `_ensure_init` fell through to the previous file when JSON.loads failed
     on the LAST line, which left any well-formed entries written between
     the prior file and the corruption point disconnected from the chain.
  2. All-files-corrupt silently restarted from GENESIS — an attacker who
     can corrupt logs could mask tampering as a normal restart. New
     `audit_strict_chain` opt-in raises instead.

Plus regression: thread-safe init via double-checked locking.
"""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from datetime import datetime, timezone
from pathlib import Path

from cloakllm import Shield, ShieldConfig
from cloakllm.audit import AuditLogger, GENESIS_HASH


def _today_log_path(log_dir: Path) -> Path:
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    return log_dir / f"audit_{today}.jsonl"


def _write_entries(shield: Shield, n: int = 3) -> list[dict]:
    """Sanitize n distinct strings; return the resulting audit entries."""
    for i in range(n):
        shield.sanitize(f"contact user{i}@example.com please")
    log_dir = Path(shield.config.log_dir)
    entries = []
    for line in _today_log_path(log_dir).read_text(encoding="utf-8").splitlines():
        if line.strip():
            entries.append(json.loads(line))
    return entries


class TestCorruptTrailingLine(unittest.TestCase):
    """Bug 1: a partial-write trailing line must NOT strand earlier valid
    entries — recovery must scan backward to find the last well-formed entry."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="cloakllm-h4-corrupt-"))

    def test_corrupt_tail_recovery_links_to_last_valid(self):
        # Step 1: write some entries via shield_1 (process #1).
        shield_1 = Shield(ShieldConfig(log_dir=self.dir, audit_enabled=True))
        entries = _write_entries(shield_1, n=3)
        self.assertEqual(len(entries), 3)  # 3 sanitize entries (no auto-marker)

        # Step 2: simulate a crash mid-write — append a partial JSON line.
        log_path = _today_log_path(self.dir)
        with open(log_path, "a", encoding="utf-8") as f:
            f.write('{"seq":99,"timestamp":"2026-04-')  # truncated mid-string

        # Step 3: new process starts — should chain to the LAST valid entry,
        # not silently fall through to GENESIS or roll the chain back.
        shield_2 = Shield(ShieldConfig(log_dir=self.dir, audit_enabled=True))
        shield_2.sanitize("a new entry")

        # Verify chain integrity: last valid entry's hash should be the
        # prev_hash of the FIRST new entry written by shield_2.
        last_valid_hash = entries[-1]["entry_hash"]
        # Re-read and find the new sanitize entry
        all_lines = log_path.read_text(encoding="utf-8").splitlines()
        new_entries = []
        for line in all_lines:
            try:
                new_entries.append(json.loads(line))
            except json.JSONDecodeError:
                continue  # the partial line we injected
        # Find the first entry written by shield_2 (after shield_2's
        # shield_enabled marker, the next sanitize)
        post_corruption = [
            e for e in new_entries if e.get("seq", -1) > entries[-1]["seq"]
        ]
        self.assertGreater(len(post_corruption), 0)
        # The very next entry's prev_hash must be the last valid entry's hash.
        # NOT GENESIS (silent restart bug) and NOT some older file's tail.
        self.assertEqual(post_corruption[0]["prev_hash"], last_valid_hash)
        # And seq must be exactly last_valid + 1, not a re-numbering.
        self.assertEqual(post_corruption[0]["seq"], entries[-1]["seq"] + 1)

    def test_only_corrupt_lines_in_file_falls_through_to_older(self):
        # Two files in the dir; current day's file has ONLY corrupt lines.
        # Recovery must walk to the older file and pick up its tail.
        yesterday_file = self.dir / "audit_2026-01-01.jsonl"
        # Build a synthetic valid entry to anchor the chain.
        anchor = {
            "seq": 42,
            "timestamp": "2026-01-01T00:00:00+00:00",
            "event_type": "sanitize",
            "entity_count": 0,
            "categories": {},
            "tokens_used": [],
            "prompt_hash": "",
            "sanitized_hash": "",
            "model": None,
            "provider": None,
            "latency_ms": 0,
            "metadata": None,
            "prev_hash": GENESIS_HASH,
            "mode": "tokenize",
            "entity_details": [],
            "timing": {"total_ms": 0},
        }
        anchor_hash = AuditLogger._compute_hash(dict(anchor))
        anchor["entry_hash"] = anchor_hash
        yesterday_file.write_text(json.dumps(anchor) + "\n", encoding="utf-8")

        # Today's file is just garbage.
        today_file = _today_log_path(self.dir)
        today_file.write_text("garbage\nmore garbage\n{not json", encoding="utf-8")

        # New shield should recover anchor's hash, not start from GENESIS.
        cfg = ShieldConfig(log_dir=self.dir, audit_enabled=True)
        audit = AuditLogger(cfg)
        audit._ensure_init()
        self.assertEqual(audit._prev_hash, anchor_hash)
        self.assertEqual(audit._seq, 43)


class TestStrictChain(unittest.TestCase):
    """Bug 2: silent GENESIS restart must be opt-out via audit_strict_chain."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="cloakllm-h4-strict-"))

    def test_strict_mode_raises_on_recovery_failure(self):
        # Log dir contains files but ALL are unparseable.
        (self.dir / "audit_2026-01-01.jsonl").write_text("garbage")
        (self.dir / "audit_2026-01-02.jsonl").write_text("more garbage")

        cfg = ShieldConfig(
            log_dir=self.dir,
            audit_enabled=True,
            audit_strict_chain=True,  # H4: opt-in strict mode
        )
        audit = AuditLogger(cfg)
        with self.assertRaises(RuntimeError) as cm:
            audit._ensure_init()
        msg = str(cm.exception)
        self.assertIn("Refusing to silently restart from GENESIS", msg)
        self.assertIn("audit_strict_chain=True", msg)

    def test_non_strict_mode_silently_restarts(self):
        # Same scenario — without strict mode, recovery silently uses GENESIS.
        (self.dir / "audit_2026-01-01.jsonl").write_text("garbage")
        cfg = ShieldConfig(log_dir=self.dir, audit_enabled=True)
        audit = AuditLogger(cfg)
        audit._ensure_init()
        self.assertEqual(audit._prev_hash, GENESIS_HASH)
        self.assertEqual(audit._seq, 0)

    def test_strict_mode_with_no_files_starts_at_genesis(self):
        # Empty dir + strict mode = first run, GENESIS is correct.
        cfg = ShieldConfig(
            log_dir=self.dir,
            audit_enabled=True,
            audit_strict_chain=True,
        )
        audit = AuditLogger(cfg)
        audit._ensure_init()  # must not raise
        self.assertEqual(audit._prev_hash, GENESIS_HASH)
        self.assertEqual(audit._seq, 0)

    def test_strict_mode_recovers_normally_when_chain_intact(self):
        # Strict mode shouldn't break the happy path — write entries, restart,
        # verify recovery works normally.
        cfg = ShieldConfig(
            log_dir=self.dir,
            audit_enabled=True,
            audit_strict_chain=True,
        )
        shield_1 = Shield(cfg)
        shield_1.sanitize("john@example.com")
        # Restart
        shield_2 = Shield(ShieldConfig(
            log_dir=self.dir,
            audit_enabled=True,
            audit_strict_chain=True,
        ))
        shield_2.sanitize("jane@example.com")
        ok, errors, _ = shield_2.audit.verify_chain()
        self.assertTrue(ok, f"chain broken: {errors}")


class TestRestartChainContinuity(unittest.TestCase):
    """Regression: a normal process restart must produce a verifiable chain."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="cloakllm-h4-restart-"))

    def test_restart_continuity(self):
        shield_1 = Shield(ShieldConfig(log_dir=self.dir, audit_enabled=True))
        shield_1.sanitize("a@example.com")
        shield_1.sanitize("b@example.com")
        # Drop the reference (simulates process exit)
        del shield_1

        # Restart from same dir
        shield_2 = Shield(ShieldConfig(log_dir=self.dir, audit_enabled=True))
        shield_2.sanitize("c@example.com")
        ok, errors, _ = shield_2.audit.verify_chain()
        self.assertTrue(ok, f"chain broken across restart: {errors}")


class TestThreadedInit(unittest.TestCase):
    """Defense-in-depth: multiple threads calling log() simultaneously on a
    fresh AuditLogger must produce a valid chain (no init race)."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="cloakllm-h4-thread-"))

    def test_concurrent_first_log_calls_produce_valid_chain(self):
        cfg = ShieldConfig(log_dir=self.dir, audit_enabled=True)
        # Single shared shield, threaded sanitize calls.
        shield = Shield(cfg)
        n_threads = 10

        def worker(i):
            shield.sanitize(f"user{i}@example.com")

        threads = [threading.Thread(target=worker, args=(i,)) for i in range(n_threads)]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        ok, errors, _ = shield.audit.verify_chain()
        self.assertTrue(ok, f"thread race produced broken chain: {errors}")


class TestScanForLastValidEntry(unittest.TestCase):
    """Direct unit test for the recovery helper."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="cloakllm-h4-scan-"))

    def test_returns_none_for_empty_list(self):
        self.assertIsNone(AuditLogger._scan_for_last_valid_entry([]))

    def test_skips_corrupt_lines_within_a_file(self):
        f = self.dir / "audit_2026-01-01.jsonl"
        f.write_text(
            json.dumps({"seq": 1, "entry_hash": "h1"}) + "\n"
            + json.dumps({"seq": 2, "entry_hash": "h2"}) + "\n"
            + "{partial-corrupt\n",
            encoding="utf-8",
        )
        result = AuditLogger._scan_for_last_valid_entry([f])
        self.assertEqual(result["seq"], 2)
        self.assertEqual(result["entry_hash"], "h2")

    def test_walks_to_older_file_when_newer_is_all_corrupt(self):
        old = self.dir / "audit_2026-01-01.jsonl"
        new = self.dir / "audit_2026-01-02.jsonl"
        old.write_text(json.dumps({"seq": 5, "entry_hash": "old_h"}) + "\n")
        new.write_text("garbage\n{partial\n")
        result = AuditLogger._scan_for_last_valid_entry([old, new])
        self.assertEqual(result["seq"], 5)
        self.assertEqual(result["entry_hash"], "old_h")

    def test_requires_both_seq_and_entry_hash(self):
        f = self.dir / "audit_2026-01-01.jsonl"
        # Missing entry_hash → not a valid recovery point
        f.write_text(json.dumps({"seq": 1, "no_hash": True}) + "\n")
        self.assertIsNone(AuditLogger._scan_for_last_valid_entry([f]))


if __name__ == "__main__":
    unittest.main()
