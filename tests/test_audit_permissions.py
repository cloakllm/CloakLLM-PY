"""v0.6.3 G7 — audit dir/file permissions are 0o700/0o600 on POSIX.

The B3 invariant is "no PII in audit logs" — but the entries STILL
contain entity hashes, token counts, categories, and timing buckets.
On a default Linux umask (022), audit logs would be created mode 0o644
(world-readable). Other system users could then list audit activity
patterns, infer category mix, and correlate token counts to known
inputs. G7 forces 0o600 on files and 0o700 on the dir at creation
time so the audit log contents are visible only to the owning user.

These tests are POSIX-only; Windows handles permissions via NTFS ACLs,
not POSIX bits, and `os.chmod` is largely a no-op there.
"""

from __future__ import annotations

import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

from cloakllm import Shield, ShieldConfig


@unittest.skipIf(sys.platform == "win32", "POSIX permissions only")
class TestAuditPermissions(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cloakllm-g7-perms-"))

    def _mode(self, path: Path) -> int:
        return stat.S_IMODE(path.stat().st_mode)

    def test_audit_dir_created_0o700(self):
        # Use a fresh subdir so we exercise the mkdir path.
        log_dir = self.tmp / "fresh_audit_dir"
        shield = Shield(ShieldConfig(log_dir=log_dir, audit_enabled=True))
        # Trigger init by writing a sanitize entry.
        shield.sanitize("a@b.com")
        self.assertEqual(self._mode(log_dir), 0o700)

    def test_audit_log_file_created_0o600(self):
        log_dir = self.tmp / "fresh_log_for_perms"
        shield = Shield(ShieldConfig(log_dir=log_dir, audit_enabled=True))
        shield.sanitize("a@b.com")
        files = list(log_dir.glob("audit_*.jsonl"))
        self.assertEqual(len(files), 1, f"expected 1 audit file, found {files}")
        self.assertEqual(self._mode(files[0]), 0o600)

    def test_existing_dir_with_loose_perms_tightened(self):
        # Pre-create the dir with world-readable bits.
        log_dir = self.tmp / "existing_loose_dir"
        log_dir.mkdir(mode=0o755)
        os.chmod(log_dir, 0o755)  # bypass umask
        self.assertEqual(self._mode(log_dir), 0o755)
        shield = Shield(ShieldConfig(log_dir=log_dir, audit_enabled=True))
        shield.sanitize("a@b.com")
        # G7 should have tightened it back to 0o700 at init.
        self.assertEqual(self._mode(log_dir), 0o700)

    def test_subsequent_writes_keep_0o600(self):
        # After the first write, the file is 0o600. Subsequent writes go
        # through `os.open(..., O_APPEND, 0o600)` which doesn't change
        # mode on existing files — that's correct behavior. Verify the
        # file stays at 0o600 across multiple sanitize calls.
        log_dir = self.tmp / "multi_write"
        shield = Shield(ShieldConfig(log_dir=log_dir, audit_enabled=True))
        for _ in range(5):
            shield.sanitize("a@b.com")
        files = list(log_dir.glob("audit_*.jsonl"))
        self.assertEqual(self._mode(files[0]), 0o600)


if __name__ == "__main__":
    unittest.main()
