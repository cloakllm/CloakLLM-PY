"""v0.6.3 G1 — Shield.export_compliance_config runtime path validation.

The H5 work hardened ShieldConfig.__post_init__ to validate `log_dir` and
`attestation_key_path` against symlinks / NUL bytes / outside-CWD writes.
But Shield.export_compliance_config(path) accepted any string and passed
it straight to `open()` — bypassing the same protections at runtime.

G1 wires the same validation through the runtime call site, plus uses
`O_NOFOLLOW` on POSIX to defend against symlink-swap TOCTOU between
the validation check and the open() call.
"""

from __future__ import annotations

import json
import os
import stat
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

from cloakllm import Shield, ShieldConfig


class TestExportComplianceConfigPathValidation(unittest.TestCase):

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cloakllm-g1-"))
        self.shield = Shield(ShieldConfig(
            log_dir=self.tmp / "audit",
            audit_enabled=True,
            compliance_mode="eu_ai_act_article12",
        ))

    def test_clean_path_succeeds(self):
        out = self.tmp / "compliance.json"
        result = self.shield.export_compliance_config(str(out))
        self.assertEqual(Path(result), out)
        self.assertTrue(out.exists())
        # Sanity: actual JSON content.
        data = json.loads(out.read_text(encoding="utf-8"))
        self.assertIn("note", data)

    def test_nul_byte_in_path_rejected(self):
        with self.assertRaises(ValueError) as cm:
            self.shield.export_compliance_config(str(self.tmp / "evil\x00.json"))
        self.assertIn("NUL", str(cm.exception))

    @unittest.skipIf(sys.platform == "win32", "symlink creation needs admin on Windows")
    def test_symlink_target_rejected(self):
        # Pre-create the destination as a symlink to a sensitive file.
        target = self.tmp / "real_secret.txt"
        target.write_text("very sensitive")
        link = self.tmp / "compliance.json"
        link.symlink_to(target)
        with self.assertRaises(ValueError) as cm:
            self.shield.export_compliance_config(str(link))
        self.assertIn("symlink", str(cm.exception).lower())
        # Critical: the symlink target must NOT be overwritten.
        self.assertEqual(target.read_text(), "very sensitive")

    @unittest.skipIf(sys.platform == "win32", "POSIX permissions only")
    def test_file_created_with_0o600_mode(self):
        out = self.tmp / "compliance_perms.json"
        self.shield.export_compliance_config(str(out))
        mode = stat.S_IMODE(out.stat().st_mode)
        self.assertEqual(
            mode, 0o600,
            f"compliance config should be 0o600 (owner-only), got 0o{mode:o}"
        )

    def test_strict_paths_rejects_outside_cwd_path(self):
        strict_shield = Shield(ShieldConfig(
            log_dir=Path.cwd() / "in_cwd_audit_g1",
            audit_enabled=True,
            audit_strict_paths=True,
        ))
        try:
            with self.assertRaises(ValueError) as cm:
                # tmp is outside cwd
                strict_shield.export_compliance_config(str(self.tmp / "out.json"))
            self.assertIn("outside the current working directory", str(cm.exception))
        finally:
            log_dir = Path.cwd() / "in_cwd_audit_g1"
            if log_dir.exists():
                import shutil
                shutil.rmtree(log_dir)


if __name__ == "__main__":
    unittest.main()
