"""v0.6.3 H5 — path traversal / symlink / NUL-byte tests for log_dir
and attestation_key_path validation.

Symlink rejection and NUL-byte rejection are ALWAYS on (security
invariants); audit_strict_paths gates only the "outside CWD" promotion
from warning to error (back-compat).
"""

from __future__ import annotations

import os
import sys
import tempfile
import unittest
from pathlib import Path

import pytest

from cloakllm import ShieldConfig


class TestSymlinkRejection(unittest.TestCase):
    """Always-on: a symlink at log_dir is rejected regardless of strict mode."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cloakllm-h5-symlink-"))
        # Real target the attacker controls
        self.attacker_target = self.tmp / "attacker_dir"
        self.attacker_target.mkdir()
        # The symlink we'd put at log_dir
        self.symlink_at_log_dir = self.tmp / "audit_logs"

    def _try_symlink(self):
        """Create the symlink — skip if OS denies (Windows non-admin)."""
        try:
            self.symlink_at_log_dir.symlink_to(self.attacker_target, target_is_directory=True)
            return True
        except (OSError, NotImplementedError):
            return False

    def test_symlink_log_dir_rejected_in_default_mode(self):
        if not self._try_symlink():
            self.skipTest("symlink creation not supported on this platform/permission")
        with self.assertRaises(ValueError) as cm:
            ShieldConfig(log_dir=self.symlink_at_log_dir)
        self.assertIn("symlink", str(cm.exception).lower())

    def test_symlink_log_dir_rejected_in_strict_mode_too(self):
        # Strict mode doesn't change the symlink behavior — both modes reject.
        if not self._try_symlink():
            self.skipTest("symlink creation not supported on this platform/permission")
        with self.assertRaises(ValueError):
            ShieldConfig(log_dir=self.symlink_at_log_dir, audit_strict_paths=True)

    def test_real_dir_at_log_dir_accepted(self):
        # Regression guard: a regular directory must still be accepted.
        regular_dir = self.tmp / "regular_logs"
        regular_dir.mkdir()
        # No exception; the outside-CWD warning fires but doesn't raise.
        cfg = ShieldConfig(log_dir=regular_dir)
        self.assertEqual(Path(cfg.log_dir).resolve(), regular_dir.resolve())

    def test_nonexistent_log_dir_accepted(self):
        # Fresh install — log_dir doesn't exist yet, mkdir runs at first write.
        not_yet = self.tmp / "fresh_logs"
        cfg = ShieldConfig(log_dir=not_yet)
        self.assertEqual(Path(cfg.log_dir), not_yet)


class TestNulByteRejection(unittest.TestCase):
    """Always-on: NUL byte in path is rejected (defense vs C-string truncation)."""

    def test_nul_byte_in_log_dir_raises(self):
        with self.assertRaises(ValueError) as cm:
            ShieldConfig(log_dir="./logs\x00/sneaky")
        self.assertIn("NUL", str(cm.exception))

    def test_nul_byte_in_attestation_key_path_raises(self):
        with self.assertRaises(ValueError) as cm:
            ShieldConfig(
                log_dir="./logs",
                attestation_key_path="./key.json\x00bypass",
            )
        self.assertIn("NUL", str(cm.exception))


class TestStrictPathsMode(unittest.TestCase):
    """Strict mode promotes outside-CWD from warning to error."""

    def setUp(self):
        # tempfile.mkdtemp returns an absolute path outside CWD.
        self.tmp = Path(tempfile.mkdtemp(prefix="cloakllm-h5-strict-"))

    def test_outside_cwd_default_warns(self):
        # Without strict_paths, the existing RuntimeWarning fires but no raise.
        with pytest.warns(RuntimeWarning, match="outside the current working directory"):
            ShieldConfig(log_dir=self.tmp)

    def test_outside_cwd_strict_raises(self):
        with self.assertRaises(ValueError) as cm:
            ShieldConfig(log_dir=self.tmp, audit_strict_paths=True)
        msg = str(cm.exception)
        self.assertIn("outside the current working directory", msg)
        self.assertIn("audit_strict_paths=True", msg)

    def test_inside_cwd_strict_no_raise(self):
        # If log_dir IS under CWD, strict mode is silent.
        cwd = Path.cwd()
        inside = cwd / "test_h5_audit_dir"
        try:
            cfg = ShieldConfig(log_dir=inside, audit_strict_paths=True)
            self.assertEqual(Path(cfg.log_dir), inside)
        finally:
            if inside.exists():
                inside.rmdir()


class TestStrictPathsForAttestationKey(unittest.TestCase):
    """attestation_key_path gets the same H5 protections as log_dir."""

    def test_outside_cwd_strict_raises_for_key_path(self):
        tmp = Path(tempfile.mkdtemp(prefix="cloakllm-h5-keypath-"))
        key_path = tmp / "fake_key.json"
        key_path.write_text("{}")  # exists but not a real key — that's fine, validation is path-only
        with self.assertRaises(ValueError) as cm:
            ShieldConfig(
                log_dir="./logs",
                attestation_key_path=str(key_path),
                audit_strict_paths=True,
            )
        msg = str(cm.exception)
        self.assertIn("attestation_key_path", msg)


class TestEnvVar(unittest.TestCase):
    """env var CLOAKLLM_AUDIT_STRICT_PATHS=true should equal kwarg."""

    def test_env_true_promotes_to_error(self):
        tmp = Path(tempfile.mkdtemp(prefix="cloakllm-h5-env-"))
        old = os.environ.get("CLOAKLLM_AUDIT_STRICT_PATHS")
        os.environ["CLOAKLLM_AUDIT_STRICT_PATHS"] = "true"
        try:
            with self.assertRaises(ValueError):
                ShieldConfig(log_dir=tmp)
        finally:
            if old is None:
                os.environ.pop("CLOAKLLM_AUDIT_STRICT_PATHS", None)
            else:
                os.environ["CLOAKLLM_AUDIT_STRICT_PATHS"] = old

    def test_env_false_keeps_warning_behavior(self):
        tmp = Path(tempfile.mkdtemp(prefix="cloakllm-h5-env-off-"))
        old = os.environ.get("CLOAKLLM_AUDIT_STRICT_PATHS")
        os.environ.pop("CLOAKLLM_AUDIT_STRICT_PATHS", None)
        try:
            with pytest.warns(RuntimeWarning):
                ShieldConfig(log_dir=tmp)
        finally:
            if old is not None:
                os.environ["CLOAKLLM_AUDIT_STRICT_PATHS"] = old


if __name__ == "__main__":
    unittest.main()
