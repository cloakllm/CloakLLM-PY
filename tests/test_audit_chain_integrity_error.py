"""v0.6.3 G4 — typed exception for audit chain integrity failures.

Pre-G4, chain-recovery failure under `audit_strict_chain=True` raised
plain `RuntimeError` — callers couldn't distinguish chain integrity
failures from any other RuntimeError (e.g., a B3 schema violation, a
custom-backend bug, a dataclass init error).

G4 introduces `AuditChainIntegrityError(AuditError(RuntimeError))` so
callers can pattern-match specifically. Back-compat preserved by
inheriting from RuntimeError — existing `except RuntimeError:` callers
still work.
"""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from cloakllm import (
    Shield,
    ShieldConfig,
    AuditError,
    AuditChainIntegrityError,
    AuditSchemaViolation,
)
from cloakllm.audit import AuditLogger


class TestExceptionHierarchy(unittest.TestCase):
    """Inheritance contract: typed exceptions ARE RuntimeError for back-compat."""

    def test_AuditError_is_RuntimeError(self):
        self.assertTrue(issubclass(AuditError, RuntimeError))

    def test_AuditChainIntegrityError_is_AuditError(self):
        self.assertTrue(issubclass(AuditChainIntegrityError, AuditError))

    def test_AuditChainIntegrityError_is_RuntimeError(self):
        # Back-compat invariant: existing `except RuntimeError:` callers
        # continue to catch v0.6.3 chain integrity failures.
        self.assertTrue(issubclass(AuditChainIntegrityError, RuntimeError))

    def test_AuditSchemaViolation_is_AuditError(self):
        self.assertTrue(issubclass(AuditSchemaViolation, AuditError))


class TestAuditChainIntegrityErrorRaised(unittest.TestCase):
    """The strict-chain failure path now raises the typed exception."""

    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="cloakllm-g4-"))

    def test_strict_chain_raises_typed_exception(self):
        # Seed log dir with garbage that recovery can't parse.
        (self.tmp / "audit_2026-01-01.jsonl").write_text("garbage")
        cfg = ShieldConfig(
            log_dir=self.tmp,
            audit_enabled=True,
            audit_strict_chain=True,
        )
        audit = AuditLogger(cfg)
        with self.assertRaises(AuditChainIntegrityError) as cm:
            audit._ensure_init()
        self.assertIn("Refusing to silently restart from GENESIS", str(cm.exception))

    def test_strict_chain_failure_still_caught_by_RuntimeError(self):
        # Back-compat: pre-v0.6.3 callers using `except RuntimeError:` still work.
        (self.tmp / "audit_2026-01-01.jsonl").write_text("garbage")
        cfg = ShieldConfig(
            log_dir=self.tmp,
            audit_enabled=True,
            audit_strict_chain=True,
        )
        audit = AuditLogger(cfg)
        try:
            audit._ensure_init()
            self.fail("expected exception")
        except RuntimeError as e:
            # Confirm it IS the typed one (so new callers can match), and
            # confirm RuntimeError still catches it (so old callers keep working).
            self.assertIsInstance(e, AuditChainIntegrityError)
            self.assertIsInstance(e, AuditError)

    def test_typed_match_distinguishes_from_other_runtime_errors(self):
        # The whole point of G4: callers can match SPECIFICALLY on chain
        # integrity failure, not on every RuntimeError.
        (self.tmp / "audit_2026-01-01.jsonl").write_text("garbage")
        cfg = ShieldConfig(
            log_dir=self.tmp,
            audit_enabled=True,
            audit_strict_chain=True,
        )
        audit = AuditLogger(cfg)
        try:
            audit._ensure_init()
            self.fail("expected exception")
        except AuditChainIntegrityError:
            pass  # ✓ caught by specific type
        except RuntimeError:
            self.fail(
                "should have been caught by AuditChainIntegrityError "
                "before falling through to RuntimeError"
            )


class TestExportedFromInit(unittest.TestCase):
    """Top-level cloakllm.* import surface includes the typed exceptions."""

    def test_AuditError_importable_from_cloakllm(self):
        import cloakllm
        self.assertTrue(hasattr(cloakllm, "AuditError"))
        self.assertTrue(hasattr(cloakllm, "AuditChainIntegrityError"))
        self.assertTrue(hasattr(cloakllm, "AuditSchemaViolation"))


if __name__ == "__main__":
    unittest.main()
