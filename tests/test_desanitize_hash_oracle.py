"""v0.6.3 G2 — close the desanitize sanitized_hash PII oracle.

Pre-v0.6.3, a `desanitize` audit entry had:
    prompt_hash    = sha256(tokenized_input_text)   ← safe (no PII)
    sanitized_hash = sha256(restored_PII_text)      ← THE ORACLE

An attacker with audit log read access could hash candidate PII
(sha256("123-45-6789") for SSNs, common email formats) and confirm
matches against `sanitized_hash`. Direct PII oracle in production logs.

v0.6.3 fix: pass `text` (the tokenized input) for BOTH original_text
and sanitized_text in the audit log call. Result:
    prompt_hash    = sha256(tokenized_input_text)
    sanitized_hash = sha256(tokenized_input_text)  (same as prompt_hash)

The restored PII is NEVER hashed and NEVER appears in the audit log.

Note: chain verification (verify_chain) is unaffected — it re-computes
the entry-level chain hash, not the field-level prompt_hash /
sanitized_hash. Pre-v0.6.3 chains continue to verify correctly. The
`legacy_desanitize_hash` flag in PLAN_v063_REVISED was a no-op (the
plan author conflated chain re-verification with content re-derivation);
not adding it.
"""

from __future__ import annotations

import hashlib
import json
import tempfile
import unittest
from pathlib import Path

from cloakllm import Shield, ShieldConfig


def _read_entries(log_dir: Path) -> list[dict]:
    out = []
    for f in sorted(log_dir.glob("audit_*.jsonl")):
        for line in f.read_text(encoding="utf-8").splitlines():
            if line.strip():
                out.append(json.loads(line))
    return out


class TestDesanitizeHashOracleClosed(unittest.TestCase):
    """Direct verification: sanitized_hash on desanitize entries no longer
    leaks the restored PII via hash matching."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="cloakllm-g2-"))
        self.shield = Shield(ShieldConfig(log_dir=self.dir, audit_enabled=True))

    def test_sanitized_hash_equals_prompt_hash_on_desanitize_entries(self):
        original = "Email john@example.com about it"
        _, tm = self.shield.sanitize(original)
        # Pick the issued token and feed back via desanitize.
        token = next(iter(tm.reverse.keys()))
        llm_response = f"Reply to {token} please"
        result = self.shield.desanitize(llm_response, tm)
        # Sanity: substitution worked.
        self.assertIn("john@example.com", result)

        entries = _read_entries(self.dir)
        desan = [e for e in entries if e["event_type"] == "desanitize"][-1]
        # The headline G2 invariant.
        self.assertEqual(
            desan["sanitized_hash"], desan["prompt_hash"],
            "desanitize entries must hash the tokenized input twice — "
            "not the restored PII (which would be a hash oracle).",
        )
        # Both equal the hash of the tokenized input we fed in.
        expected = hashlib.sha256(llm_response.encode()).hexdigest()
        self.assertEqual(desan["prompt_hash"], expected)
        self.assertEqual(desan["sanitized_hash"], expected)

    def test_restored_pii_hash_does_NOT_appear_in_audit(self):
        # Build the test so the restored PII has a distinctive content
        # whose SHA-256 wouldn't accidentally collide with anything.
        original = "Email diana-test-7g4@cloakllm.example about it"
        _, tm = self.shield.sanitize(original)
        token = next(iter(tm.reverse.keys()))
        llm_response = f"reply to {token}"
        restored = self.shield.desanitize(llm_response, tm)
        restored_hash = hashlib.sha256(restored.encode()).hexdigest()

        # Read audit + assert NO entry contains the restored hash.
        entries = _read_entries(self.dir)
        for e in entries:
            self.assertNotEqual(
                e.get("prompt_hash"), restored_hash,
                f"prompt_hash leaked restored PII via hash match: {e}",
            )
            self.assertNotEqual(
                e.get("sanitized_hash"), restored_hash,
                f"sanitized_hash leaked restored PII via hash match: {e}",
            )

    def test_chain_still_verifies_after_g2(self):
        # Chain verification only checks the entry-level hash linkage.
        # Changing what `sanitized_text` was passed in MUST NOT break
        # cross-entry hash chaining.
        _, tm = self.shield.sanitize("a@b.com")
        token = next(iter(tm.reverse.keys()))
        self.shield.desanitize(f"out: {token}", tm)
        self.shield.desanitize(f"again: {token}", tm)

        ok, errors, _ = self.shield.audit.verify_chain()
        self.assertTrue(ok, f"chain broken after G2 changes: {errors}")


class TestPreV063ChainStillVerifies(unittest.TestCase):
    """Mixed-vintage scenario: a chain containing entries written by v0.6.2
    semantics (sanitized_hash = sha256(restored PII)) followed by entries
    written by v0.6.3 semantics (sanitized_hash = sha256(tokenized input))
    must still chain-verify correctly. We don't have a real v0.6.2 chain to
    hand; instead we synthesize an "old-style" entry by hand and confirm
    the verifier accepts it."""

    def setUp(self):
        self.dir = Path(tempfile.mkdtemp(prefix="cloakllm-g2-mixed-"))

    def test_synthetic_pre_v063_desanitize_entry_verifies(self):
        from cloakllm.audit import AuditLogger, GENESIS_HASH

        # Build a synthetic v0.6.2-style desanitize entry where
        # sanitized_hash hashes a different string than prompt_hash
        # (simulating sha256(restored_PII) in the old semantics).
        old_entry = {
            "seq": 0,
            "event_id": "00000000-0000-4000-8000-000000000000",
            "timestamp": "2026-04-18T10:00:00+00:00",
            "event_type": "desanitize",
            "model": None,
            "provider": None,
            "entity_count": 1,
            "categories": {"EMAIL": 1},
            "tokens_used": ["[EMAIL_0]"],
            "prompt_hash": hashlib.sha256(b"reply to [EMAIL_0]").hexdigest(),
            "sanitized_hash": hashlib.sha256(b"reply to alice@example.com").hexdigest(),  # OLD oracle
            "latency_ms": 0,
            "mode": "tokenize",
            "entity_details": [],
            "timing": {"total_ms": 0, "tokenization_ms": 0},
            "certificate_hash": None,
            "key_id": None,
            "prev_hash": GENESIS_HASH,
            "metadata": {},
            "risk_assessment": None,
        }
        # Compute the entry_hash the same way the v0.6.2 logger would have.
        entry_hash = AuditLogger._compute_hash(dict(old_entry))
        old_entry["entry_hash"] = entry_hash

        # Write it to the log dir and run verify_chain.
        log_path = self.dir / "audit_2026-04-18.jsonl"
        log_path.write_text(json.dumps(old_entry) + "\n", encoding="utf-8")

        cfg = ShieldConfig(log_dir=self.dir, audit_enabled=False)
        shield = Shield(cfg)
        ok, errors, _ = shield.audit.verify_chain()
        self.assertTrue(
            ok,
            f"v0.6.2-style entry should verify under v0.6.3 because chain "
            f"verification only checks entry-level hash linkage. Errors: {errors}"
        )


if __name__ == "__main__":
    unittest.main()
