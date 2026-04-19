"""v0.6.3 I7 — Python verifies fixtures written by the JS SDK.

Each SDK ships a generator (tests/fixtures/generate_cross_sdk_fixtures.{py,js})
that produces a small audit chain + a signed certificate. Both fixtures are
mirrored into the OTHER SDK's fixtures directory and read by these tests.

Cross-SDK round-trip is the strongest possible cross-language regression
gate: a future change to canonical JSON, audit hash chaining, or the
attestation signing scheme breaks CI on BOTH sides immediately.

To regenerate fixtures (commit the result):
    python tests/fixtures/generate_cross_sdk_fixtures.py
    node ../cloakllm-js/test/fixtures/generate_cross_sdk_fixtures.js
"""

from __future__ import annotations

import base64
import json
import shutil
import tempfile
import unittest
from pathlib import Path

from cloakllm import Shield, ShieldConfig
from cloakllm.attestation import SanitizationCertificate


HERE = Path(__file__).parent
FIXTURES = HERE / "fixtures"


def _load_metadata() -> dict:
    return json.loads((FIXTURES / "cross_sdk_metadata.json").read_text(encoding="utf-8"))


class TestVerifyJsAuditChain(unittest.TestCase):
    """Python verifies the audit chain JSONL produced by JS."""

    def setUp(self):
        self.fixture = FIXTURES / "audit_chain_js.jsonl"
        if not self.fixture.exists():
            self.skipTest(
                "audit_chain_js.jsonl missing — regenerate via "
                "node ../cloakllm-js/test/fixtures/generate_cross_sdk_fixtures.js"
            )

    def test_js_chain_passes_python_verify_chain(self):
        # Stage the JS-written file into a temp log dir, then verify_chain.
        tmp = Path(tempfile.mkdtemp(prefix="cloakllm-i7-py-vs-js-"))
        try:
            shutil.copy(self.fixture, tmp / "audit_2026-04-19.jsonl")
            shield = Shield(ShieldConfig(log_dir=tmp, audit_enabled=False))
            ok, errors, final_seq = shield.audit.verify_chain()
            self.assertTrue(
                ok,
                f"JS-written chain failed Python verify_chain. "
                f"Errors: {errors}\nFinal seq: {final_seq}",
            )
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_js_chain_metadata_matches_fixture_content(self):
        # The metadata recorded by the JS generator should match what we see
        # when we count entries — guards against accidental fixture rot.
        meta = _load_metadata()
        js_meta = meta.get("javascript_chain") or {}
        self.assertTrue(js_meta.get("chain_valid"), "JS generator reported chain invalid")
        actual_entries = sum(
            1 for line in self.fixture.read_text(encoding="utf-8").splitlines() if line.strip()
        )
        self.assertEqual(actual_entries, js_meta["entries"])


class TestVerifyJsCertificate(unittest.TestCase):
    """Python verifies the signed certificate produced by JS."""

    def setUp(self):
        self.fixture = FIXTURES / "certificate_js.json"
        if not self.fixture.exists():
            self.skipTest(
                "certificate_js.json missing — regenerate via "
                "node ../cloakllm-js/test/fixtures/generate_cross_sdk_fixtures.js"
            )

    def test_js_certificate_signature_verifies_in_python(self):
        wrapper = json.loads(self.fixture.read_text(encoding="utf-8"))
        cert_dict = wrapper["certificate"]
        public_key = base64.b64decode(wrapper["public_key_b64"])
        cert = SanitizationCertificate.from_dict(cert_dict)
        self.assertTrue(
            cert.verify(public_key),
            "JS-signed certificate failed Python verify(). "
            "This means the canonical JSON or the Ed25519 signing scheme "
            "diverged between SDKs.",
        )

    def test_js_certificate_metadata_matches(self):
        meta = _load_metadata()
        js_meta = meta.get("javascript_certificate") or {}
        wrapper = json.loads(self.fixture.read_text(encoding="utf-8"))
        cert = wrapper["certificate"]
        self.assertEqual(cert["entity_count"], js_meta["entity_count"])
        self.assertEqual(cert["input_hash"], js_meta["input_hash"])
        self.assertEqual(cert["output_hash"], js_meta["output_hash"])


class TestVerifyPythonOwnFixtures(unittest.TestCase):
    """Sanity check: the Python-written fixtures still verify in Python.
    Detects regression in either the generator OR the verifier."""

    def test_python_chain_self_verifies(self):
        f = FIXTURES / "audit_chain_py.jsonl"
        if not f.exists():
            self.skipTest("audit_chain_py.jsonl not generated yet")
        tmp = Path(tempfile.mkdtemp(prefix="cloakllm-i7-py-self-"))
        try:
            shutil.copy(f, tmp / "audit_2026-04-19.jsonl")
            shield = Shield(ShieldConfig(log_dir=tmp, audit_enabled=False))
            ok, errors, _ = shield.audit.verify_chain()
            self.assertTrue(ok, f"Python self-chain failed: {errors}")
        finally:
            shutil.rmtree(tmp, ignore_errors=True)

    def test_python_certificate_self_verifies(self):
        f = FIXTURES / "certificate_py.json"
        if not f.exists():
            self.skipTest("certificate_py.json not generated yet")
        wrapper = json.loads(f.read_text(encoding="utf-8"))
        cert = SanitizationCertificate.from_dict(wrapper["certificate"])
        public_key = base64.b64decode(wrapper["public_key_b64"])
        self.assertTrue(cert.verify(public_key))


if __name__ == "__main__":
    unittest.main()
