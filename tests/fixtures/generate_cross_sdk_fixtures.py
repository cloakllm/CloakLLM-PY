"""v0.6.3 I7 — generate cross-SDK fixture corpus from the Python SDK.

Run from cloakllm-py root:

    python tests/fixtures/generate_cross_sdk_fixtures.py

Produces three fixtures, all committed under tests/fixtures/ AND mirrored
into cloakllm-js/test/fixtures/ for the JS suite to verify:

  * audit_chain_py.jsonl       — small audit chain written by Python
  * certificate_py.json        — signed sanitization certificate from Python
  * cross_sdk_metadata.json    — describes what's in each fixture so the
                                 JS-side verifier can assert specific
                                 invariants (entity_count, categories, etc.)

The JS SDK ships a parallel generator that produces audit_chain_js.jsonl,
certificate_js.json, and updates cross_sdk_metadata.json. Each SDK's I7
tests verify the OTHER SDK's fixture.

Idempotent: running the script twice produces functionally-identical
output (chain valid, certificate self-verifies). Timestamps and signatures
will differ across runs because audit timestamps and certificate nonces
are not pinned — but the chain hash linkage and certificate signature
are deterministic given their pinned inputs.
"""

from __future__ import annotations

import base64
import json
import shutil
import tempfile
from datetime import datetime, timezone
from pathlib import Path

from cloakllm import Shield, ShieldConfig
from cloakllm.attestation import DeploymentKeyPair, SanitizationCertificate


HERE = Path(__file__).parent
PY_FIXTURES = HERE
JS_FIXTURES = HERE.parent.parent.parent / "cloakllm-js" / "test" / "fixtures"


# 32-byte test seed for reproducible signing keypair (NOT a real key — the
# private bytes are committed to the repo). Same seed in Py and JS yields
# the same Ed25519 keypair, so cross-SDK signature verification is meaningful.
_PINNED_KEY_SEED = (b"cloakllm_i7_seed_v063" + b"\x00" * 32)[:32]
assert len(_PINNED_KEY_SEED) == 32


def _build_pinned_keypair() -> DeploymentKeyPair:
    """Build an Ed25519 keypair from the pinned seed."""
    try:
        # Prefer cryptography (often present in cloakllm[attestation])
        from cryptography.hazmat.primitives.asymmetric.ed25519 import (
            Ed25519PrivateKey,
        )
        from cryptography.hazmat.primitives import serialization
        priv = Ed25519PrivateKey.from_private_bytes(_PINNED_KEY_SEED)
        priv_bytes = priv.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
        pub_bytes = priv.public_key().public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    except ImportError:
        from nacl.signing import SigningKey
        sk = SigningKey(_PINNED_KEY_SEED)
        priv_bytes = bytes(sk)
        pub_bytes = bytes(sk.verify_key)
    key_id = "cross_sdk_test_v063"
    return DeploymentKeyPair(
        private_key=priv_bytes,
        public_key=pub_bytes,
        key_id=key_id,
    )


def _write_audit_chain_fixture(out_path: Path) -> dict:
    """Generate a small audit chain via Shield and dump to JSONL."""
    tmp = Path(tempfile.mkdtemp(prefix="cloakllm_i7_chain_"))
    try:
        shield = Shield(ShieldConfig(
            log_dir=tmp,
            audit_enabled=True,
            compliance_mode="eu_ai_act_article12",
        ))
        # Mix of categories so the chain has variety.
        shield.sanitize("Email john@example.com about the meeting.")
        shield.sanitize("Reach Sarah at sarah@example.org or call 555-123-4567.")
        shield.sanitize("SSN 123-45-6789 should never appear in logs.")
        chain_files = sorted(tmp.glob("audit_*.jsonl"))
        assert chain_files, "no audit file produced"
        content = chain_files[-1].read_text(encoding="utf-8")
        out_path.write_text(content, encoding="utf-8")
        ok, errors, final_seq = shield.audit.verify_chain()
        return {
            "format": "jsonl",
            "writer_sdk": "python",
            "writer_version": "0.6.3",
            "chain_valid": ok,
            "chain_errors": errors,
            "final_seq": final_seq,
            "entries": len([l for l in content.splitlines() if l.strip()]),
        }
    finally:
        shutil.rmtree(tmp, ignore_errors=True)


def _write_certificate_fixture(out_path: Path) -> dict:
    """Generate a signed sanitization certificate."""
    keypair = _build_pinned_keypair()
    cert = SanitizationCertificate.create(
        original_text="Email john@example.com please",
        sanitized_text="Email [EMAIL_0] please",
        entity_count=1,
        categories={"EMAIL": 1},
        detection_passes=["regex"],
        mode="tokenize",
        keypair=keypair,
    )
    cert_dict = cert.to_dict()
    out_path.write_text(
        json.dumps({
            "certificate": cert_dict,
            "public_key_b64": keypair.public_key_b64,
            "key_id": keypair.key_id,
        }, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    self_verify_ok = cert.verify(keypair.public_key)
    return {
        "writer_sdk": "python",
        "writer_version": "0.6.3",
        "self_verify_ok": self_verify_ok,
        "input_hash": cert_dict.get("input_hash"),
        "output_hash": cert_dict.get("output_hash"),
        "entity_count": cert_dict.get("entity_count"),
    }


def main() -> None:
    PY_FIXTURES.mkdir(parents=True, exist_ok=True)
    JS_FIXTURES.mkdir(parents=True, exist_ok=True)

    chain_path_py = PY_FIXTURES / "audit_chain_py.jsonl"
    cert_path_py = PY_FIXTURES / "certificate_py.json"

    chain_meta = _write_audit_chain_fixture(chain_path_py)
    cert_meta = _write_certificate_fixture(cert_path_py)

    # Mirror to JS fixtures dir.
    shutil.copyfile(chain_path_py, JS_FIXTURES / "audit_chain_py.jsonl")
    shutil.copyfile(cert_path_py, JS_FIXTURES / "certificate_py.json")

    # Update / merge metadata (the JS generator writes the JS-side keys).
    meta_path_py = PY_FIXTURES / "cross_sdk_metadata.json"
    meta_path_js = JS_FIXTURES / "cross_sdk_metadata.json"
    existing = {}
    if meta_path_py.exists():
        try:
            existing = json.loads(meta_path_py.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    existing["python_chain"] = chain_meta
    existing["python_certificate"] = cert_meta
    existing["regenerated_at_utc"] = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    payload = json.dumps(existing, indent=2, sort_keys=True) + "\n"
    meta_path_py.write_text(payload, encoding="utf-8")
    meta_path_js.write_text(payload, encoding="utf-8")

    print(f"wrote {chain_path_py.name} ({chain_meta['entries']} entries, valid={chain_meta['chain_valid']})")
    print(f"wrote {cert_path_py.name} (self_verify_ok={cert_meta['self_verify_ok']})")
    print(f"mirrored both into {JS_FIXTURES.name}/")
    print(f"updated cross_sdk_metadata.json in both repos")


if __name__ == "__main__":
    main()
