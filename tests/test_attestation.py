"""
Unit tests for the cryptographic attestation module.

Tests: DeploymentKeyPair, SanitizationCertificate, MerkleTree, derive_entity_hash_key.
"""

import base64
import hashlib
import json
import sys
import tempfile
from pathlib import Path

import pytest

from cloakllm.attestation import (
    DeploymentKeyPair,
    MerkleTree,
    SanitizationCertificate,
    _canonical_json,
    derive_entity_hash_key,
)


# ── DeploymentKeyPair ──────────────────────────────────────────


class TestDeploymentKeyPair:
    """Tests for Ed25519 deployment keypair."""

    def test_generate_creates_valid_keypair(self):
        kp = DeploymentKeyPair.generate()
        assert len(kp.private_key) == 32
        assert len(kp.public_key) == 32
        assert len(kp.key_id) == 16
        assert all(c in "0123456789abcdef" for c in kp.key_id)

    def test_sign_and_verify_roundtrip(self):
        kp = DeploymentKeyPair.generate()
        data = b"hello world"
        sig = kp.sign(data)
        assert len(sig) == 64
        assert DeploymentKeyPair.verify(kp.public_key, data, sig) is True

    def test_verify_wrong_data_fails(self):
        kp = DeploymentKeyPair.generate()
        sig = kp.sign(b"correct data")
        assert DeploymentKeyPair.verify(kp.public_key, b"wrong data", sig) is False

    def test_verify_wrong_key_fails(self):
        kp1 = DeploymentKeyPair.generate()
        kp2 = DeploymentKeyPair.generate()
        sig = kp1.sign(b"data")
        assert DeploymentKeyPair.verify(kp2.public_key, b"data", sig) is False

    def test_save_and_load_roundtrip(self):
        kp = DeploymentKeyPair.generate()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "key.json"
            kp.save(path)
            loaded = DeploymentKeyPair.from_file(path)
            assert loaded.private_key == kp.private_key
            assert loaded.public_key == kp.public_key
            assert loaded.key_id == kp.key_id

    @pytest.mark.skipif(sys.platform == "win32", reason="Unix permissions not on Windows")
    def test_save_sets_permissions(self):
        kp = DeploymentKeyPair.generate()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "key.json"
            kp.save(path)
            mode = path.stat().st_mode & 0o777
            assert mode == 0o600

    def test_key_id_deterministic(self):
        kp = DeploymentKeyPair.generate()
        expected = hashlib.sha256(kp.public_key).hexdigest()[:16]
        assert kp.key_id == expected

    def test_sign_b64_format(self):
        kp = DeploymentKeyPair.generate()
        sig_b64 = kp.sign_b64(b"test")
        raw = base64.b64decode(sig_b64)
        assert len(raw) == 64

    def test_public_key_b64_property(self):
        kp = DeploymentKeyPair.generate()
        decoded = base64.b64decode(kp.public_key_b64)
        assert decoded == kp.public_key
        assert len(decoded) == 32

    def test_verify_b64_roundtrip(self):
        kp = DeploymentKeyPair.generate()
        data = b"verify b64 test"
        sig_b64 = kp.sign_b64(data)
        assert DeploymentKeyPair.verify_b64(kp.public_key, data, sig_b64) is True
        assert DeploymentKeyPair.verify_b64(kp.public_key, b"wrong", sig_b64) is False

    def test_loaded_key_can_sign(self):
        """Key loaded from file can sign and verify."""
        kp = DeploymentKeyPair.generate()
        with tempfile.TemporaryDirectory() as tmpdir:
            path = Path(tmpdir) / "key.json"
            kp.save(path)
            loaded = DeploymentKeyPair.from_file(path)
            sig = loaded.sign(b"loaded key test")
            assert DeploymentKeyPair.verify(loaded.public_key, b"loaded key test", sig)


# ── SanitizationCertificate ────────────────────────────────────


class TestSanitizationCertificate:
    """Tests for sanitization certificates."""

    @pytest.fixture
    def keypair(self):
        return DeploymentKeyPair.generate()

    def test_create_produces_valid_cert(self, keypair):
        cert = SanitizationCertificate.create(
            "input text", "output text", 2, {"EMAIL": 1, "PHONE": 1},
            ["regex", "ner"], "tokenize", keypair,
        )
        assert cert.version == "1.0"
        assert cert.timestamp != ""
        assert cert.input_hash != ""
        assert cert.output_hash != ""
        assert cert.entity_count == 2
        assert cert.categories == {"EMAIL": 1, "PHONE": 1}
        assert cert.detection_passes == ["regex", "ner"]
        assert cert.mode == "tokenize"
        assert cert.key_id == keypair.key_id
        assert cert.signature != ""
        assert cert.public_key != ""

    def test_create_and_verify_roundtrip(self, keypair):
        cert = SanitizationCertificate.create(
            "hello", "world", 1, {"EMAIL": 1}, ["regex"], "tokenize", keypair,
        )
        assert cert.verify(keypair.public_key) is True

    def test_verify_tampered_input_hash_fails(self, keypair):
        cert = SanitizationCertificate.create(
            "hello", "world", 1, {"EMAIL": 1}, ["regex"], "tokenize", keypair,
        )
        cert.input_hash = "tampered"
        assert cert.verify(keypair.public_key) is False

    def test_verify_tampered_entity_count_fails(self, keypair):
        cert = SanitizationCertificate.create(
            "hello", "world", 1, {"EMAIL": 1}, ["regex"], "tokenize", keypair,
        )
        cert.entity_count = 999
        assert cert.verify(keypair.public_key) is False

    def test_verify_tampered_signature_fails(self, keypair):
        cert = SanitizationCertificate.create(
            "hello", "world", 1, {"EMAIL": 1}, ["regex"], "tokenize", keypair,
        )
        cert.signature = base64.b64encode(b"\x00" * 64).decode()
        assert cert.verify(keypair.public_key) is False

    def test_verify_wrong_key_fails(self, keypair):
        kp2 = DeploymentKeyPair.generate()
        cert = SanitizationCertificate.create(
            "hello", "world", 1, {"EMAIL": 1}, ["regex"], "tokenize", keypair,
        )
        assert cert.verify(kp2.public_key) is False

    def test_to_dict_contains_all_fields(self, keypair):
        cert = SanitizationCertificate.create(
            "hello", "world", 0, {}, ["regex"], "tokenize", keypair,
        )
        d = cert.to_dict()
        expected_fields = {
            "version", "timestamp", "input_hash", "output_hash",
            "entity_count", "categories", "detection_passes", "mode",
            "key_id", "signature", "public_key",
        }
        assert set(d.keys()) == expected_fields

    def test_timestamp_is_utc_iso(self, keypair):
        cert = SanitizationCertificate.create(
            "hello", "world", 0, {}, ["regex"], "tokenize", keypair,
        )
        from datetime import datetime
        # Should parse without error
        dt = datetime.fromisoformat(cert.timestamp)
        assert dt.tzinfo is not None  # has timezone

    def test_input_hash_is_sha256(self, keypair):
        cert = SanitizationCertificate.create(
            "hello", "world", 0, {}, ["regex"], "tokenize", keypair,
        )
        assert len(cert.input_hash) == 64
        assert all(c in "0123456789abcdef" for c in cert.input_hash)
        assert cert.input_hash == hashlib.sha256(b"hello").hexdigest()

    def test_output_hash_is_sha256(self, keypair):
        cert = SanitizationCertificate.create(
            "hello", "world", 0, {}, ["regex"], "tokenize", keypair,
        )
        assert len(cert.output_hash) == 64
        assert cert.output_hash == hashlib.sha256(b"world").hexdigest()

    def test_from_dict_roundtrip(self, keypair):
        cert = SanitizationCertificate.create(
            "hello", "world", 1, {"EMAIL": 1}, ["regex"], "tokenize", keypair,
        )
        d = cert.to_dict()
        cert2 = SanitizationCertificate.from_dict(d)
        assert cert2.verify(keypair.public_key) is True
        assert cert2.to_dict() == d

    def test_batch_cert_with_merkle_roots(self, keypair):
        cert = SanitizationCertificate.create(
            original_text=None,
            sanitized_text=None,
            entity_count=3,
            categories={"EMAIL": 2, "PHONE": 1},
            detection_passes=["regex"],
            mode="tokenize",
            keypair=keypair,
            input_merkle_root="abc123",
            output_merkle_root="def456",
        )
        assert cert.input_hash == "abc123"
        assert cert.output_hash == "def456"
        assert cert.verify(keypair.public_key) is True

    def test_create_no_text_no_merkle_raises(self, keypair):
        with pytest.raises(ValueError, match="original_text or input_merkle_root"):
            SanitizationCertificate.create(
                None, "out", 0, {}, [], "tokenize", keypair,
            )
        with pytest.raises(ValueError, match="sanitized_text or output_merkle_root"):
            SanitizationCertificate.create(
                "in", None, 0, {}, [], "tokenize", keypair,
            )

    def test_public_key_in_dict_matches_keypair(self, keypair):
        cert = SanitizationCertificate.create(
            "hello", "world", 0, {}, ["regex"], "tokenize", keypair,
        )
        assert cert.public_key == keypair.public_key_b64

    def test_empty_categories_and_passes(self, keypair):
        """Certificate with empty categories and no passes verifies."""
        cert = SanitizationCertificate.create(
            "no pii", "no pii", 0, {}, [], "tokenize", keypair,
        )
        assert cert.verify(keypair.public_key) is True
        assert cert.entity_count == 0
        assert cert.categories == {}
        assert cert.detection_passes == []


# ── MerkleTree ─────────────────────────────────────────────────


class TestMerkleTree:
    """Tests for Merkle tree."""

    def test_single_leaf(self):
        tree = MerkleTree(["abc123"])
        assert tree.root == "abc123"

    def test_two_leaves(self):
        tree = MerkleTree(["aaa", "bbb"])
        expected = hashlib.sha256(b"aaabbb").hexdigest()
        assert tree.root == expected

    def test_three_leaves_odd_promotion(self):
        tree = MerkleTree(["aaa", "bbb", "ccc"])
        level1_left = hashlib.sha256(b"aaabbb").hexdigest()
        level1_right = "ccc"  # promoted
        expected = hashlib.sha256((level1_left + level1_right).encode()).hexdigest()
        assert tree.root == expected

    def test_four_leaves(self):
        tree = MerkleTree(["a", "b", "c", "d"])
        h_ab = hashlib.sha256(b"ab").hexdigest()
        h_cd = hashlib.sha256(b"cd").hexdigest()
        expected = hashlib.sha256((h_ab + h_cd).encode()).hexdigest()
        assert tree.root == expected

    def test_proof_and_verify_all_indices(self):
        leaves = [hashlib.sha256(f"leaf{i}".encode()).hexdigest() for i in range(8)]
        tree = MerkleTree(leaves)
        for i in range(8):
            proof = tree.proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, tree.root) is True

    def test_proof_tampered_leaf_fails(self):
        leaves = ["aaa", "bbb", "ccc", "ddd"]
        tree = MerkleTree(leaves)
        proof = tree.proof(0)
        assert MerkleTree.verify_proof("TAMPERED", proof, tree.root) is False

    def test_empty_leaves_raises(self):
        with pytest.raises(ValueError, match="no leaves"):
            MerkleTree([])

    def test_proof_out_of_range_raises(self):
        tree = MerkleTree(["a", "b"])
        with pytest.raises(IndexError):
            tree.proof(2)
        with pytest.raises(IndexError):
            tree.proof(-1)

    def test_five_leaves_odd(self):
        """5 leaves: odd at level 0 and level 1."""
        leaves = ["a", "b", "c", "d", "e"]
        tree = MerkleTree(leaves)
        for i in range(5):
            proof = tree.proof(i)
            assert MerkleTree.verify_proof(leaves[i], proof, tree.root)

    def test_single_leaf_proof_empty(self):
        """Single leaf has an empty proof path."""
        tree = MerkleTree(["only"])
        proof = tree.proof(0)
        assert proof == []
        assert MerkleTree.verify_proof("only", proof, tree.root)


# ── HKDF ───────────────────────────────────────────────────────


class TestHKDF:
    """Tests for HKDF key derivation."""

    def test_derive_produces_64_char_hex(self):
        key = derive_entity_hash_key(b"master")
        assert len(key) == 64
        assert all(c in "0123456789abcdef" for c in key)

    def test_derive_deterministic(self):
        k1 = derive_entity_hash_key(b"same-key")
        k2 = derive_entity_hash_key(b"same-key")
        assert k1 == k2

    def test_derive_different_salt_different_key(self):
        k1 = derive_entity_hash_key(b"key", salt=b"salt-a" + b"\x00" * 26)
        k2 = derive_entity_hash_key(b"key", salt=b"salt-b" + b"\x00" * 26)
        assert k1 != k2

    def test_derive_different_info_different_key(self):
        k1 = derive_entity_hash_key(b"key", info=b"info-a")
        k2 = derive_entity_hash_key(b"key", info=b"info-b")
        assert k1 != k2

    def test_derive_known_vector(self):
        """Cross-language test: must match Node.js hkdfSync output."""
        result = derive_entity_hash_key(b"test-master-key-1234567890abcdef")
        assert result == "2836bb676c8d77ebbf3c5101a6d25d674123ebd0eff8b4354060119bfd182e49"


# ── Canonical JSON ─────────────────────────────────────────────


class TestCanonicalJSON:
    """Tests for canonical JSON serialization."""

    def test_sorted_keys(self):
        result = _canonical_json({"b": 2, "a": 1})
        assert result == '{"a":1,"b":2}'

    def test_nested_sorted_keys(self):
        result = _canonical_json({"z": {"b": 2, "a": 1}})
        # json.dumps with sort_keys sorts at ALL levels
        assert result == '{"z":{"a":1,"b":2}}'

    def test_compact_separators(self):
        result = _canonical_json({"key": "value"})
        assert " " not in result

    def test_integer_not_float(self):
        """Integers must serialize as integers (no .0), matching JS."""
        result = _canonical_json({"n": 3})
        assert result == '{"n":3}'
