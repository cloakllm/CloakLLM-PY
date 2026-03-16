"""
Cryptographic Attestation Module.

Ed25519 digital signatures for sanitization certificates.
Merkle trees for batch attestation. HKDF for key derivation.

Requires pynacl or cryptography for Ed25519 operations:
    pip install pynacl
    # or
    pip install cryptography

MerkleTree and derive_entity_hash_key use only stdlib (no optional deps).
"""

from __future__ import annotations

import base64
import hashlib
import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

# --- Optional Ed25519 backends ---

try:
    from nacl.signing import SigningKey, VerifyKey

    _HAS_NACL = True
except ImportError:
    _HAS_NACL = False

try:
    from cryptography.hazmat.primitives.asymmetric.ed25519 import (
        Ed25519PrivateKey,
        Ed25519PublicKey,
    )
    from cryptography.hazmat.primitives import serialization

    _HAS_CRYPTOGRAPHY = True
except ImportError:
    _HAS_CRYPTOGRAPHY = False


# --- Canonical JSON (must match JS exactly) ---

def _canonical_json(data: dict) -> str:
    """Deterministic JSON: sorted keys, compact separators, no floats."""
    return json.dumps(data, sort_keys=True, separators=(",", ":"))


# --- DeploymentKeyPair ---

@dataclass
class DeploymentKeyPair:
    """Ed25519 deployment keypair for signing sanitization certificates."""

    private_key: bytes
    public_key: bytes
    key_id: str

    @classmethod
    def generate(cls) -> DeploymentKeyPair:
        """Generate a new Ed25519 keypair."""
        if _HAS_NACL:
            sk = SigningKey.generate()
            private_key = bytes(sk)
            public_key = bytes(sk.verify_key)
        elif _HAS_CRYPTOGRAPHY:
            sk = Ed25519PrivateKey.generate()
            private_key = sk.private_bytes(
                serialization.Encoding.Raw,
                serialization.PrivateFormat.Raw,
                serialization.NoEncryption(),
            )
            public_key = sk.public_key().public_bytes(
                serialization.Encoding.Raw,
                serialization.PublicFormat.Raw,
            )
        else:
            raise ImportError(
                "Ed25519 requires pynacl or cryptography: "
                "pip install pynacl  # or: pip install cryptography"
            )
        key_id = hashlib.sha256(public_key).hexdigest()[:16]
        return cls(private_key=private_key, public_key=public_key, key_id=key_id)

    def sign(self, data: bytes) -> bytes:
        """Sign data with Ed25519. Returns 64-byte raw signature."""
        if _HAS_NACL:
            return SigningKey(self.private_key).sign(data).signature
        elif _HAS_CRYPTOGRAPHY:
            return Ed25519PrivateKey.from_private_bytes(self.private_key).sign(data)
        raise ImportError("No Ed25519 library available")

    def sign_b64(self, data: bytes) -> str:
        """Sign data and return base64-encoded signature."""
        return base64.b64encode(self.sign(data)).decode("ascii")

    @staticmethod
    def verify(public_key: bytes, data: bytes, signature: bytes) -> bool:
        """Verify an Ed25519 signature. Returns True if valid."""
        try:
            if _HAS_NACL:
                VerifyKey(public_key).verify(data, signature)
                return True
            elif _HAS_CRYPTOGRAPHY:
                Ed25519PublicKey.from_public_bytes(public_key).verify(signature, data)
                return True
        except Exception:
            return False
        return False

    @staticmethod
    def verify_b64(public_key: bytes, data: bytes, signature_b64: str) -> bool:
        """Verify a base64-encoded Ed25519 signature."""
        return DeploymentKeyPair.verify(
            public_key, data, base64.b64decode(signature_b64)
        )

    @property
    def public_key_b64(self) -> str:
        """Base64-encoded public key (44 chars)."""
        return base64.b64encode(self.public_key).decode("ascii")

    def save(self, path: Path | str) -> None:
        """Save keypair to JSON file with restricted permissions."""
        path = Path(path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(
            json.dumps(
                {
                    "key_id": self.key_id,
                    "private_key": base64.b64encode(self.private_key).decode(),
                    "public_key": base64.b64encode(self.public_key).decode(),
                },
                indent=2,
            )
        )
        try:
            path.chmod(0o600)
        except OSError:
            pass  # Windows doesn't support Unix permissions

    @classmethod
    def from_file(cls, path: Path | str) -> DeploymentKeyPair:
        """Load keypair from JSON file."""
        data = json.loads(Path(path).read_text())
        return cls(
            private_key=base64.b64decode(data["private_key"]),
            public_key=base64.b64decode(data["public_key"]),
            key_id=data["key_id"],
        )


# --- SanitizationCertificate ---

# Fields included in the signed payload (order doesn't matter — sorted by key)
_SIGNED_FIELDS = [
    "version",
    "timestamp",
    "input_hash",
    "output_hash",
    "entity_count",
    "categories",
    "detection_passes",
    "mode",
    "key_id",
]


@dataclass
class SanitizationCertificate:
    """Cryptographic proof that a sanitization operation occurred."""

    version: str = "1.0"
    timestamp: str = ""
    input_hash: str = ""
    output_hash: str = ""
    entity_count: int = 0
    categories: dict[str, int] = field(default_factory=dict)
    detection_passes: list[str] = field(default_factory=list)
    mode: str = "tokenize"
    key_id: str = ""
    signature: str = ""          # NOT included in signed payload
    public_key: str = ""         # NOT included in signed payload

    def _signed_payload(self) -> dict:
        """Extract only the fields that are signed."""
        return {k: getattr(self, k) for k in _SIGNED_FIELDS}

    def to_dict(self) -> dict:
        """Return all fields as a dict (including signature and public_key)."""
        d = self._signed_payload()
        d["signature"] = self.signature
        d["public_key"] = self.public_key
        return d

    @classmethod
    def create(
        cls,
        original_text: Optional[str],
        sanitized_text: Optional[str],
        entity_count: int,
        categories: dict[str, int],
        detection_passes: list[str],
        mode: str,
        keypair: DeploymentKeyPair,
        input_merkle_root: Optional[str] = None,
        output_merkle_root: Optional[str] = None,
    ) -> SanitizationCertificate:
        """Create and sign a new certificate."""
        if original_text is None and input_merkle_root is None:
            raise ValueError(
                "Either original_text or input_merkle_root must be provided"
            )
        if sanitized_text is None and output_merkle_root is None:
            raise ValueError(
                "Either sanitized_text or output_merkle_root must be provided"
            )

        input_hash = (
            input_merkle_root
            or hashlib.sha256(original_text.encode()).hexdigest()
        )
        output_hash = (
            output_merkle_root
            or hashlib.sha256(sanitized_text.encode()).hexdigest()
        )

        cert = cls(
            timestamp=datetime.now(timezone.utc).isoformat(),
            input_hash=input_hash,
            output_hash=output_hash,
            entity_count=entity_count,
            categories=dict(categories),
            detection_passes=list(detection_passes),
            mode=mode,
            key_id=keypair.key_id,
        )
        payload = _canonical_json(cert._signed_payload())
        cert.signature = keypair.sign_b64(payload.encode("utf-8"))
        cert.public_key = keypair.public_key_b64
        return cert

    def verify(self, public_key: bytes) -> bool:
        """Verify this certificate's signature against a public key."""
        payload = _canonical_json(self._signed_payload())
        return DeploymentKeyPair.verify_b64(
            public_key, payload.encode("utf-8"), self.signature
        )

    @classmethod
    def from_dict(cls, d: dict) -> SanitizationCertificate:
        """Reconstruct a certificate from a dict (e.g., from JSON)."""
        return cls(
            version=d.get("version", "1.0"),
            timestamp=d.get("timestamp", ""),
            input_hash=d.get("input_hash", ""),
            output_hash=d.get("output_hash", ""),
            entity_count=d.get("entity_count", 0),
            categories=d.get("categories", {}),
            detection_passes=d.get("detection_passes", []),
            mode=d.get("mode", "tokenize"),
            key_id=d.get("key_id", ""),
            signature=d.get("signature", ""),
            public_key=d.get("public_key", ""),
        )


# --- MerkleTree ---

class MerkleTree:
    """Binary Merkle tree for batch attestation."""

    def __init__(self, leaves: list[str]):
        if not leaves:
            raise ValueError("Cannot build Merkle tree with no leaves")
        self._leaves = list(leaves)
        self._tree: list[list[str]] = [self._leaves]
        self._build()

    @staticmethod
    def _hash_pair(left: str, right: str) -> str:
        """Hash two sibling nodes: SHA-256(left + right)."""
        return hashlib.sha256((left + right).encode("utf-8")).hexdigest()

    def _build(self) -> None:
        """Build the tree bottom-up. Odd leaves are promoted."""
        current = self._leaves
        while len(current) > 1:
            next_level: list[str] = []
            for i in range(0, len(current), 2):
                if i + 1 < len(current):
                    next_level.append(self._hash_pair(current[i], current[i + 1]))
                else:
                    next_level.append(current[i])  # odd leaf promoted
            self._tree.append(next_level)
            current = next_level

    @property
    def root(self) -> str:
        """Root hash of the Merkle tree."""
        return self._tree[-1][0]

    def proof(self, index: int) -> list[tuple[str, str]]:
        """
        Generate a Merkle proof for the leaf at the given index.

        Returns a list of (sibling_hash, side) tuples where side is
        "left" or "right" indicating the sibling's position.
        """
        if index < 0 or index >= len(self._leaves):
            raise IndexError(f"Leaf index {index} out of range")
        proof_path: list[tuple[str, str]] = []
        idx = index
        for level in self._tree[:-1]:
            if idx % 2 == 0:
                if idx + 1 < len(level):
                    proof_path.append((level[idx + 1], "right"))
            else:
                proof_path.append((level[idx - 1], "left"))
            idx //= 2
        return proof_path

    @staticmethod
    def verify_proof(
        leaf_hash: str, proof: list[tuple[str, str]], root: str
    ) -> bool:
        """Verify a Merkle proof against a root hash."""
        current = leaf_hash
        for sibling_hash, side in proof:
            if side == "left":
                current = MerkleTree._hash_pair(sibling_hash, current)
            else:
                current = MerkleTree._hash_pair(current, sibling_hash)
        return current == root


# --- HKDF Key Derivation ---

def derive_entity_hash_key(
    master_key: bytes,
    salt: bytes = b"",
    info: bytes = b"cloakllm-entity-hash",
) -> str:
    """
    Derive an entity hash key from a master key using HKDF-SHA256.

    Uses only stdlib (hmac + hashlib). No optional deps needed.

    Args:
        master_key: Raw key material (e.g., deployment keypair private key)
        salt: Optional salt (defaults to 32 zero bytes)
        info: Context info string (defaults to b"cloakllm-entity-hash")

    Returns:
        64-char hex string (32 bytes)
    """
    import hmac as _hmac

    if not salt:
        salt = b"\x00" * 32
    # HKDF-Extract
    prk = _hmac.new(salt, master_key, hashlib.sha256).digest()
    # HKDF-Expand (single block — 32 bytes is <= hash output size)
    okm = _hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm.hex()
