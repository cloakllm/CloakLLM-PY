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
import logging
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger("cloakllm.attestation")

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
# Delegated to cloakllm._canonical for cross-SDK byte-equivalence (v0.6.1+).
# Pre-v0.6.1 this used `ensure_ascii=True`, which broke verification of any
# non-ASCII data across SDKs. See `_canonical.py` for details.

from cloakllm._canonical import canonical_json as _canonical_json  # noqa: E402,F401


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
            import platform
            if platform.system() == "Windows":
                logger.warning(
                    "Cannot set restrictive file permissions on Windows for '%s'. "
                    "Ensure the file is protected by NTFS ACLs.", path
                )

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
    "nonce",
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
    nonce: str = ""
    signature: str = ""          # NOT included in signed payload
    public_key: str = ""         # NOT included in signed payload

    def _signed_payload(self) -> dict:
        """Extract only the fields that are signed."""
        return {k: getattr(self, k) for k in _SIGNED_FIELDS}

    def to_dict(self) -> dict:
        """Return all fields as a dict (including signature, public_key, and nonce)."""
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
            nonce=str(uuid.uuid4()),
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
            nonce=d.get("nonce", ""),
            signature=d.get("signature", ""),
            public_key=d.get("public_key", ""),
        )


# --- MerkleTree ---

class MerkleTree:
    """Binary Merkle tree for batch attestation.

    Builds a bottom-up SHA-256 hash tree from a list of leaf hashes.
    When a tree level has an odd number of nodes, the last node is
    promoted to the next level without hashing (odd-leaf promotion).
    This avoids duplicating leaves and keeps proofs compact.
    """

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
    # HKDF-Expand (single block -- 32 bytes is <= hash output size)
    okm = _hmac.new(prk, info + b"\x01", hashlib.sha256).digest()
    return okm.hex()


# ===================================================================
# v0.8.1 KM-1: KeyManifest -- externally-verifiable key provenance
# ===================================================================
#
# Today (v0.7.x/v0.8.0) an Ed25519 attestation surface proves exactly:
#   "The holder of private key K signed this certificate."
#
# It does NOT prove who holds K, whether K was authorized by the deployer,
# whether K is still valid, or whether K has been revoked. KeyManifest
# binds a signing key to a deployer identity + validity window, optionally
# signed by a SEPARATE offline root key (the chain-of-trust anchor).
#
# See PLAN_v081.md + COMPLIANCE.md "Externally-Verifiable Key Provenance"
# for the threat model and explicit boundary callouts (trusted timestamping
# remains out of scope -- v1.0 candidate via RFC 3161 / sigstore Rekor).
#
# Cross-SDK invariant: Python-generated manifests verify in JS and vice
# versa. Extends the I7 fixture parity contract.

KEY_MANIFEST_SCHEMA_VERSION = "1.0"
_KEY_MANIFEST_PURPOSE_WHITELIST = frozenset({"cloakllm-audit-attestation"})
_KEY_MANIFEST_DEPLOYER_ID_MAX = 256
_KEY_MANIFEST_ROOT_KEY_ID_MAX = 256

# Fields included in the manifest_hash (sorted by key by canonical_json).
# Excludes manifest_hash itself + root_signature (which signs manifest_hash).
_MANIFEST_HASH_FIELDS = (
    "key_id",
    "public_key",
    "deployer_id",
    "valid_from",
    "valid_until",
    "purpose",
    "manifest_version",
    "root_key_id",
)


def _validate_iso8601_utc(value: str, field_name: str) -> None:
    """Reject non-ISO-8601, non-UTC, or non-string timestamps.

    v0.8.1 AUDIT-3 hardening lesson from v0.8.0: defensive parsing at the
    boundary. Producers always emit ISO 8601 UTC; rejection here catches
    corrupt hand-edits before they propagate into the hash.
    """
    if not isinstance(value, str) or not value:
        raise ValueError(f"{field_name} must be a non-empty ISO 8601 string")
    # Accept "+00:00" or "Z"; reject naive timestamps.
    if not (value.endswith("+00:00") or value.endswith("Z")):
        raise ValueError(
            f"{field_name} must be UTC (end with '+00:00' or 'Z'); got {value!r}"
        )
    # Sanity-check parseability.
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as e:
        raise ValueError(f"{field_name} is not a valid ISO 8601 timestamp: {e}")


@dataclass(frozen=True)
class KeyManifest:
    """v0.8.1 externally-verifiable binding of a signing key to a deployer
    identity and validity window.

    Generated at key-creation time; published alongside the deployment so
    external auditors can verify CloakLLM audit chains without trusting
    CloakLLM or the deployer out-of-band.

    The manifest is self-contained -- it carries the public key, deployer
    identity, validity window, and (optionally) a root signature that
    anchors the chain of trust to an offline root key.

    Use `derive_key_manifest()` to construct; the factory enforces field
    validation, computes the deterministic manifest_hash, and optionally
    invokes a root-signing callback.
    """

    # --- Identity ---
    key_id: str                       # Existing CloakLLM key_id (string, <= 64 chars)
    public_key: str                   # Base64 Ed25519 public key (32-byte raw + b64)
    deployer_id: str                  # Free-form deployer identifier. <= 256 chars.

    # --- Validity window ---
    valid_from: str                   # ISO 8601 UTC timestamp
    valid_until: Optional[str]        # ISO 8601 UTC OR None (open-ended)

    # --- Purpose binding ---
    purpose: str                      # Must be "cloakllm-audit-attestation"

    # --- Integrity ---
    manifest_version: str             # "1.0"
    manifest_hash: str                # SHA-256 hex of canonical_json of _MANIFEST_HASH_FIELDS

    # --- Chain of trust (optional, but load-bearing when present) ---
    root_signature: Optional[str] = None   # Base64 Ed25519 sig over manifest_hash
    root_key_id: Optional[str] = None      # Identifier of the root key

    def to_dict(self) -> dict:
        """Return all fields as a dict for JSON serialization."""
        return {
            "key_id": self.key_id,
            "public_key": self.public_key,
            "deployer_id": self.deployer_id,
            "valid_from": self.valid_from,
            "valid_until": self.valid_until,
            "purpose": self.purpose,
            "manifest_version": self.manifest_version,
            "manifest_hash": self.manifest_hash,
            "root_signature": self.root_signature,
            "root_key_id": self.root_key_id,
        }

    @classmethod
    def from_dict(cls, d: dict) -> KeyManifest:
        """Reconstruct a KeyManifest from a dict (e.g., from JSON).

        Does NOT re-validate field semantics or recompute manifest_hash --
        use `verify_key_provenance(...)` to check integrity. This is the
        deserializer; verification is a separate concern.
        """
        if not isinstance(d, dict):
            raise TypeError(f"KeyManifest.from_dict expects a dict, got {type(d).__name__}")
        return cls(
            key_id=str(d.get("key_id", "")),
            public_key=str(d.get("public_key", "")),
            deployer_id=str(d.get("deployer_id", "")),
            valid_from=str(d.get("valid_from", "")),
            valid_until=d.get("valid_until"),
            purpose=str(d.get("purpose", "")),
            manifest_version=str(d.get("manifest_version", KEY_MANIFEST_SCHEMA_VERSION)),
            manifest_hash=str(d.get("manifest_hash", "")),
            root_signature=d.get("root_signature"),
            root_key_id=d.get("root_key_id"),
        )


def _compute_manifest_hash(
    *,
    key_id: str,
    public_key: str,
    deployer_id: str,
    valid_from: str,
    valid_until: Optional[str],
    purpose: str,
    manifest_version: str,
    root_key_id: Optional[str],
) -> str:
    """Deterministic SHA-256 of the canonical-JSON of _MANIFEST_HASH_FIELDS.

    Cross-SDK invariant: same inputs in Py and JS must produce the same hash.
    Delegated to `_canonical_json` (the same canonicaliser used by audit
    chain entries since v0.6.1).
    """
    payload = {
        "key_id": key_id,
        "public_key": public_key,
        "deployer_id": deployer_id,
        "valid_from": valid_from,
        "valid_until": valid_until,
        "purpose": purpose,
        "manifest_version": manifest_version,
        "root_key_id": root_key_id,
    }
    return hashlib.sha256(_canonical_json(payload).encode("utf-8")).hexdigest()


def derive_key_manifest(
    keypair: DeploymentKeyPair,
    *,
    deployer_id: str,
    valid_from: Optional[str] = None,
    valid_until: Optional[str] = None,
    purpose: str = "cloakllm-audit-attestation",
    root_signing_callback: Optional[Any] = None,
    root_key_id: Optional[str] = None,
) -> KeyManifest:
    """Produce a KeyManifest binding `keypair` to `deployer_id`.

    If `root_signing_callback` is provided, the manifest_hash bytes are
    handed to the callback (typically an HSM call or an offline ceremony
    script) which returns a 64-byte Ed25519 signature. CloakLLM runtime
    NEVER holds the root key -- the callback is the trust boundary.

    Args:
        keypair: The signing keypair to publish provenance for.
        deployer_id: Free-form deployer identifier (org name, URN, etc.).
            Required, 1..256 chars.
        valid_from: ISO 8601 UTC. Defaults to current UTC time.
        valid_until: ISO 8601 UTC OR None (open-ended; documented as the
            less-secure default -- compliance-grade deployers SHOULD set
            a value and rotate).
        purpose: Must be "cloakllm-audit-attestation" in v0.8.1. The
            whitelist leaves room for future v2 purposes.
        root_signing_callback: Optional callable that receives the
            manifest_hash bytes and returns a 64-byte raw Ed25519 signature.
            When provided, `root_key_id` is required.
        root_key_id: Identifier of the root key (auditor uses this to
            look up the root public key via deployer's published key
            directory or other out-of-band channel).

    Returns:
        A frozen KeyManifest with deterministic manifest_hash and (when
        a root signer was supplied) root_signature.

    Raises:
        ValueError: deployer_id empty/too long, purpose not whitelisted,
            valid_from/valid_until malformed, root_signing_callback supplied
            without root_key_id, root_signing_callback returns wrong-length
            signature.
    """
    # --- Field validation (AUDIT-3 hardening from day 1) ---
    if not isinstance(deployer_id, str) or not deployer_id:
        raise ValueError("deployer_id must be a non-empty string")
    if len(deployer_id) > _KEY_MANIFEST_DEPLOYER_ID_MAX:
        raise ValueError(
            f"deployer_id must be <= {_KEY_MANIFEST_DEPLOYER_ID_MAX} chars "
            f"(got {len(deployer_id)})"
        )
    if "\x00" in deployer_id:
        raise ValueError("deployer_id must not contain NUL bytes")

    if purpose not in _KEY_MANIFEST_PURPOSE_WHITELIST:
        raise ValueError(
            f"purpose must be one of {sorted(_KEY_MANIFEST_PURPOSE_WHITELIST)}; "
            f"got {purpose!r}"
        )

    if valid_from is None:
        valid_from = datetime.now(timezone.utc).isoformat()
    _validate_iso8601_utc(valid_from, "valid_from")

    if valid_until is not None:
        _validate_iso8601_utc(valid_until, "valid_until")
        if valid_until < valid_from:
            raise ValueError(
                f"valid_until ({valid_until}) must be >= valid_from ({valid_from})"
            )

    if root_signing_callback is not None and not isinstance(root_key_id, str):
        raise ValueError(
            "root_key_id is required when root_signing_callback is provided "
            "(auditors need it to look up the root public key)"
        )
    if root_key_id is not None:
        if not isinstance(root_key_id, str) or not root_key_id:
            raise ValueError("root_key_id must be a non-empty string")
        if len(root_key_id) > _KEY_MANIFEST_ROOT_KEY_ID_MAX:
            raise ValueError(
                f"root_key_id must be <= {_KEY_MANIFEST_ROOT_KEY_ID_MAX} chars"
            )
        if "\x00" in root_key_id:
            raise ValueError("root_key_id must not contain NUL bytes")

    # --- Hash computation ---
    manifest_hash = _compute_manifest_hash(
        key_id=keypair.key_id,
        public_key=keypair.public_key_b64,
        deployer_id=deployer_id,
        valid_from=valid_from,
        valid_until=valid_until,
        purpose=purpose,
        manifest_version=KEY_MANIFEST_SCHEMA_VERSION,
        root_key_id=root_key_id,
    )

    # --- Optional root signature (offline ceremony) ---
    root_signature: Optional[str] = None
    if root_signing_callback is not None:
        sig_bytes = root_signing_callback(manifest_hash.encode("ascii"))
        if not isinstance(sig_bytes, (bytes, bytearray)) or len(sig_bytes) != 64:
            raise ValueError(
                "root_signing_callback must return 64 bytes (raw Ed25519 signature); "
                f"got {type(sig_bytes).__name__} of length "
                f"{len(sig_bytes) if hasattr(sig_bytes, '__len__') else 'unknown'}"
            )
        root_signature = base64.b64encode(bytes(sig_bytes)).decode("ascii")

    return KeyManifest(
        key_id=keypair.key_id,
        public_key=keypair.public_key_b64,
        deployer_id=deployer_id,
        valid_from=valid_from,
        valid_until=valid_until,
        purpose=purpose,
        manifest_version=KEY_MANIFEST_SCHEMA_VERSION,
        manifest_hash=manifest_hash,
        root_signature=root_signature,
        root_key_id=root_key_id,
    )


# ===================================================================
# v0.8.1 KM-2: verify_key_provenance + ProvenanceReport
# ===================================================================
#
# Structured ProvenanceReport (not a bool) so auditors can cite SPECIFIC
# findings. A signed ProvenanceReport JSON output IS the audit deliverable
# for one verified entry. KM-9 aggregates these into the v0.8.0
# compliance_report's attestation.provenance_summary slot.
#
# Strict zero-tolerance timestamps by default (Decision 2 in PLAN_v081.md).
# Auditor-friendly -- no silent NTP fudge factor that could miss a
# backdated-by-30s attack. Callers opt into skew via `clock_skew_seconds=N`.

# Root signature status values (cross-SDK enum)
ROOT_SIG_VALID = "VALID"
ROOT_SIG_INVALID = "INVALID"
ROOT_SIG_NOT_REQUESTED = "NOT_REQUESTED"
ROOT_SIG_UNVERIFIED_NO_KEY = "UNVERIFIED_NO_KEY"

# Provenance status values
PROVENANCE_VERIFIED = "VERIFIED"
PROVENANCE_FAILED = "FAILED"
PROVENANCE_UNVERIFIED = "UNVERIFIED"  # back-compat: manifest=None


@dataclass(frozen=True)
class ProvenanceReport:
    """v0.8.1 structured verification result for a (certificate, manifest) pair.

    Auditors cite individual fields, not a single bool. KM-9 aggregates
    these into compliance_report's attestation.provenance_summary slot.
    """
    overall_valid: bool
    provenance_status: str          # VERIFIED | FAILED | UNVERIFIED
    signature_valid: bool
    key_id_matches: Optional[bool]                # None when manifest=None
    within_validity_window: Optional[bool]        # None when manifest=None
    root_signature_status: str                    # VALID | INVALID | NOT_REQUESTED | UNVERIFIED_NO_KEY
    manifest_hash_consistent: Optional[bool]      # None when manifest=None
    checked_at: str                               # ISO 8601 UTC
    notes: list[str]                              # Human-readable findings

    def to_dict(self) -> dict:
        return {
            "overall_valid": self.overall_valid,
            "provenance_status": self.provenance_status,
            "signature_valid": self.signature_valid,
            "key_id_matches": self.key_id_matches,
            "within_validity_window": self.within_validity_window,
            "root_signature_status": self.root_signature_status,
            "manifest_hash_consistent": self.manifest_hash_consistent,
            "checked_at": self.checked_at,
            "notes": list(self.notes),
        }


def _parse_iso8601_safe(value: Optional[str]) -> Optional[datetime]:
    """Defensive parse: returns None for any non-string or unparseable value.

    AUDIT-3 hardening: a hand-crafted manifest with valid_until=42 (int)
    or valid_until="not a date" must not crash the verifier. Returns None
    to signal "uninterpretable" -- caller decides what that means.
    """
    if not isinstance(value, str) or not value:
        return None
    try:
        return datetime.fromisoformat(value.replace("Z", "+00:00"))
    except (ValueError, TypeError):
        return None


def verify_key_provenance(
    certificate: SanitizationCertificate,
    manifest: Optional[KeyManifest],
    *,
    root_public_key: Optional[bytes] = None,
    now: Optional[str] = None,
    clock_skew_seconds: int = 0,
) -> ProvenanceReport:
    """Verify a certificate's signature AND the key's provenance.

    Runs up to 5 independent checks:
      1. signature_valid: cert.verify(manifest.public_key) succeeds
      2. key_id_matches: cert.key_id == manifest.key_id
      3. within_validity_window: manifest.valid_from - skew <= cert.timestamp <= valid_until + skew
      4. root_signature_valid: when root_public_key + manifest.root_signature present
      5. manifest_hash_consistent: recompute manifest_hash, compare

    Backward compat:
      - manifest=None: only (1) runs against certificate.public_key.
        provenance_status='UNVERIFIED'. Same boolean outcome as the
        v0.6.x cert.verify(pk) API.
      - root_public_key=None and manifest.root_signature=None:
        check (4) reports NOT_REQUESTED (no chain-of-trust claimed)
      - root_public_key=None and manifest.root_signature set:
        check (4) reports UNVERIFIED_NO_KEY (manifest CLAIMS chain-of-trust
        but caller didn't supply the root key to check it)

    Args:
        certificate: The signed SanitizationCertificate to verify.
        manifest: KeyManifest binding the signing key. None -> backward-compat
            mode (signature-only check, provenance_status=UNVERIFIED).
        root_public_key: 32-byte raw Ed25519 public key of the offline root.
            Required to verify manifest.root_signature.
        now: ISO 8601 UTC timestamp for "current time" in the validity check.
            Default: datetime.now(timezone.utc).isoformat().
        clock_skew_seconds: Tolerance (in seconds) added to both ends of
            the validity window. Strict zero by default (Decision 2).
            Set to non-zero only when you understand the security tradeoff.

    Returns:
        ProvenanceReport with per-check booleans + human-readable notes.
        The overall_valid bool is the AND of REQUIRED checks (signature_valid
        + (key_id_matches + within_validity_window + manifest_hash_consistent
        when manifest present) + (root_signature_status==VALID when manifest
        has root_signature AND root_public_key was supplied)).
    """
    notes: list[str] = []
    checked_at = now if now is not None else datetime.now(timezone.utc).isoformat()

    # --- Check 1: signature_valid ---
    # When manifest is provided, verify against manifest.public_key (the
    # auditor's trust anchor). Without manifest, verify against the
    # certificate's embedded public_key (backward-compat).
    if manifest is not None:
        try:
            pk_bytes = base64.b64decode(manifest.public_key)
            signature_valid = certificate.verify(pk_bytes)
        except Exception as e:
            signature_valid = False
            notes.append(f"signature check raised: {type(e).__name__}: {e}")
    else:
        try:
            pk_bytes = base64.b64decode(certificate.public_key) if certificate.public_key else b""
            signature_valid = bool(pk_bytes) and certificate.verify(pk_bytes)
        except Exception as e:
            signature_valid = False
            notes.append(f"signature check raised: {type(e).__name__}: {e}")

    # --- Manifest-absent backward-compat short-circuit ---
    if manifest is None:
        notes.append("manifest=None: signature-only check (UNVERIFIED provenance)")
        return ProvenanceReport(
            overall_valid=signature_valid,
            provenance_status=PROVENANCE_UNVERIFIED,
            signature_valid=signature_valid,
            key_id_matches=None,
            within_validity_window=None,
            root_signature_status=ROOT_SIG_NOT_REQUESTED,
            manifest_hash_consistent=None,
            checked_at=checked_at,
            notes=notes,
        )

    # --- Check 2: key_id_matches ---
    key_id_matches = certificate.key_id == manifest.key_id
    if not key_id_matches:
        notes.append(
            f"key_id mismatch: cert.key_id={certificate.key_id!r} "
            f"!= manifest.key_id={manifest.key_id!r}"
        )

    # --- Check 3: within_validity_window ---
    # Use cert.timestamp (when the cert was signed) against manifest window.
    cert_ts = _parse_iso8601_safe(certificate.timestamp)
    valid_from_ts = _parse_iso8601_safe(manifest.valid_from)
    valid_until_ts = _parse_iso8601_safe(manifest.valid_until)  # None OK

    if cert_ts is None or valid_from_ts is None:
        within_validity_window = False
        notes.append(
            f"cannot compare timestamps: cert.timestamp={certificate.timestamp!r}, "
            f"manifest.valid_from={manifest.valid_from!r}"
        )
    else:
        from datetime import timedelta as _td
        skew = _td(seconds=int(clock_skew_seconds))
        lower = valid_from_ts - skew
        if valid_until_ts is None:
            # Open-ended -- only lower bound enforced.
            within_validity_window = cert_ts >= lower
        else:
            upper = valid_until_ts + skew
            within_validity_window = lower <= cert_ts <= upper
        if not within_validity_window:
            if valid_until_ts is not None and cert_ts > valid_until_ts + skew:
                notes.append(f"key expired: cert.timestamp={certificate.timestamp} > valid_until={manifest.valid_until}")
            elif cert_ts < valid_from_ts - skew:
                notes.append(f"cert before key validity: cert.timestamp={certificate.timestamp} < valid_from={manifest.valid_from}")

    # --- Check 5: manifest_hash_consistent ---
    # (Done before check 4 because check 4 depends on hash being correct.)
    expected_hash = _compute_manifest_hash(
        key_id=manifest.key_id,
        public_key=manifest.public_key,
        deployer_id=manifest.deployer_id,
        valid_from=manifest.valid_from,
        valid_until=manifest.valid_until,
        purpose=manifest.purpose,
        manifest_version=manifest.manifest_version,
        root_key_id=manifest.root_key_id,
    )
    manifest_hash_consistent = expected_hash == manifest.manifest_hash
    if not manifest_hash_consistent:
        notes.append("manifest_hash mismatch: manifest fields have been tampered with")

    # --- Check 4: root_signature_status ---
    if manifest.root_signature is None:
        root_signature_status = ROOT_SIG_NOT_REQUESTED
        notes.append("no root_signature on manifest (self-published, not load-bearing)")
    elif root_public_key is None:
        root_signature_status = ROOT_SIG_UNVERIFIED_NO_KEY
        notes.append(
            "manifest has root_signature but caller did not supply root_public_key "
            f"(root_key_id={manifest.root_key_id!r})"
        )
    else:
        try:
            sig_bytes = base64.b64decode(manifest.root_signature)
            # Root signature signs the manifest_hash (as ASCII bytes -- same
            # form the callback received in derive_key_manifest).
            valid = DeploymentKeyPair.verify(
                root_public_key,
                manifest.manifest_hash.encode("ascii"),
                sig_bytes,
            )
            root_signature_status = ROOT_SIG_VALID if valid else ROOT_SIG_INVALID
            if not valid:
                notes.append(
                    f"root_signature INVALID: claimed signer root_key_id={manifest.root_key_id!r} "
                    "but signature does not verify"
                )
        except Exception as e:
            root_signature_status = ROOT_SIG_INVALID
            notes.append(f"root_signature parse/verify raised: {type(e).__name__}: {e}")

    # --- Compute overall_valid ---
    required_checks = [
        signature_valid,
        key_id_matches,
        within_validity_window,
        manifest_hash_consistent,
    ]
    # Root signature is REQUIRED when claimed (manifest has root_signature)
    # AND the caller supplied root_public_key. NOT_REQUESTED and
    # UNVERIFIED_NO_KEY do not fail overall_valid -- they're just status.
    if manifest.root_signature is not None and root_public_key is not None:
        required_checks.append(root_signature_status == ROOT_SIG_VALID)
    overall_valid = all(required_checks)

    return ProvenanceReport(
        overall_valid=overall_valid,
        provenance_status=PROVENANCE_VERIFIED if overall_valid else PROVENANCE_FAILED,
        signature_valid=signature_valid,
        key_id_matches=key_id_matches,
        within_validity_window=within_validity_window,
        root_signature_status=root_signature_status,
        manifest_hash_consistent=manifest_hash_consistent,
        checked_at=checked_at,
        notes=notes,
    )
