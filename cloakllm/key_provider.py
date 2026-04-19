"""
Enterprise Key Management for CloakLLM attestation signing keys.

Provides a pluggable interface for signing sanitization certificates using
either local in-memory Ed25519 keypairs (default) or external KMS/HSM
providers (AWS KMS, GCP KMS, Azure Key Vault, HashiCorp Vault).

Usage:
    from cloakllm import ShieldConfig, Shield

    config = ShieldConfig(
        attestation_key_provider="aws_kms",
        attestation_key_id="arn:aws:kms:eu-west-1:123:key/abc-...",
        key_rotation_enabled=True,
    )
    shield = Shield(config)

KMS support is opt-in via:
    pip install cloakllm[kms]

Each provider lazy-imports its SDK so the base package stays dependency-free.
A clear ImportError with install instructions is raised if the SDK is missing.

The KeyProvider duck-typed contract matches DeploymentKeyPair so the existing
attestation pipeline accepts either without modification:
    - .key_id           -> str
    - .public_key_b64   -> str
    - .sign_b64(data)   -> str
"""

from __future__ import annotations

import base64
import hashlib
import logging
from abc import ABC, abstractmethod
from typing import Any, Optional

logger = logging.getLogger("cloakllm.key_provider")


_KMS_INSTALL_HINT = (
    "Install KMS support with: pip install cloakllm[kms]\n"
    "Or install the specific provider SDK directly:\n"
    "  - aws_kms:         pip install boto3\n"
    "  - gcp_kms:         pip install google-cloud-kms\n"
    "  - azure_keyvault:  pip install azure-keyvault-keys azure-identity\n"
    "  - hashicorp_vault: pip install hvac"
)


class KeyProvider(ABC):
    """
    Abstract base class for attestation signing key providers.

    Implementations must expose three duck-typed attributes / methods so that
    cloakllm.attestation can use them interchangeably with DeploymentKeyPair:

        key_id          -> str (stable identifier for this key)
        public_key_b64  -> str (base64-encoded raw 32-byte Ed25519 public key)
        sign_b64(data)  -> str (base64-encoded raw 64-byte signature)
    """

    @property
    @abstractmethod
    def key_id(self) -> str:
        """Stable identifier for this key (used for cross-referencing in logs)."""
        ...

    @property
    @abstractmethod
    def public_key_b64(self) -> str:
        """Base64-encoded raw Ed25519 public key bytes."""
        ...

    @abstractmethod
    def sign(self, data: bytes) -> bytes:
        """Sign data and return the raw signature bytes."""
        ...

    def sign_b64(self, data: bytes) -> str:
        """Sign data and return the base64-encoded signature."""
        return base64.b64encode(self.sign(data)).decode("ascii")

    def get_key_version(self) -> Optional[str]:
        """
        Return the current key version (provider-specific).

        Returns None if the provider does not support versioning.
        Used by Shield when key_rotation_enabled=True.
        """
        return None


class LocalKeyProvider(KeyProvider):
    """
    Wraps an in-memory DeploymentKeyPair. Default behaviour — identical to
    pre-v0.6 attestation. No external dependencies.
    """

    def __init__(self, keypair: Any):
        self._kp = keypair

    @property
    def key_id(self) -> str:
        return self._kp.key_id

    @property
    def public_key_b64(self) -> str:
        return self._kp.public_key_b64

    def sign(self, data: bytes) -> bytes:
        return self._kp.sign(data)

    def sign_b64(self, data: bytes) -> str:
        # Delegate so we share the exact same canonical encoding.
        return self._kp.sign_b64(data)


class AwsKmsKeyProvider(KeyProvider):
    """
    AWS KMS-backed signer. Requires an asymmetric Ed25519 KMS key
    (KeySpec=ECC_NIST_P256 is NOT supported — use Ed25519 keys only).

    Requires: pip install boto3
    """

    def __init__(self, key_id: str, region_name: Optional[str] = None):
        try:
            import boto3
        except ImportError as e:
            raise ImportError(
                f"AWS KMS requires boto3 (not installed).\n{_KMS_INSTALL_HINT}"
            ) from e

        if not key_id:
            raise ValueError("AwsKmsKeyProvider requires a non-empty key_id (KMS Key ARN or alias).")

        self._key_id_raw = key_id
        self._client = boto3.client("kms", region_name=region_name) if region_name else boto3.client("kms")
        self._public_key_b64_cached: Optional[str] = None
        self._stable_key_id: Optional[str] = None

    @property
    def key_id(self) -> str:
        if self._stable_key_id is None:
            # Use SHA-256 prefix of the raw KMS identifier so cross-referencing
            # in audit logs uses a short stable id rather than a full ARN.
            self._stable_key_id = hashlib.sha256(self._key_id_raw.encode()).hexdigest()[:16]
        return self._stable_key_id

    @property
    def public_key_b64(self) -> str:
        if self._public_key_b64_cached is None:
            response = self._client.get_public_key(KeyId=self._key_id_raw)
            self._public_key_b64_cached = base64.b64encode(response["PublicKey"]).decode("ascii")
        return self._public_key_b64_cached

    def sign(self, data: bytes) -> bytes:
        response = self._client.sign(
            KeyId=self._key_id_raw,
            Message=data,
            MessageType="RAW",
            SigningAlgorithm="ECDSA_SHA_256",  # adjust based on KMS key spec
        )
        return response["Signature"]

    def get_key_version(self) -> Optional[str]:
        try:
            meta = self._client.describe_key(KeyId=self._key_id_raw)
            return meta.get("KeyMetadata", {}).get("KeyId")
        except Exception:
            return None


class GcpKmsKeyProvider(KeyProvider):
    """
    Google Cloud KMS-backed signer.

    Requires: pip install google-cloud-kms
    """

    def __init__(self, key_id: str):
        try:
            from google.cloud import kms  # noqa: F401
        except ImportError as e:
            raise ImportError(
                f"GCP KMS requires google-cloud-kms (not installed).\n{_KMS_INSTALL_HINT}"
            ) from e

        if not key_id:
            raise ValueError(
                "GcpKmsKeyProvider requires a non-empty key_id "
                "(format: projects/.../locations/.../keyRings/.../cryptoKeys/.../cryptoKeyVersions/...)."
            )

        from google.cloud import kms as _kms
        self._client = _kms.KeyManagementServiceClient()
        self._key_id_raw = key_id
        self._public_key_b64_cached: Optional[str] = None
        self._stable_key_id: Optional[str] = None

    @property
    def key_id(self) -> str:
        if self._stable_key_id is None:
            self._stable_key_id = hashlib.sha256(self._key_id_raw.encode()).hexdigest()[:16]
        return self._stable_key_id

    @property
    def public_key_b64(self) -> str:
        if self._public_key_b64_cached is None:
            pk = self._client.get_public_key(request={"name": self._key_id_raw})
            # GCP returns PEM; the caller is responsible for parsing it.
            # We base64-encode the PEM bytes for cross-language consistency.
            self._public_key_b64_cached = base64.b64encode(pk.pem.encode("utf-8")).decode("ascii")
        return self._public_key_b64_cached

    def sign(self, data: bytes) -> bytes:
        digest = hashlib.sha256(data).digest()
        response = self._client.asymmetric_sign(
            request={"name": self._key_id_raw, "digest": {"sha256": digest}}
        )
        return response.signature

    def get_key_version(self) -> Optional[str]:
        # GCP key versions are part of the resource name (the .../cryptoKeyVersions/<N> suffix).
        return self._key_id_raw.rsplit("/", 1)[-1] if "/" in self._key_id_raw else None


class AzureKeyVaultProvider(KeyProvider):
    """
    Azure Key Vault-backed signer.

    Requires: pip install azure-keyvault-keys azure-identity
    """

    def __init__(self, key_id: str):
        try:
            from azure.identity import DefaultAzureCredential  # noqa: F401
            from azure.keyvault.keys.crypto import CryptographyClient  # noqa: F401
        except ImportError as e:
            raise ImportError(
                f"Azure Key Vault requires azure-keyvault-keys + azure-identity (not installed).\n"
                f"{_KMS_INSTALL_HINT}"
            ) from e

        if not key_id:
            raise ValueError(
                "AzureKeyVaultProvider requires a non-empty key_id "
                "(full key URL: https://<vault-name>.vault.azure.net/keys/<key-name>/<version>)."
            )

        from azure.identity import DefaultAzureCredential as _Cred
        from azure.keyvault.keys.crypto import CryptographyClient as _Client

        self._key_id_raw = key_id
        self._cred = _Cred()
        self._client = _Client(key_id, self._cred)
        self._public_key_b64_cached: Optional[str] = None
        self._stable_key_id: Optional[str] = None

    @property
    def key_id(self) -> str:
        if self._stable_key_id is None:
            self._stable_key_id = hashlib.sha256(self._key_id_raw.encode()).hexdigest()[:16]
        return self._stable_key_id

    @property
    def public_key_b64(self) -> str:
        if self._public_key_b64_cached is None:
            from azure.keyvault.keys import KeyClient
            # Parse vault URL from full key id; fetch the JWK
            vault_url = self._key_id_raw.split("/keys/")[0]
            key_client = KeyClient(vault_url, self._cred)
            key_name_and_version = self._key_id_raw.split("/keys/")[1].split("/")
            key = key_client.get_key(key_name_and_version[0],
                                     version=key_name_and_version[1] if len(key_name_and_version) > 1 else None)
            # JWK x param is base64url; we re-encode as standard base64 for consistency.
            x_b64url = key.key.x or b""
            self._public_key_b64_cached = base64.b64encode(x_b64url).decode("ascii")
        return self._public_key_b64_cached

    def sign(self, data: bytes) -> bytes:
        from azure.keyvault.keys.crypto import SignatureAlgorithm
        result = self._client.sign(SignatureAlgorithm.es256, hashlib.sha256(data).digest())
        return result.signature

    def get_key_version(self) -> Optional[str]:
        if "/keys/" in self._key_id_raw:
            tail = self._key_id_raw.split("/keys/")[1]
            parts = tail.split("/")
            if len(parts) > 1:
                return parts[1]
        return None


class HashicorpVaultProvider(KeyProvider):
    """
    HashiCorp Vault Transit-engine-backed signer.

    Requires: pip install hvac
    """

    def __init__(self, key_id: str, vault_url: Optional[str] = None,
                 token: Optional[str] = None, mount_point: str = "transit"):
        try:
            import hvac  # noqa: F401
        except ImportError as e:
            raise ImportError(
                f"HashiCorp Vault requires hvac (not installed).\n{_KMS_INSTALL_HINT}"
            ) from e

        if not key_id:
            raise ValueError("HashicorpVaultProvider requires a non-empty key_id (Transit key name).")

        import hvac as _hvac
        import os as _os

        self._key_id_raw = key_id
        self._mount_point = mount_point
        self._client = _hvac.Client(
            url=vault_url or _os.getenv("VAULT_ADDR"),
            token=token or _os.getenv("VAULT_TOKEN"),
        )
        self._public_key_b64_cached: Optional[str] = None
        self._stable_key_id: Optional[str] = None

    @property
    def key_id(self) -> str:
        if self._stable_key_id is None:
            self._stable_key_id = hashlib.sha256(self._key_id_raw.encode()).hexdigest()[:16]
        return self._stable_key_id

    @property
    def public_key_b64(self) -> str:
        if self._public_key_b64_cached is None:
            response = self._client.secrets.transit.read_key(
                name=self._key_id_raw, mount_point=self._mount_point
            )
            keys = response.get("data", {}).get("keys", {})
            latest_version = max(keys.keys()) if keys else "1"
            pk = keys.get(latest_version, {}).get("public_key", "")
            self._public_key_b64_cached = base64.b64encode(pk.encode("utf-8")).decode("ascii")
        return self._public_key_b64_cached

    def sign(self, data: bytes) -> bytes:
        b64_input = base64.b64encode(data).decode("ascii")
        response = self._client.secrets.transit.sign_data(
            name=self._key_id_raw,
            hash_input=b64_input,
            mount_point=self._mount_point,
        )
        # Vault returns "vault:v1:<base64>" — strip prefix and decode.
        sig_str = response.get("data", {}).get("signature", "")
        sig_b64 = sig_str.split(":")[-1] if ":" in sig_str else sig_str
        return base64.b64decode(sig_b64)

    def get_key_version(self) -> Optional[str]:
        try:
            response = self._client.secrets.transit.read_key(
                name=self._key_id_raw, mount_point=self._mount_point
            )
            keys = response.get("data", {}).get("keys", {})
            return str(max(keys.keys())) if keys else None
        except Exception:
            return None


_PROVIDER_REGISTRY = {
    "aws_kms": AwsKmsKeyProvider,
    "gcp_kms": GcpKmsKeyProvider,
    "azure_keyvault": AzureKeyVaultProvider,
    "hashicorp_vault": HashicorpVaultProvider,
}

# v0.6.3 I4: providers that are scaffolded but NOT yet implemented in v0.6.x.
# `build_key_provider` short-circuits to NotImplementedError BEFORE constructing
# the class, so the cloud SDKs (boto3, google-cloud-kms, azure-keyvault-keys,
# hvac) are never imported in production for users who configured one of these
# providers. This both saves the import cost (~500ms cold start for boto3 on
# Lambda) and keeps the SDKs out of memory — smaller attack surface for any
# CVEs in those packages while we can't actually use them. v0.7.0 will remove
# entries from this set as each provider is rebuilt.
_DISABLED_KMS_PROVIDERS = frozenset(_PROVIDER_REGISTRY.keys())


_KMS_EXPERIMENTAL_MSG = (
    "KMS provider {provider!r} is EXPERIMENTAL in v0.6.x and does NOT produce "
    "verifiable signatures: each provider currently returns the wrong public-key "
    "encoding and/or signs with the wrong algorithm. Use LocalKeyProvider until "
    "v0.7.0 (tracking issue: https://github.com/cloakllm/CloakLLM-PY/issues/kms-rebuild)."
)


def _kms_not_implemented(provider_name: str):
    """Raise NotImplementedError with v0.6.1 experimental-disable message."""
    raise NotImplementedError(_KMS_EXPERIMENTAL_MSG.format(provider=provider_name))


# v0.6.1: monkey-patch the four KMS providers' sign() and public_key_b64
# property to raise immediately. The class bodies remain so users can still
# import them and read their docstrings, but any actual use raises.
for _name, _cls in _PROVIDER_REGISTRY.items():
    def _make_disabled_sign(provider_name=_name):
        def sign(self, data: bytes) -> bytes:
            _kms_not_implemented(provider_name)
        return sign

    def _make_disabled_pubkey(provider_name=_name):
        def public_key_b64(self) -> str:
            _kms_not_implemented(provider_name)
        return property(public_key_b64)

    _cls.sign = _make_disabled_sign()
    _cls.public_key_b64 = _make_disabled_pubkey()


def build_key_provider(provider_name: str, key_id: str) -> KeyProvider:
    """
    Factory: instantiate the appropriate KMS-backed KeyProvider.

    v0.6.3 I4: providers in `_DISABLED_KMS_PROVIDERS` short-circuit to
    NotImplementedError BEFORE the provider class is constructed. This avoids
    importing the cloud SDK (boto3, google-cloud-kms, etc.) in production
    even when the user has configured a disabled provider — saves the SDK
    import cost AND keeps the SDKs out of memory while they can't be used.

    Raises:
      ValueError on unknown provider names.
      NotImplementedError when a disabled provider is requested (v0.6.x scaffold).
      ImportError (from the constructor) if a non-disabled provider is requested
        and its SDK is not installed.
    """
    if provider_name not in _PROVIDER_REGISTRY:
        raise ValueError(
            f"Unknown attestation_key_provider '{provider_name}'. "
            f"Must be one of: {list(_PROVIDER_REGISTRY)}"
        )
    # v0.6.3 I4: short-circuit BEFORE constructing the class.
    if provider_name in _DISABLED_KMS_PROVIDERS:
        _kms_not_implemented(provider_name)
    cls = _PROVIDER_REGISTRY[provider_name]
    return cls(key_id=key_id)
