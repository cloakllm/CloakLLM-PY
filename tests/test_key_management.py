"""
Tests for v0.6.0 Enterprise Key Management.

Covers:
- LocalKeyProvider exposes the same duck-typed contract as DeploymentKeyPair
- KMS providers raise ImportError with install instructions when SDK missing
- build_key_provider factory rejects unknown providers
- Key rotation event is logged when key_rotation_enabled=True
"""

import builtins
import json
import sys
import tempfile
from pathlib import Path
from unittest import mock

import pytest

from cloakllm import (
    DeploymentKeyPair,
    LocalKeyProvider,
    Shield,
    ShieldConfig,
    build_key_provider,
)


@pytest.fixture
def tmp_log_dir():
    with tempfile.TemporaryDirectory() as d:
        yield Path(d)


# --- LocalKeyProvider --------------------------------------------------------


def test_local_key_provider_duck_typed_contract():
    kp = DeploymentKeyPair.generate()
    provider = LocalKeyProvider(kp)

    assert provider.key_id == kp.key_id
    assert provider.public_key_b64 == kp.public_key_b64
    sig_b64 = provider.sign_b64(b"hello world")
    assert isinstance(sig_b64, str)
    assert len(sig_b64) > 0

    # Same input deterministically yields the same signature (Ed25519 is deterministic)
    sig_b64_again = provider.sign_b64(b"hello world")
    assert sig_b64 == sig_b64_again


def test_local_key_provider_sign_returns_bytes():
    kp = DeploymentKeyPair.generate()
    provider = LocalKeyProvider(kp)
    raw_sig = provider.sign(b"data")
    assert isinstance(raw_sig, bytes)
    assert len(raw_sig) == 64  # Ed25519 signature length


# --- build_key_provider factory ---------------------------------------------


def test_build_key_provider_rejects_unknown():
    with pytest.raises(ValueError, match="Unknown attestation_key_provider"):
        build_key_provider("not_a_provider", "some-key-id")


# --- KMS providers raise ImportError when SDK missing -----------------------


def test_aws_kms_raises_import_error_when_boto3_missing():
    """Simulate boto3 absent and verify the error message guides the user."""
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "boto3":
            raise ImportError("No module named 'boto3'")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=fake_import):
        from cloakllm.key_provider import AwsKmsKeyProvider
        with pytest.raises(ImportError, match="boto3"):
            AwsKmsKeyProvider(key_id="arn:aws:kms:eu-west-1:123:key/abc")


def test_gcp_kms_raises_import_error_when_sdk_missing():
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("google.cloud"):
            raise ImportError(f"No module named '{name}'")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=fake_import):
        from cloakllm.key_provider import GcpKmsKeyProvider
        with pytest.raises(ImportError, match="google-cloud-kms"):
            GcpKmsKeyProvider(key_id="projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1")


def test_azure_keyvault_raises_import_error_when_sdk_missing():
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name.startswith("azure."):
            raise ImportError(f"No module named '{name}'")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=fake_import):
        from cloakllm.key_provider import AzureKeyVaultProvider
        with pytest.raises(ImportError, match="azure"):
            AzureKeyVaultProvider(key_id="https://vault.vault.azure.net/keys/k/v")


def test_hashicorp_vault_raises_import_error_when_sdk_missing():
    real_import = builtins.__import__

    def fake_import(name, *args, **kwargs):
        if name == "hvac":
            raise ImportError("No module named 'hvac'")
        return real_import(name, *args, **kwargs)

    with mock.patch("builtins.__import__", side_effect=fake_import):
        from cloakllm.key_provider import HashicorpVaultProvider
        with pytest.raises(ImportError, match="hvac"):
            HashicorpVaultProvider(key_id="my-transit-key")


# --- B2 partial: KMS providers raise NotImplementedError on use (v0.6.1) ----


def _stub_sdks_for_kms():
    """Provide minimal stub modules so KMS classes can __init__ without real SDKs.

    The whole point of the v0.6.1 disable is that operations raise; we still
    need to construct an instance to test that.
    """
    import sys
    import types

    if "boto3" not in sys.modules:
        boto3_stub = types.ModuleType("boto3")
        boto3_stub.client = lambda *args, **kwargs: object()
        sys.modules["boto3"] = boto3_stub


def test_aws_kms_sign_raises_not_implemented_v061():
    _stub_sdks_for_kms()
    from cloakllm.key_provider import AwsKmsKeyProvider
    p = AwsKmsKeyProvider(key_id="arn:aws:kms:eu-west-1:123:key/abc")
    with pytest.raises(NotImplementedError, match="EXPERIMENTAL"):
        p.sign(b"data")


def test_aws_kms_public_key_raises_not_implemented_v061():
    _stub_sdks_for_kms()
    from cloakllm.key_provider import AwsKmsKeyProvider
    p = AwsKmsKeyProvider(key_id="arn:aws:kms:eu-west-1:123:key/abc")
    with pytest.raises(NotImplementedError, match="v0.7"):
        _ = p.public_key_b64


def test_local_key_provider_still_works_after_kms_disable():
    """B2 disabling KMS providers must NOT affect LocalKeyProvider."""
    kp = DeploymentKeyPair.generate()
    provider = LocalKeyProvider(kp)
    sig = provider.sign(b"data")
    assert isinstance(sig, bytes)
    assert len(sig) == 64
    assert isinstance(provider.public_key_b64, str)


# --- Key rotation event ------------------------------------------------------


def test_key_rotation_event_logged_when_enabled(tmp_log_dir):
    """When key_rotation_enabled=True and a keypair is loaded, init writes
    a key_rotation_event entry containing no PII."""
    kp = DeploymentKeyPair.generate()
    cfg = ShieldConfig(
        log_dir=tmp_log_dir,
        attestation_key=kp,
        key_rotation_enabled=True,
        audit_enabled=True,
    )
    Shield(cfg)

    log_files = list(tmp_log_dir.glob("audit_*.jsonl"))
    assert len(log_files) == 1
    entries = [
        json.loads(line) for line in log_files[0].read_text().splitlines() if line
    ]
    rotation_entries = [e for e in entries if e["event_type"] == "key_rotation_event"]
    assert len(rotation_entries) == 1
    e = rotation_entries[0]
    assert e["key_id"] == kp.key_id
    assert e["metadata"]["key_provider"] == "local"
    # No PII in rotation events
    assert e.get("entity_count", 0) == 0
    assert e.get("entity_details") == []


def test_key_rotation_event_not_logged_when_disabled(tmp_log_dir):
    kp = DeploymentKeyPair.generate()
    cfg = ShieldConfig(
        log_dir=tmp_log_dir,
        attestation_key=kp,
        key_rotation_enabled=False,
        audit_enabled=True,
    )
    Shield(cfg)

    log_files = list(tmp_log_dir.glob("audit_*.jsonl"))
    if log_files:
        entries = [
            json.loads(line) for line in log_files[0].read_text().splitlines() if line
        ]
        assert not any(e["event_type"] == "key_rotation_event" for e in entries)
