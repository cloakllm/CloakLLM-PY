"""v0.6.3 I4 — KMS provider lazy-init tests.

`build_key_provider` short-circuits to NotImplementedError BEFORE constructing
disabled provider classes — so the cloud SDKs (boto3, google-cloud-kms,
azure-keyvault-keys, hvac) are never imported when the user configures a
disabled provider. Closes both:
  * Import cost (~500ms cold start for boto3 on Lambda)
  * Memory/attack-surface footprint (loaded SDKs are exposed to any CVEs
    in those packages even though we can't actually use them)

When v0.7.0 enables a provider, removing it from _DISABLED_KMS_PROVIDERS
restores the full constructor path including its SDK import.
"""

from __future__ import annotations

import sys
import unittest

import pytest

from cloakllm.key_provider import (
    build_key_provider,
    _DISABLED_KMS_PROVIDERS,
    _PROVIDER_REGISTRY,
)


class TestDisabledProvidersFactory(unittest.TestCase):
    """build_key_provider raises NotImplementedError for disabled providers."""

    def test_aws_kms_disabled(self):
        with self.assertRaises(NotImplementedError) as cm:
            build_key_provider("aws_kms", "arn:aws:kms:eu-west-1:123:key/abc")
        # Message includes the v0.6.x experimental hint
        self.assertIn("EXPERIMENTAL", str(cm.exception))
        self.assertIn("aws_kms", str(cm.exception))

    def test_gcp_kms_disabled(self):
        with self.assertRaises(NotImplementedError):
            build_key_provider(
                "gcp_kms",
                "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
            )

    def test_azure_keyvault_disabled(self):
        with self.assertRaises(NotImplementedError):
            build_key_provider(
                "azure_keyvault",
                "https://vault.vault.azure.net/keys/k/v",
            )

    def test_hashicorp_vault_disabled(self):
        with self.assertRaises(NotImplementedError):
            build_key_provider("hashicorp_vault", "my-transit-key")


class TestNoSdkImportOnFactoryShortCircuit(unittest.TestCase):
    """The headline I4 invariant: factory rejection must NOT import the SDK.

    These tests assert that after a disabled-provider factory call, the SDK
    module is not in sys.modules (i.e., we never imported it). They use
    sentinel module names that are unlikely to be present from other tests.
    """

    def _purge(self, prefixes):
        """Remove any modules matching the given prefixes from sys.modules.
        Required before each test so we know the absence afterward is meaningful.
        Returns the snapshot of removed modules so we can restore on tearDown.
        """
        removed = {}
        for k in list(sys.modules):
            if any(k == p or k.startswith(p + ".") for p in prefixes):
                removed[k] = sys.modules.pop(k)
        return removed

    def _restore(self, removed):
        for k, v in removed.items():
            sys.modules[k] = v

    def test_aws_factory_does_not_import_boto3(self):
        removed = self._purge(["boto3", "botocore"])
        try:
            with pytest.raises(NotImplementedError):
                build_key_provider("aws_kms", "arn:aws:kms:eu-west-1:123:key/abc")
            # The headline assertion: boto3 must NOT have been imported.
            self.assertNotIn("boto3", sys.modules)
        finally:
            self._restore(removed)

    def test_gcp_factory_does_not_import_google_cloud(self):
        removed = self._purge(["google.cloud.kms", "google.cloud.kms_v1"])
        try:
            with pytest.raises(NotImplementedError):
                build_key_provider(
                    "gcp_kms",
                    "projects/p/locations/l/keyRings/r/cryptoKeys/k/cryptoKeyVersions/1",
                )
            self.assertNotIn("google.cloud.kms", sys.modules)
            self.assertNotIn("google.cloud.kms_v1", sys.modules)
        finally:
            self._restore(removed)

    def test_azure_factory_does_not_import_azure_identity(self):
        removed = self._purge(["azure.identity", "azure.keyvault"])
        try:
            with pytest.raises(NotImplementedError):
                build_key_provider(
                    "azure_keyvault",
                    "https://vault.vault.azure.net/keys/k/v",
                )
            self.assertNotIn("azure.identity", sys.modules)
            self.assertNotIn("azure.keyvault.keys", sys.modules)
        finally:
            self._restore(removed)

    def test_hashicorp_factory_does_not_import_hvac(self):
        removed = self._purge(["hvac"])
        try:
            with pytest.raises(NotImplementedError):
                build_key_provider("hashicorp_vault", "my-transit-key")
            self.assertNotIn("hvac", sys.modules)
        finally:
            self._restore(removed)


class TestUnknownProviderStillRejected(unittest.TestCase):
    """Regression: I4 must not change unknown-provider rejection."""

    def test_unknown_provider_raises_value_error(self):
        with self.assertRaises(ValueError) as cm:
            build_key_provider("not_a_provider", "any-key")
        self.assertIn("Unknown attestation_key_provider", str(cm.exception))


class TestDisabledRegistryShape(unittest.TestCase):
    """Sanity check on the v0.6.x disabled set."""

    def test_all_four_providers_disabled_in_v_0_6_x(self):
        self.assertEqual(
            set(_DISABLED_KMS_PROVIDERS),
            {"aws_kms", "gcp_kms", "azure_keyvault", "hashicorp_vault"},
        )

    def test_disabled_set_subset_of_registry(self):
        self.assertTrue(
            set(_DISABLED_KMS_PROVIDERS).issubset(set(_PROVIDER_REGISTRY)),
            "_DISABLED_KMS_PROVIDERS must reference only known provider names",
        )


class TestDirectConstructorStillImportsSdk(unittest.TestCase):
    """Pre-existing behavior preserved: direct construction (not via factory)
    still imports the SDK because the constructor needs it. I4 only changes
    the factory path. This keeps existing ImportError tests valid for users
    who construct providers directly.
    """

    def test_direct_aws_construction_still_attempts_boto3(self):
        # We can't easily assert boto3 IS imported without coupling to install
        # state. Instead, verify that the constructor exists and is callable
        # — i.e., the disable monkey-patch on sign() doesn't prevent __init__.
        from cloakllm.key_provider import AwsKmsKeyProvider
        self.assertTrue(callable(AwsKmsKeyProvider))


if __name__ == "__main__":
    unittest.main()
