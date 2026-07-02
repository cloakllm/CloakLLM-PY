"""
CloakLLM -- AI Compliance Middleware
PII protection, tamper-evident audit logs, and EU AI Act compliance for LLM gateways.

Usage with LiteLLM:
    import cloakllm
    cloakllm.enable()  # That's it. All LiteLLM calls are now cloaked.

Usage with OpenAI SDK:
    from cloakllm import enable_openai
    from openai import OpenAI
    client = OpenAI()
    enable_openai(client)  # All chat.completions.create calls are now cloaked.

Standalone usage:
    from cloakllm import Shield
    shield = Shield()
    sanitized, token_map = shield.sanitize("Send email to john@acme.com about Project Falcon")
    # sanitized: "Send email to [EMAIL_0] about [ORG_0]"
"""

__version__ = "0.12.0"

# v0.12.0: LAZY top-level imports (PEP 562). `import cloakllm` no longer eager-
# loads Shield -> detection -> spaCy. This lets the crypto/verify layer
# (attestation, timestamping, compliance_report, token_spec) be imported
# WITHOUT spaCy installed, which is what makes the standalone cloakllm-verifier
# lean. spaCy moved to the `[detection]` extra; NER degrades gracefully without
# it (v0.11.3). Public API is unchanged: `from cloakllm import Shield` etc. still
# work, resolved on first access.
import importlib as _importlib
from typing import TYPE_CHECKING as _TYPE_CHECKING

if _TYPE_CHECKING:
    # Static-analysis mirror of the lazy map below. The package ships py.typed;
    # without this block, module-level __getattr__ makes every top-level name
    # resolve as Any for mypy/pyright (type errors silently swallowed). Zero
    # runtime cost -- only type checkers execute this branch.
    from cloakllm.shield import Shield
    from cloakllm.config import ShieldConfig
    from cloakllm.stream import StreamDesanitizer
    from cloakllm.integrations.litellm_middleware import enable, disable, get_shield, is_enabled
    from cloakllm.integrations.openai_middleware import (
        enable as enable_openai,
        disable as disable_openai,
    )
    from cloakllm.attestation import (
        DeploymentKeyPair, SanitizationCertificate, MerkleTree, derive_entity_hash_key,
        KeyManifest, derive_key_manifest, KEY_MANIFEST_SCHEMA_VERSION,
        ProvenanceReport, verify_key_provenance,
        RevocationEntry, RevocationList, derive_revocation_list, REVOCATION_LIST_SCHEMA_VERSION,
    )
    from cloakllm.context_analyzer import ContextAnalyzer, RiskAssessment
    from cloakllm.backends import DetectorBackend, RegexBackend, NerBackend, LlmBackend
    from cloakllm.key_provider import (
        KeyProvider, LocalKeyProvider, AwsKmsKeyProvider, GcpKmsKeyProvider,
        AzureKeyVaultProvider, HashicorpVaultProvider, build_key_provider,
    )
    from cloakllm.token_spec import (
        validate_token, parse_token, validate_category_name, is_redacted_token,
        BUILTIN_CATEGORIES, SPECIAL_CATEGORY_CATEGORIES, CLOAKLLM_TOKEN_PATTERN, MAX_TOKEN_LENGTH,
    )
    from cloakllm.exceptions import (
        AuditError, AuditChainIntegrityError, AuditSchemaViolation,
        BiasDetectionError, BiasDetectionScopeError, BiasDetectionStateError, BiasDetectionTimeoutError,
    )
    from cloakllm.bias_detection import BiasDetectionSession

_LAZY_GROUPS = {
    "cloakllm.shield": ["Shield"],
    "cloakllm.config": ["ShieldConfig"],
    "cloakllm.stream": ["StreamDesanitizer"],
    "cloakllm.integrations.litellm_middleware": ["enable", "disable", "get_shield", "is_enabled"],
    "cloakllm.attestation": [
        "DeploymentKeyPair", "SanitizationCertificate", "MerkleTree", "derive_entity_hash_key",
        "KeyManifest", "derive_key_manifest", "KEY_MANIFEST_SCHEMA_VERSION",
        "ProvenanceReport", "verify_key_provenance",
        "RevocationEntry", "RevocationList", "derive_revocation_list", "REVOCATION_LIST_SCHEMA_VERSION",
    ],
    "cloakllm.context_analyzer": ["ContextAnalyzer", "RiskAssessment"],
    "cloakllm.backends": ["DetectorBackend", "RegexBackend", "NerBackend", "LlmBackend"],
    "cloakllm.key_provider": [
        "KeyProvider", "LocalKeyProvider", "AwsKmsKeyProvider", "GcpKmsKeyProvider",
        "AzureKeyVaultProvider", "HashicorpVaultProvider", "build_key_provider",
    ],
    "cloakllm.token_spec": [
        "validate_token", "parse_token", "validate_category_name", "is_redacted_token",
        "BUILTIN_CATEGORIES", "SPECIAL_CATEGORY_CATEGORIES", "CLOAKLLM_TOKEN_PATTERN", "MAX_TOKEN_LENGTH",
    ],
    "cloakllm.exceptions": [
        "AuditError", "AuditChainIntegrityError", "AuditSchemaViolation",
        "BiasDetectionError", "BiasDetectionScopeError", "BiasDetectionStateError", "BiasDetectionTimeoutError",
    ],
    "cloakllm.bias_detection": ["BiasDetectionSession"],
}
# name -> (module_path, source_attr)
_LAZY = {name: (mod, name) for mod, names in _LAZY_GROUPS.items() for name in names}
# aliases whose source attribute differs from the public name:
_LAZY["enable_openai"] = ("cloakllm.integrations.openai_middleware", "enable")
_LAZY["disable_openai"] = ("cloakllm.integrations.openai_middleware", "disable")

# Submodules reachable as attributes (`import cloakllm; cloakllm.audit`).
# The eager pre-v0.12.0 __init__ bound these as a side effect of its imports;
# third-party code relies on it, so the lazy layer preserves the behavior.
_LAZY_SUBMODULES = frozenset({
    "shield", "config", "stream", "audit", "attestation", "tokenizer",
    "detector", "token_spec", "timestamping", "compliance_report",
    "exceptions", "backends", "integrations", "bias_detection",
    "context_analyzer", "key_provider", "llm_detector", "locale_patterns",
})


def __getattr__(name):
    if name in _LAZY_SUBMODULES:
        value = _importlib.import_module(f"cloakllm.{name}")
        globals()[name] = value
        return value
    target = _LAZY.get(name)
    if target is None:
        raise AttributeError(f"module 'cloakllm' has no attribute {name!r}")
    module_path, attr = target
    value = getattr(_importlib.import_module(module_path), attr)
    globals()[name] = value  # cache so subsequent access skips __getattr__
    return value


def __dir__():
    return sorted(set(list(globals().keys()) + list(_LAZY.keys()) + list(_LAZY_SUBMODULES)))


__all__ = [
    "Shield",
    "ShieldConfig",
    "StreamDesanitizer",
    "enable",
    "disable",
    "get_shield",
    "is_enabled",
    "enable_openai",
    "disable_openai",
    "DeploymentKeyPair",
    "SanitizationCertificate",
    "MerkleTree",
    "derive_entity_hash_key",
    "KeyManifest",
    "derive_key_manifest",
    "KEY_MANIFEST_SCHEMA_VERSION",
    "ProvenanceReport",
    "verify_key_provenance",
    "RevocationEntry",
    "RevocationList",
    "derive_revocation_list",
    "REVOCATION_LIST_SCHEMA_VERSION",
    "ContextAnalyzer",
    "RiskAssessment",
    "validate_token",
    "parse_token",
    "validate_category_name",
    "is_redacted_token",
    "BUILTIN_CATEGORIES",
    "SPECIAL_CATEGORY_CATEGORIES",
    "CLOAKLLM_TOKEN_PATTERN",
    "MAX_TOKEN_LENGTH",
    "DetectorBackend",
    "RegexBackend",
    "NerBackend",
    "LlmBackend",
    "KeyProvider",
    "LocalKeyProvider",
    "AwsKmsKeyProvider",
    "GcpKmsKeyProvider",
    "AzureKeyVaultProvider",
    "HashicorpVaultProvider",
    "build_key_provider",
    # v0.6.3 G4: typed exceptions
    "AuditError",
    "AuditChainIntegrityError",
    "AuditSchemaViolation",
    # v0.7.0 A4a: BiasDetectionSession (Article 4a)
    "BiasDetectionSession",
    "BiasDetectionError",
    "BiasDetectionScopeError",
    "BiasDetectionStateError",
    "BiasDetectionTimeoutError",
]
