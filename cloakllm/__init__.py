"""
CloakLLM — AI Compliance Middleware
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

__version__ = "0.6.4"

from cloakllm.shield import Shield
from cloakllm.config import ShieldConfig
from cloakllm.stream import StreamDesanitizer
from cloakllm.integrations.litellm_middleware import enable, disable, get_shield, is_enabled
from cloakllm.integrations.openai_middleware import (
    enable as enable_openai,
    disable as disable_openai,
)
from cloakllm.attestation import (
    DeploymentKeyPair,
    SanitizationCertificate,
    MerkleTree,
    derive_entity_hash_key,
)
from cloakllm.context_analyzer import ContextAnalyzer, RiskAssessment
from cloakllm.backends import DetectorBackend, RegexBackend, NerBackend, LlmBackend
from cloakllm.key_provider import (
    KeyProvider,
    LocalKeyProvider,
    AwsKmsKeyProvider,
    GcpKmsKeyProvider,
    AzureKeyVaultProvider,
    HashicorpVaultProvider,
    build_key_provider,
)
from cloakllm.token_spec import (
    validate_token,
    parse_token,
    validate_category_name,
    is_redacted_token,
    BUILTIN_CATEGORIES,
    CLOAKLLM_TOKEN_PATTERN,
    MAX_TOKEN_LENGTH,
)
from cloakllm.exceptions import (
    AuditError,
    AuditChainIntegrityError,
    AuditSchemaViolation,
)

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
    "ContextAnalyzer",
    "RiskAssessment",
    "validate_token",
    "parse_token",
    "validate_category_name",
    "is_redacted_token",
    "BUILTIN_CATEGORIES",
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
]
