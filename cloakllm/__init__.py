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

__version__ = "0.4.0"

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
]
