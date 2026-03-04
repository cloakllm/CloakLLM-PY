"""
CloakLLM — AI Compliance Middleware
PII protection, tamper-evident audit logs, and EU AI Act compliance for LLM gateways.

Usage with LiteLLM:
    import cloakllm
    cloakllm.enable()  # That's it. All LiteLLM calls are now cloaked.

Standalone usage:
    from cloakllm import Shield
    shield = Shield()
    sanitized, token_map = shield.sanitize("Send email to john@acme.com about Project Falcon")
    # sanitized: "Send email to [EMAIL_0] about [ORG_0]"
"""

__version__ = "0.1.4"

from cloakllm.shield import Shield
from cloakllm.config import ShieldConfig
from cloakllm.integrations.litellm_middleware import enable, disable, get_shield, is_enabled

__all__ = ["Shield", "ShieldConfig", "enable", "disable", "get_shield", "is_enabled"]
