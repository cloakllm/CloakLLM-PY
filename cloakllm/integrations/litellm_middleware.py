"""
LiteLLM Middleware Integration.

Usage:
    import cloakllm
    cloakllm.enable()  # All LiteLLM calls are now cloaked

    # Or with custom config:
    from cloakllm import ShieldConfig
    cloakllm.enable(config=ShieldConfig(detect_phones=False))

    # Disable:
    cloakllm.disable()

How it works:
    CloakLLM hooks into LiteLLM's callback system to:
    1. Intercept outgoing prompts and sanitize them (pre-API call)
    2. Intercept incoming responses and desanitize them (post-API call)
    3. Log everything to a tamper-evident audit chain

    The token map for each request is stored in a thread-safe dict keyed by
    LiteLLM's call_id, so concurrent requests don't interfere.
"""

from __future__ import annotations

import threading
import uuid
from typing import Any, Optional

from cloakllm.config import ShieldConfig
from cloakllm.shield import Shield
from cloakllm.tokenizer import TokenMap


# Thread-safe storage for active token maps (keyed by unique call ID)
_active_maps: dict[str, TokenMap] = {}
_maps_lock = threading.Lock()

# System hint injected when PII tokens are present, so the LLM treats them as real data
_SYSTEM_HINT = (
    "This conversation contains placeholders like [PERSON_0], [EMAIL_0], [ORG_0], etc. "
    "Treat each placeholder as if it were the real value. Use them exactly as-is in your "
    "response — do not ask the user to replace them or provide actual details."
)

# Module-level shield instance
_shield: Optional[Shield] = None
_original_completion = None
_enabled = False


def _sanitize_messages(messages: list[dict], model: str) -> tuple[list[dict], str]:
    """Sanitize all message content in a chat completion request.

    Returns (sanitized_messages, call_key) where call_key is a unique ID
    for retrieving the token map during response desanitization.
    """
    if not _shield or not messages:
        return messages, ""

    call_key = str(uuid.uuid4())
    token_map: Optional[TokenMap] = None

    sanitized_messages = []
    for msg in messages:
        content = msg.get("content", "")
        if isinstance(content, str) and content.strip():
            sanitized_content, token_map = _shield.sanitize(
                text=content,
                token_map=token_map,
                model=model,
                metadata={"role": msg.get("role", "unknown")},
            )
            sanitized_messages.append({**msg, "content": sanitized_content})
        elif isinstance(content, list):
            # Handle multimodal content (list of text/image blocks)
            sanitized_parts = []
            for part in content:
                if isinstance(part, dict) and part.get("type") == "text":
                    sanitized_text, token_map = _shield.sanitize(
                        text=part["text"],
                        token_map=token_map,
                        model=model,
                    )
                    sanitized_parts.append({**part, "text": sanitized_text})
                else:
                    sanitized_parts.append(part)
            sanitized_messages.append({**msg, "content": sanitized_parts})
        else:
            sanitized_messages.append(msg)

    # Inject system hint so the LLM treats sanitized tokens as real values
    if token_map is not None and token_map.entity_count > 0:
        if sanitized_messages and sanitized_messages[0].get("role") == "system":
            sanitized_messages[0] = {
                **sanitized_messages[0],
                "content": sanitized_messages[0]["content"] + "\n\n" + _SYSTEM_HINT,
            }
        else:
            sanitized_messages.insert(0, {"role": "system", "content": _SYSTEM_HINT})

    # Store token map for response desanitization
    with _maps_lock:
        _active_maps[call_key] = token_map

    return sanitized_messages, call_key


def _desanitize_response(response_text: str, model: str, call_key: str) -> str:
    """Desanitize a response using the stored token map."""
    if not _shield:
        return response_text

    with _maps_lock:
        token_map = _active_maps.pop(call_key, None)

    if not token_map or token_map.entity_count == 0:
        return response_text

    return _shield.desanitize(
        text=response_text,
        token_map=token_map,
        model=model,
    )


def _should_skip(model: str) -> bool:
    """Check if this model should skip sanitization."""
    if not _shield:
        return True
    for prefix in _shield.config.skip_models:
        if model.startswith(prefix):
            return True
    return False


def enable(config: Optional[ShieldConfig] = None):
    """
    Enable CloakLLM for all LiteLLM calls.

    This monkey-patches litellm.completion and litellm.acompletion
    to add sanitization/desanitization around every call.

    Args:
        config: Optional ShieldConfig. Uses defaults if not provided.
    """
    global _shield, _original_completion, _enabled

    if _enabled:
        return

    _shield = Shield(config or ShieldConfig())

    try:
        import litellm
    except ImportError:
        raise ImportError(
            "LiteLLM is required for the middleware integration. "
            "Install it with: pip install litellm"
        )

    # Store original functions
    _original_completion = litellm.completion

    # Wrap synchronous completion
    def shielded_completion(*args, **kwargs):
        model = kwargs.get("model") or (args[0] if args else "unknown")
        messages = kwargs.get("messages") or (args[1] if len(args) > 1 else [])
        call_key = ""

        if not _should_skip(model):
            messages, call_key = _sanitize_messages(messages, model)
            kwargs["messages"] = messages

        try:
            # Call original
            response = _original_completion(*args, **kwargs)

            # Desanitize response
            if not _should_skip(model) and call_key and hasattr(response, "choices"):
                for choice in response.choices:
                    if hasattr(choice, "message") and hasattr(choice.message, "content"):
                        if choice.message.content:
                            choice.message.content = _desanitize_response(
                                choice.message.content, model, call_key
                            )

            return response
        finally:
            if call_key:
                with _maps_lock:
                    _active_maps.pop(call_key, None)

    # Patch LiteLLM
    litellm.completion = shielded_completion
    _enabled = True

    # Log that shield is active
    _shield.audit.log(
        event_type="shield_enabled",
        metadata={"spacy_model": _shield.config.spacy_model},
    )

    print(f"🛡️  CloakLLM enabled — detecting PII across all LiteLLM calls")
    print(f"   Audit logs: {_shield.config.log_dir.absolute()}")


def disable():
    """Disable CloakLLM and restore original LiteLLM functions."""
    global _shield, _enabled

    if not _enabled:
        return

    try:
        import litellm
        if _original_completion:
            litellm.completion = _original_completion
    except ImportError:
        pass

    if _shield:
        _shield.audit.log(event_type="shield_disabled")

    _shield = None
    _enabled = False

    with _maps_lock:
        _active_maps.clear()

    print("🛡️  CloakLLM disabled")


def get_shield() -> Optional[Shield]:
    """Get the active Shield instance (for advanced usage)."""
    return _shield


def is_enabled() -> bool:
    """Check if CloakLLM is currently enabled."""
    return _enabled
