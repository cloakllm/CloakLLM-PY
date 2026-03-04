"""
OpenAI SDK Middleware Integration.

Usage:
    from cloakllm import enable_openai

    from openai import OpenAI
    client = OpenAI()
    enable_openai(client)  # All chat.completions.create calls are now cloaked

    # Or with custom config:
    from cloakllm import ShieldConfig
    enable_openai(client, config=ShieldConfig(detect_phones=False))

    # Disable:
    from cloakllm import disable_openai
    disable_openai(client)

How it works:
    CloakLLM monkey-patches client.chat.completions.create to:
    1. Intercept outgoing prompts and sanitize them (pre-API call)
    2. Intercept incoming responses and desanitize them (post-API call)
    3. Log everything to a tamper-evident audit chain

    Supports sync, async, and streaming calls. Each client is patched
    independently — multiple clients can be enabled/disabled separately.
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

# System hint injected when PII tokens are present
_SYSTEM_HINT = (
    "This conversation contains placeholders like [PERSON_0], [EMAIL_0], [ORG_0], etc. "
    "Treat each placeholder as if it were the real value. Use them exactly as-is in your "
    "response — do not ask the user to replace them or provide actual details."
)

# Module-level shield instance (shared across all clients)
_shield: Optional[Shield] = None

# Track patched clients: client id -> original create function
_original_creates: dict[int, Any] = {}
_original_acreates: dict[int, Any] = {}


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


def enable(client: Any, config: Optional[ShieldConfig] = None):
    """
    Enable CloakLLM for an OpenAI client instance.

    Monkey-patches client.chat.completions.create to add
    sanitization/desanitization around every call. Supports sync,
    async, and streaming calls.

    Args:
        client: An OpenAI client instance (OpenAI or AsyncOpenAI).
        config: Optional ShieldConfig. Uses defaults if not provided.
    """
    global _shield

    if not hasattr(client, "chat") or not hasattr(client.chat, "completions"):
        raise TypeError(
            "CloakLLM: Expected an OpenAI client with chat.completions.create. "
            "Usage: enable_openai(OpenAI())"
        )

    client_id = id(client)
    if client_id in _original_creates:
        return  # Already patched

    if not _shield:
        _shield = Shield(config or ShieldConfig())

    completions = client.chat.completions
    original_create = completions.create

    # Detect if this is an async client
    is_async = _is_async_client(client)

    if is_async:
        _original_acreates[client_id] = original_create

        async def shielded_acreate(*args, **kwargs):
            model = kwargs.get("model", "unknown")
            messages = kwargs.get("messages", [])
            stream = kwargs.get("stream", False)
            call_key = ""

            if not _should_skip(model) and messages:
                messages, call_key = _sanitize_messages(messages, model)
                kwargs["messages"] = messages

            try:
                response = await original_create(*args, **kwargs)

                if stream and call_key and not _should_skip(model):
                    stream_key = call_key
                    call_key = ""  # stream wrapper owns cleanup
                    return _async_stream_wrapper(response, model, stream_key)

                if call_key and not _should_skip(model) and hasattr(response, "choices"):
                    for choice in response.choices:
                        if hasattr(choice, "message") and hasattr(choice.message, "content"):
                            if choice.message.content:
                                choice.message.content = _desanitize_response(
                                    choice.message.content, model, call_key
                                )
                                call_key = ""  # consumed

                return response
            finally:
                if call_key:
                    with _maps_lock:
                        _active_maps.pop(call_key, None)

        completions.create = shielded_acreate
        # Store under _original_creates too for unified tracking
        _original_creates[client_id] = original_create
    else:
        _original_creates[client_id] = original_create

        def shielded_create(*args, **kwargs):
            model = kwargs.get("model", "unknown")
            messages = kwargs.get("messages", [])
            stream = kwargs.get("stream", False)
            call_key = ""

            if not _should_skip(model) and messages:
                messages, call_key = _sanitize_messages(messages, model)
                kwargs["messages"] = messages

            try:
                response = original_create(*args, **kwargs)

                if stream and call_key and not _should_skip(model):
                    stream_key = call_key
                    call_key = ""  # stream wrapper owns cleanup
                    return _sync_stream_wrapper(response, model, stream_key)

                if call_key and not _should_skip(model) and hasattr(response, "choices"):
                    for choice in response.choices:
                        if hasattr(choice, "message") and hasattr(choice.message, "content"):
                            if choice.message.content:
                                choice.message.content = _desanitize_response(
                                    choice.message.content, model, call_key
                                )
                                call_key = ""  # consumed

                return response
            finally:
                if call_key:
                    with _maps_lock:
                        _active_maps.pop(call_key, None)

        completions.create = shielded_create

    _shield.audit.log(
        event_type="shield_enabled",
        metadata={"integration": "openai"},
    )

    print("🛡️  CloakLLM enabled — detecting PII across OpenAI calls")
    print(f"   Audit logs: {_shield.config.log_dir.absolute()}")


def disable(client: Any):
    """Disable CloakLLM and restore original create method for the given client."""
    global _shield

    client_id = id(client)
    original = _original_creates.pop(client_id, None)
    _original_acreates.pop(client_id, None)

    if original and hasattr(client, "chat") and hasattr(client.chat, "completions"):
        client.chat.completions.create = original

    # If no more patched clients, clean up
    if not _original_creates:
        if _shield:
            _shield.audit.log(event_type="shield_disabled")
        _shield = None
        with _maps_lock:
            _active_maps.clear()


def get_shield() -> Optional[Shield]:
    """Get the active Shield instance (for advanced usage)."""
    return _shield


def is_enabled(client: Any = None) -> bool:
    """Check if CloakLLM is enabled for a specific client (or any client)."""
    if client is not None:
        return id(client) in _original_creates
    return bool(_original_creates)


def _is_async_client(client: Any) -> bool:
    """Detect if the client is an AsyncOpenAI instance."""
    cls_name = type(client).__name__
    return "Async" in cls_name


def _sync_stream_wrapper(stream, model: str, call_key: str):
    """Wrap a sync streaming response: buffer all chunks, desanitize, yield final."""
    try:
        buffer = ""
        last_chunk = None
        for chunk in stream:
            last_chunk = chunk
            if hasattr(chunk, "choices") and chunk.choices:
                delta = chunk.choices[0].delta
                if hasattr(delta, "content") and delta.content:
                    buffer += delta.content
                finish_reason = chunk.choices[0].finish_reason
                if finish_reason:
                    desanitized = _desanitize_response(buffer, model, call_key)
                    chunk.choices[0].delta.content = desanitized
                    yield chunk
                    return

        # Stream ended without finish_reason — emit whatever we have
        if buffer and last_chunk:
            desanitized = _desanitize_response(buffer, model, call_key)
            last_chunk.choices[0].delta.content = desanitized
            yield last_chunk
    finally:
        with _maps_lock:
            _active_maps.pop(call_key, None)


async def _async_stream_wrapper(stream, model: str, call_key: str):
    """Wrap an async streaming response: buffer all chunks, desanitize, yield final."""
    try:
        buffer = ""
        last_chunk = None
        async for chunk in stream:
            last_chunk = chunk
            if hasattr(chunk, "choices") and chunk.choices:
                delta = chunk.choices[0].delta
                if hasattr(delta, "content") and delta.content:
                    buffer += delta.content
                finish_reason = chunk.choices[0].finish_reason
                if finish_reason:
                    desanitized = _desanitize_response(buffer, model, call_key)
                    chunk.choices[0].delta.content = desanitized
                    yield chunk
                    return

        # Stream ended without finish_reason
        if buffer and last_chunk:
            desanitized = _desanitize_response(buffer, model, call_key)
            last_chunk.choices[0].delta.content = desanitized
            yield last_chunk
    finally:
        with _maps_lock:
            _active_maps.pop(call_key, None)
