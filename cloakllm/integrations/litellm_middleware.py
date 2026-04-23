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
import time
import uuid
from typing import Any, Optional

from cloakllm.config import ShieldConfig
from cloakllm.shield import Shield
from cloakllm.stream import StreamDesanitizer
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
_original_acompletion = None
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


def _pop_token_map(call_key: str) -> Optional[TokenMap]:
    """Retrieve and remove the stored token map for a call."""
    with _maps_lock:
        return _active_maps.pop(call_key, None)


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
    global _shield, _original_completion, _original_acompletion, _enabled

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
    _original_acompletion = litellm.acompletion

    # Wrap synchronous completion
    def shielded_completion(*args, **kwargs):
        model = kwargs.get("model") or (args[0] if args else "unknown")
        messages = kwargs.get("messages") or (args[1] if len(args) > 1 else [])
        stream = kwargs.get("stream", False)
        call_key = ""

        if not _should_skip(model):
            messages, call_key = _sanitize_messages(messages, model)
            kwargs["messages"] = messages

        try:
            # Call original
            response = _original_completion(*args, **kwargs)

            # Handle streaming responses
            if stream and call_key and not _should_skip(model):
                # v0.6.3 P0-2: pop token_map + capture _shield SYNCHRONOUSLY
                # before returning the lazy stream wrapper. Eliminates the
                # disable()-mid-stream race that would silently drop the
                # Article 12 audit entry.
                stream_token_map = _pop_token_map(call_key)
                stream_shield = _shield
                call_key = ""
                return _sync_litellm_stream_wrapper(response, model, stream_token_map, stream_shield)

            # Desanitize all choices with the SAME token map (pop once)
            if not _should_skip(model) and call_key and hasattr(response, "choices"):
                token_map = _pop_token_map(call_key)
                call_key = ""  # consumed — skip finally cleanup
                if token_map and token_map.entity_count > 0:
                    for choice in response.choices:
                        if hasattr(choice, "message") and hasattr(choice.message, "content"):
                            if choice.message.content:
                                choice.message.content = _shield.desanitize(
                                    choice.message.content, token_map, model=model
                                )

            return response
        finally:
            if call_key:
                with _maps_lock:
                    _active_maps.pop(call_key, None)

    # Wrap asynchronous completion
    async def shielded_acompletion(*args, **kwargs):
        model = kwargs.get("model") or (args[0] if args else "unknown")
        messages = kwargs.get("messages") or (args[1] if len(args) > 1 else [])
        stream = kwargs.get("stream", False)
        call_key = ""

        if not _should_skip(model):
            messages, call_key = _sanitize_messages(messages, model)
            kwargs["messages"] = messages

        try:
            response = await _original_acompletion(*args, **kwargs)

            # Handle streaming responses
            if stream and call_key and not _should_skip(model):
                # v0.6.3 P0-2: same as sync path — synchronous pop + capture.
                stream_token_map = _pop_token_map(call_key)
                stream_shield = _shield
                call_key = ""
                return _async_litellm_stream_wrapper(response, model, stream_token_map, stream_shield)

            # Desanitize all choices with the SAME token map (pop once)
            if not _should_skip(model) and call_key and hasattr(response, "choices"):
                token_map = _pop_token_map(call_key)
                call_key = ""  # consumed — skip finally cleanup
                if token_map and token_map.entity_count > 0:
                    for choice in response.choices:
                        if hasattr(choice, "message") and hasattr(choice.message, "content"):
                            if choice.message.content:
                                choice.message.content = _shield.desanitize(
                                    choice.message.content, token_map, model=model
                                )

            return response
        finally:
            if call_key:
                with _maps_lock:
                    _active_maps.pop(call_key, None)

    # Patch LiteLLM
    litellm.completion = shielded_completion
    litellm.acompletion = shielded_acompletion
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
        # v0.6.4 BUG-5: explicit `is not None` guards. Truthy checks here are
        # semantically equivalent for callables (always truthy) but `is not None`
        # is precise — defends against a future case where the original is set
        # to a sentinel falsy object (e.g., a Mock with __bool__ returning False).
        if _original_completion is not None:
            litellm.completion = _original_completion
        if _original_acompletion is not None:
            litellm.acompletion = _original_acompletion
    except ImportError:
        pass

    if _shield:
        _shield.audit.log(event_type="shield_disabled")

    _shield = None
    _enabled = False

    with _maps_lock:
        _active_maps.clear()

    print("🛡️  CloakLLM disabled")


import logging as _logging
_audit_logger = _logging.getLogger("cloakllm.audit")
_audit_failure_warned_once = False  # P0-4: warn once per process about audit failures


def _stream_audit_log(token_map, model, desan, start_perf, stream_error, shield_local):
    """v0.6.3 (NEW-3 / P0-2 / P0-4): write a single desanitize_stream audit
    entry per stream lifecycle. `shield_local` captured at wrapper-construction
    time prevents disable()-mid-stream Article 12 gaps. Audit failure logged
    via WARNING (not silently swallowed), but never breaks the stream.
    """
    if shield_local is None or shield_local.audit is None:
        return
    elapsed_ms = (time.perf_counter() - start_perf) * 1000
    metadata = {"chars_processed": int(getattr(desan, "chars_processed", 0))}
    if stream_error is not None:
        metadata["stream_error"] = True
        metadata["error_type"] = type(stream_error).__name__
    try:
        shield_local.audit.log(
            event_type="desanitize_stream",
            entity_count=token_map.entity_count if token_map else 0,
            categories=dict(token_map.categories) if token_map else {},
            tokens_used=list(token_map.reverse.keys()) if token_map else [],
            latency_ms=elapsed_ms,
            mode=token_map.mode if token_map else None,
            entity_details=token_map.entity_details if token_map else [],
            model=model,
            metadata=metadata,
        )
    except Exception as e:
        global _audit_failure_warned_once
        if not _audit_failure_warned_once:
            _audit_failure_warned_once = True
            _audit_logger.warning(
                "CloakLLM audit log write failed in litellm stream wrapper: %s. "
                "All subsequent failures of this kind will be silenced. "
                "Investigate disk space, permissions, or audit chain integrity.",
                type(e).__name__,
            )


class _NoOpDesan:
    """Stand-in for StreamDesanitizer when there's no PII to desanitize."""
    chars_processed = 0


def _sync_litellm_stream_wrapper(stream, model: str, token_map, shield_local):
    """Wrap a sync LiteLLM streaming response with incremental desanitization.

    v0.6.3 P0-2: token_map and shield_local passed in (popped/captured by outer).
    """
    # P2-3: even when entity_count == 0, write a desanitize_stream audit entry.
    if not token_map or token_map.entity_count == 0:
        start_perf = time.perf_counter()
        try:
            yield from stream
        finally:
            _stream_audit_log(token_map, model, _NoOpDesan(), start_perf, None, shield_local)
        return

    # v0.6.3 NEW-3.e
    max_in = getattr(shield_local.config, "max_input_length", 0) if shield_local else 0
    desan = StreamDesanitizer(token_map, max_input_length=max_in)
    last_chunk = None
    start_perf = time.perf_counter()
    stream_error = None

    try:
        for chunk in stream:
            last_chunk = chunk
            if hasattr(chunk, "choices") and chunk.choices:
                delta = chunk.choices[0].delta
                if hasattr(delta, "content") and delta.content:
                    output = desan.feed(delta.content)
                    if output:
                        chunk.choices[0].delta.content = output
                        yield chunk
                    continue

                finish_reason = chunk.choices[0].finish_reason
                if finish_reason:
                    flushed = desan.flush()
                    if flushed:
                        chunk.choices[0].delta.content = flushed
                    yield chunk
                    return

            yield chunk

        # Stream ended without finish_reason
        flushed = desan.flush()
        if flushed and last_chunk:
            last_chunk.choices[0].delta.content = flushed
            yield last_chunk
    except Exception as e:
        stream_error = e
        raise
    finally:
        # v0.6.3 NEW-3
        _stream_audit_log(token_map, model, desan, start_perf, stream_error, shield_local)


async def _async_litellm_stream_wrapper(stream, model: str, token_map, shield_local):
    """Async mirror. Same P0-2 guarantees."""
    # P2-3
    if not token_map or token_map.entity_count == 0:
        start_perf = time.perf_counter()
        try:
            async for chunk in stream:
                yield chunk
        finally:
            _stream_audit_log(token_map, model, _NoOpDesan(), start_perf, None, shield_local)
        return

    # v0.6.3 NEW-3.e
    max_in = getattr(shield_local.config, "max_input_length", 0) if shield_local else 0
    desan = StreamDesanitizer(token_map, max_input_length=max_in)
    last_chunk = None
    start_perf = time.perf_counter()
    stream_error = None

    try:
        async for chunk in stream:
            last_chunk = chunk
            if hasattr(chunk, "choices") and chunk.choices:
                delta = chunk.choices[0].delta
                if hasattr(delta, "content") and delta.content:
                    output = desan.feed(delta.content)
                    if output:
                        chunk.choices[0].delta.content = output
                        yield chunk
                    continue

                finish_reason = chunk.choices[0].finish_reason
                if finish_reason:
                    flushed = desan.flush()
                    if flushed:
                        chunk.choices[0].delta.content = flushed
                    yield chunk
                    return

            yield chunk

        # Stream ended without finish_reason
        flushed = desan.flush()
        if flushed and last_chunk:
            last_chunk.choices[0].delta.content = flushed
            yield last_chunk
    except Exception as e:
        stream_error = e
        raise
    finally:
        # v0.6.3 NEW-3
        _stream_audit_log(token_map, model, desan, start_perf, stream_error, shield_local)


def get_shield() -> Optional[Shield]:
    """Get the active Shield instance (for advanced usage)."""
    return _shield


def is_enabled() -> bool:
    """Check if CloakLLM is currently enabled."""
    return _enabled
