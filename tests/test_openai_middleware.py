"""
Tests for OpenAI SDK middleware integration.

Run: pytest tests/test_openai_middleware.py -v
"""

import asyncio
import tempfile
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import MagicMock, AsyncMock

import pytest

from cloakllm import ShieldConfig
from cloakllm.integrations import openai_middleware


# ──────────────────────────────────────────────
# Helpers
# ──────────────────────────────────────────────

def _make_response(content: str):
    """Create a mock OpenAI ChatCompletion response."""
    message = SimpleNamespace(content=content, role="assistant")
    choice = SimpleNamespace(message=message, index=0, finish_reason="stop")
    return SimpleNamespace(choices=[choice], model="gpt-4o-mini")


def _make_sync_client(response=None):
    """Create a mock sync OpenAI client."""
    client = SimpleNamespace()
    completions = SimpleNamespace()
    if response is None:
        response = _make_response("Hello there!")
    completions.create = MagicMock(return_value=response)
    client.chat = SimpleNamespace(completions=completions)
    return client


class _AsyncOpenAI:
    """Mock async OpenAI client with 'Async' in the class name."""
    pass


def _make_async_client(response=None):
    """Create a mock async OpenAI client (AsyncOpenAI)."""
    client = _AsyncOpenAI()
    completions = SimpleNamespace()
    if response is None:
        response = _make_response("Hello there!")
    completions.create = AsyncMock(return_value=response)
    client.chat = SimpleNamespace(completions=completions)
    return client


def _make_stream_chunks(text: str):
    """Create mock streaming chunks that yield text character by character,
    with finish_reason on the last chunk."""
    chunks = []
    for i, char in enumerate(text):
        is_last = i == len(text) - 1
        delta = SimpleNamespace(content=char, role=None)
        choice = SimpleNamespace(
            delta=delta,
            index=0,
            finish_reason="stop" if is_last else None,
        )
        chunks.append(SimpleNamespace(choices=[choice]))
    return chunks


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture(autouse=True)
def clean_state(tmp_path):
    """Reset module state before each test."""
    openai_middleware._shield = None
    openai_middleware._original_creates.clear()
    openai_middleware._original_acreates.clear()
    openai_middleware._active_maps.clear()
    yield
    # Cleanup after test
    openai_middleware._shield = None
    openai_middleware._original_creates.clear()
    openai_middleware._original_acreates.clear()
    openai_middleware._active_maps.clear()


@pytest.fixture
def config(tmp_path):
    return ShieldConfig(
        log_dir=tmp_path / "audit",
        audit_enabled=True,
        log_original_values=False,
    )


# ──────────────────────────────────────────────
# Test: enable / disable
# ──────────────────────────────────────────────

class TestEnableDisable:
    def test_enable_patches_create(self, config):
        client = _make_sync_client()
        original = client.chat.completions.create
        openai_middleware.enable(client, config=config)
        assert client.chat.completions.create is not original
        assert openai_middleware.is_enabled(client)

    def test_disable_restores_create(self, config):
        client = _make_sync_client()
        original = client.chat.completions.create
        openai_middleware.enable(client, config=config)
        openai_middleware.disable(client)
        assert client.chat.completions.create is original
        assert not openai_middleware.is_enabled(client)

    def test_enable_twice_is_noop(self, config):
        client = _make_sync_client()
        openai_middleware.enable(client, config=config)
        create_after_first = client.chat.completions.create
        openai_middleware.enable(client, config=config)
        assert client.chat.completions.create is create_after_first

    def test_enable_invalid_client_raises(self, config):
        with pytest.raises(TypeError, match="Expected an OpenAI client"):
            openai_middleware.enable(object(), config=config)

    def test_is_enabled_no_client(self, config):
        assert not openai_middleware.is_enabled()
        client = _make_sync_client()
        openai_middleware.enable(client, config=config)
        assert openai_middleware.is_enabled()

    def test_multi_client(self, config):
        client1 = _make_sync_client()
        client2 = _make_sync_client()
        openai_middleware.enable(client1, config=config)
        openai_middleware.enable(client2, config=config)
        assert openai_middleware.is_enabled(client1)
        assert openai_middleware.is_enabled(client2)

        openai_middleware.disable(client1)
        assert not openai_middleware.is_enabled(client1)
        assert openai_middleware.is_enabled(client2)
        # Shield still exists because client2 is active
        assert openai_middleware._shield is not None

        openai_middleware.disable(client2)
        assert openai_middleware._shield is None


# ──────────────────────────────────────────────
# Test: sync create
# ──────────────────────────────────────────────

class TestSyncCreate:
    def test_sanitizes_messages(self, config):
        response = _make_response("Got it, [EMAIL_0]!")
        client = _make_sync_client(response)
        original_create = client.chat.completions.create
        openai_middleware.enable(client, config=config)

        result = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Email john@example.com please"}],
        )

        # Original create should have been called with sanitized messages
        call_args = original_create.call_args
        sent_messages = call_args.kwargs.get("messages", call_args.args[0] if call_args.args else [])
        # The user message should have [EMAIL_0] instead of john@example.com
        user_msg = [m for m in sent_messages if m.get("role") == "user"][0]
        assert "john@example.com" not in user_msg["content"]
        assert "[EMAIL_0]" in user_msg["content"]

    def test_desanitizes_response(self, config):
        response = _make_response("I'll email [EMAIL_0] right away.")
        client = _make_sync_client(response)
        openai_middleware.enable(client, config=config)

        result = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Email john@example.com please"}],
        )

        # Response should have the original email restored
        assert "john@example.com" in result.choices[0].message.content
        assert "[EMAIL_0]" not in result.choices[0].message.content

    def test_no_pii_passthrough(self, config):
        response = _make_response("Sure, here's the info.")
        client = _make_sync_client(response)
        original_create = client.chat.completions.create
        openai_middleware.enable(client, config=config)

        result = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "What is the weather today?"}],
        )

        assert result.choices[0].message.content == "Sure, here's the info."

    def test_system_hint_injected(self, config):
        response = _make_response("Done!")
        client = _make_sync_client(response)
        original_create = client.chat.completions.create
        openai_middleware.enable(client, config=config)

        client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Email john@example.com"}],
        )

        call_args = original_create.call_args
        sent_messages = call_args.kwargs.get("messages", [])
        # System hint should be injected as first message
        assert sent_messages[0]["role"] == "system"
        assert "placeholders" in sent_messages[0]["content"]

    def test_existing_system_message_appended(self, config):
        response = _make_response("Done!")
        client = _make_sync_client(response)
        original_create = client.chat.completions.create
        openai_middleware.enable(client, config=config)

        client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[
                {"role": "system", "content": "You are helpful."},
                {"role": "user", "content": "Email john@example.com"},
            ],
        )

        call_args = original_create.call_args
        sent_messages = call_args.kwargs.get("messages", [])
        assert sent_messages[0]["role"] == "system"
        assert "You are helpful." in sent_messages[0]["content"]
        assert "placeholders" in sent_messages[0]["content"]

    def test_multimodal_content(self, config):
        response = _make_response("Got it!")
        client = _make_sync_client(response)
        original_create = client.chat.completions.create
        openai_middleware.enable(client, config=config)

        client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{
                "role": "user",
                "content": [
                    {"type": "text", "text": "Email john@example.com"},
                    {"type": "image_url", "image_url": {"url": "data:image/png;base64,abc"}},
                ],
            }],
        )

        call_args = original_create.call_args
        sent_messages = call_args.kwargs.get("messages", [])
        user_msg = [m for m in sent_messages if m.get("role") == "user"][0]
        text_part = [p for p in user_msg["content"] if p.get("type") == "text"][0]
        assert "john@example.com" not in text_part["text"]
        assert "[EMAIL_0]" in text_part["text"]
        # Image part should be unchanged
        image_part = [p for p in user_msg["content"] if p.get("type") == "image_url"][0]
        assert image_part["image_url"]["url"] == "data:image/png;base64,abc"


# ──────────────────────────────────────────────
# Test: skip models
# ──────────────────────────────────────────────

class TestSkipModels:
    def test_skip_models_config(self, tmp_path):
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            skip_models=["ollama/"],
        )
        response = _make_response("Hello!")
        client = _make_sync_client(response)
        original_create = client.chat.completions.create
        openai_middleware.enable(client, config=config)

        client.chat.completions.create(
            model="ollama/llama3",
            messages=[{"role": "user", "content": "Email john@example.com"}],
        )

        # Messages should NOT be sanitized for skipped models
        call_args = original_create.call_args
        sent_messages = call_args.kwargs.get("messages", [])
        user_msg = [m for m in sent_messages if m.get("role") == "user"][0]
        assert "john@example.com" in user_msg["content"]


# ──────────────────────────────────────────────
# Test: sync streaming
# ──────────────────────────────────────────────

class TestSyncStreaming:
    def test_stream_desanitizes(self, config):
        chunks = _make_stream_chunks("I'll email [EMAIL_0].")
        # Set up client with the streaming mock BEFORE enable so the
        # middleware wraps it and captures the original
        client = _make_sync_client()
        client.chat.completions.create = MagicMock(return_value=iter(chunks))
        openai_middleware.enable(client, config=config)

        result = client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Email john@example.com"}],
            stream=True,
        )

        output_chunks = list(result)
        # Incremental streaming: multiple chunks emitted as text arrives
        assert len(output_chunks) >= 1
        full_content = "".join(
            c.choices[0].delta.content for c in output_chunks
            if hasattr(c.choices[0].delta, "content") and c.choices[0].delta.content
        )
        assert "john@example.com" in full_content
        assert "[EMAIL_0]" not in full_content


# ──────────────────────────────────────────────
# Test: async create
# ──────────────────────────────────────────────

class TestAsyncCreate:
    def test_async_sanitizes_and_desanitizes(self, config):
        response = _make_response("I'll email [EMAIL_0] right away.")
        client = _make_async_client(response)
        openai_middleware.enable(client, config=config)

        result = asyncio.get_event_loop().run_until_complete(
            client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "Email john@example.com please"}],
            )
        )

        assert "john@example.com" in result.choices[0].message.content
        assert "[EMAIL_0]" not in result.choices[0].message.content

    def test_async_no_pii_passthrough(self, config):
        response = _make_response("The weather is fine.")
        client = _make_async_client(response)
        openai_middleware.enable(client, config=config)

        result = asyncio.get_event_loop().run_until_complete(
            client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "What is the weather?"}],
            )
        )

        assert result.choices[0].message.content == "The weather is fine."


# ──────────────────────────────────────────────
# Test: async streaming
# ──────────────────────────────────────────────

class TestAsyncStreaming:
    def test_async_stream_desanitizes(self, config):
        chunks = _make_stream_chunks("I'll email [EMAIL_0].")

        async def async_iter():
            for chunk in chunks:
                yield chunk

        # Set up the mock before enable so it captures the right original
        client = _make_async_client()
        client.chat.completions.create = AsyncMock(return_value=async_iter())
        openai_middleware.enable(client, config=config)

        async def run():
            result = await client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "Email john@example.com"}],
                stream=True,
            )
            output = []
            async for chunk in result:
                output.append(chunk)
            return output

        output_chunks = asyncio.get_event_loop().run_until_complete(run())
        # Incremental streaming: multiple chunks emitted as text arrives
        assert len(output_chunks) >= 1
        full_content = "".join(
            c.choices[0].delta.content for c in output_chunks
            if hasattr(c.choices[0].delta, "content") and c.choices[0].delta.content
        )
        assert "john@example.com" in full_content
        assert "[EMAIL_0]" not in full_content


# ──────────────────────────────────────────────
# Test: token map cleanup
# ──────────────────────────────────────────────

class TestCleanup:
    def test_active_maps_cleaned_after_call(self, config):
        response = _make_response("Done!")
        client = _make_sync_client(response)
        openai_middleware.enable(client, config=config)

        client.chat.completions.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": "Email john@example.com"}],
        )

        assert len(openai_middleware._active_maps) == 0

    def test_active_maps_cleaned_on_error(self, config):
        # Set up mock that raises BEFORE enable so the wrapper captures it
        client = _make_sync_client()
        client.chat.completions.create = MagicMock(side_effect=RuntimeError("API error"))
        openai_middleware.enable(client, config=config)

        with pytest.raises(RuntimeError, match="API error"):
            client.chat.completions.create(
                model="gpt-4o-mini",
                messages=[{"role": "user", "content": "Email john@example.com"}],
            )

        assert len(openai_middleware._active_maps) == 0
