"""Integration tests for OpenAI SDK middleware with incremental streaming."""

import asyncio
import tempfile
from types import SimpleNamespace
from unittest.mock import MagicMock, AsyncMock

import pytest
from cloakllm.config import ShieldConfig
from cloakllm.integrations import openai_middleware


@pytest.fixture(autouse=True)
def cleanup():
    yield
    # Reset module state
    openai_middleware._shield = None
    openai_middleware._original_creates.clear()
    openai_middleware._original_acreates.clear()
    openai_middleware._active_maps.clear()


@pytest.fixture
def config(tmp_path):
    return ShieldConfig(log_dir=tmp_path / "audit", audit_enabled=False)


def _make_sync_client(response=None):
    client = SimpleNamespace(
        chat=SimpleNamespace(
            completions=SimpleNamespace(
                create=MagicMock(return_value=response),
            ),
        ),
    )
    return client


class _AsyncOpenAI:
    """Mock async OpenAI client with 'Async' in the class name."""
    pass


def _make_async_client(response=None):
    client = _AsyncOpenAI()
    client.chat = SimpleNamespace(
        completions=SimpleNamespace(
            create=AsyncMock(return_value=response),
        ),
    )
    return client


def _make_response_n_choices(text, n):
    """Create a response with n choices all containing the same text."""
    return SimpleNamespace(
        choices=[
            SimpleNamespace(
                index=i,
                message=SimpleNamespace(role="assistant", content=text),
                finish_reason="stop",
            )
            for i in range(n)
        ]
    )


def _make_stream_chunks_with_split_token():
    """Create stream chunks where a token is split across chunks."""
    chunks = [
        SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Contact ", role=None), index=0, finish_reason=None)]),
        SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="[EMA", role=None), index=0, finish_reason=None)]),
        SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="IL_0]", role=None), index=0, finish_reason=None)]),
        SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content=" now.", role=None), index=0, finish_reason="stop")]),
    ]
    return chunks


class TestSyncNChoices:
    def test_desanitizes_all_choices(self, config):
        response = _make_response_n_choices("Reply to [EMAIL_0] about the project.", 3)
        client = _make_sync_client(response)
        openai_middleware.enable(client, config=config)

        result = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Email john@example.com about the project"}],
            n=3,
        )

        for choice in result.choices:
            assert "john@example.com" in choice.message.content
            assert "[EMAIL_0]" not in choice.message.content


class TestSyncStreamingIncremental:
    def test_incremental_streaming(self, config):
        chunks = _make_stream_chunks_with_split_token()
        client = _make_sync_client()
        client.chat.completions.create = MagicMock(return_value=iter(chunks))
        openai_middleware.enable(client, config=config)

        result = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Email john@example.com"}],
            stream=True,
        )

        output_chunks = list(result)
        assert len(output_chunks) >= 1

        full_content = "".join(
            c.choices[0].delta.content for c in output_chunks
            if hasattr(c.choices[0].delta, "content") and c.choices[0].delta.content
        )
        assert "john@example.com" in full_content
        assert "[EMAIL_0]" not in full_content

    def test_passthrough_no_pii(self, config):
        chunks = [
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="Hello ", role=None), index=0, finish_reason=None)]),
            SimpleNamespace(choices=[SimpleNamespace(delta=SimpleNamespace(content="world!", role=None), index=0, finish_reason="stop")]),
        ]
        client = _make_sync_client()
        client.chat.completions.create = MagicMock(return_value=iter(chunks))
        openai_middleware.enable(client, config=config)

        result = client.chat.completions.create(
            model="gpt-4",
            messages=[{"role": "user", "content": "Say hello"}],
            stream=True,
        )

        output_chunks = list(result)
        full_content = "".join(
            c.choices[0].delta.content for c in output_chunks
            if hasattr(c.choices[0].delta, "content") and c.choices[0].delta.content
        )
        assert full_content == "Hello world!"


class TestAsyncStreamingIncremental:
    def test_async_incremental_streaming(self, config):
        chunks = _make_stream_chunks_with_split_token()

        async def async_iter():
            for chunk in chunks:
                yield chunk

        # Use the same pattern as existing tests: AsyncMock with return_value
        # and set up BEFORE enable so middleware captures it as the original
        client = _make_async_client()
        client.chat.completions.create = AsyncMock(return_value=async_iter())
        openai_middleware.enable(client, config=config)

        async def run():
            result = await client.chat.completions.create(
                model="gpt-4",
                messages=[{"role": "user", "content": "Email john@example.com"}],
                stream=True,
            )
            output = []
            async for chunk in result:
                output.append(chunk)
            return output

        output_chunks = asyncio.get_event_loop().run_until_complete(run())
        assert len(output_chunks) >= 1

        full_content = "".join(
            c.choices[0].delta.content for c in output_chunks
            if hasattr(c.choices[0].delta, "content") and c.choices[0].delta.content
        )
        assert "john@example.com" in full_content
        assert "[EMAIL_0]" not in full_content
