"""Integration tests for LiteLLM middleware with streaming support."""

import asyncio
import sys
import types
from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest
from cloakllm.config import ShieldConfig
from cloakllm.integrations import litellm_middleware


@pytest.fixture(autouse=True)
def cleanup():
    yield
    # Reset module state
    litellm_middleware._shield = None
    litellm_middleware._enabled = False
    litellm_middleware._original_completion = None
    litellm_middleware._original_acompletion = None
    litellm_middleware._active_maps.clear()
    # Clean up mock litellm module
    sys.modules.pop("litellm", None)


@pytest.fixture
def config(tmp_path):
    return ShieldConfig(log_dir=tmp_path / "audit", audit_enabled=False)


@pytest.fixture
def mock_litellm():
    """Create a mock litellm module and inject it into sys.modules."""
    mod = types.ModuleType("litellm")

    def default_completion(*args, **kwargs):
        raise NotImplementedError("Should be overridden per test")

    async def default_acompletion(*args, **kwargs):
        raise NotImplementedError("Should be overridden per test")

    mod.completion = default_completion
    mod.acompletion = default_acompletion
    sys.modules["litellm"] = mod
    return mod


def _make_response_n_choices(text, n):
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


def _make_stream_chunks(text):
    """Create char-by-char stream chunks with finish_reason on last char."""
    chunks = []
    for i, char in enumerate(text):
        is_last = i == len(text) - 1
        chunks.append(
            SimpleNamespace(
                choices=[
                    SimpleNamespace(
                        delta=SimpleNamespace(content=char, role=None),
                        index=0,
                        finish_reason="stop" if is_last else None,
                    )
                ]
            )
        )
    return chunks


class TestLiteLLMNonStreaming:
    def test_desanitizes_n_choices(self, config, mock_litellm):
        response = _make_response_n_choices("Reply to [EMAIL_0].", 3)
        mock_litellm.completion = MagicMock(return_value=response)
        mock_litellm.acompletion = MagicMock()

        litellm_middleware.enable(config=config)

        import litellm
        result = litellm.completion(
            model="gpt-4",
            messages=[{"role": "user", "content": "Email john@example.com"}],
        )

        for choice in result.choices:
            assert "john@example.com" in choice.message.content
            assert "[EMAIL_0]" not in choice.message.content


class TestLiteLLMSyncStreaming:
    def test_sync_streaming_desanitizes(self, config, mock_litellm):
        stream_chunks = _make_stream_chunks("Reply to [EMAIL_0] now.")

        def sync_completion(*args, **kwargs):
            return iter(stream_chunks)

        mock_litellm.completion = sync_completion
        mock_litellm.acompletion = MagicMock()

        litellm_middleware.enable(config=config)

        import litellm
        result = litellm.completion(
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


class TestLiteLLMAsyncStreaming:
    def test_async_streaming_desanitizes(self, config, mock_litellm):
        stream_chunks = _make_stream_chunks("Reply to [EMAIL_0] now.")

        async def async_completion(*args, **kwargs):
            async def async_iter():
                for chunk in stream_chunks:
                    yield chunk
            return async_iter()

        mock_litellm.completion = MagicMock()
        mock_litellm.acompletion = async_completion

        litellm_middleware.enable(config=config)

        async def run():
            import litellm
            result = await litellm.acompletion(
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
