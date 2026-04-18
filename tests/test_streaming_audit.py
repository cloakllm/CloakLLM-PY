"""
v0.6.3 NEW-3 / P0-2 / P0-4 / P1-1 / P1-4 / P1-5 / P2-1 / P2-3
— streaming audit invariant tests.

Before NEW-3: StreamDesanitizer paths in OpenAI/LiteLLM middlewares wrote
ZERO desanitize entries. Every streamed call produced one sanitize entry
followed by silence — the EU AI Act Article 12 invariant ("every interaction
logged") was silently violated for any user with `stream=True` (default in
production).

After NEW-3 + Phase 0 follow-on fixes: each streamed call writes exactly
ONE `desanitize_stream` audit entry in a try/finally, regardless of how the
stream terminates (normal completion, mid-stream exception, generator close,
or no-PII short-circuit). The entry passes B3 schema validation.

Coverage:
- StreamDesanitizer cap (NEW-3.e)
- bytes_processed deprecation alias (P2-1)
- OpenAI sync wrapper: writes entry on completion, error, no-pii, generator close
- OpenAI async wrapper: same scenarios
- LiteLLM sync + async wrappers: same scenarios
- B3 schema compliance for every produced entry
"""

import asyncio
import json
from pathlib import Path

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.stream import StreamDesanitizer


def _read_audit_entries(audit_dir: Path):
    entries = []
    for p in sorted(audit_dir.glob("audit_*.jsonl")):
        with open(p, encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    entries.append(json.loads(line))
    return entries


# --- StreamDesanitizer cap (NEW-3.e + P2-1) --------------------------------


def test_stream_desanitizer_default_no_cap():
    """Back-compat: default max_input_length=0 means no cap."""
    from cloakllm.tokenizer import TokenMap
    tm = TokenMap()
    desan = StreamDesanitizer(tm)
    out = desan.feed("x" * 1_000_000)
    assert isinstance(out, str)
    assert desan.chars_processed == 1_000_000


def test_stream_desanitizer_cap_enforced():
    """When cap > 0, exceeding it raises ValueError."""
    from cloakllm.tokenizer import TokenMap
    tm = TokenMap()
    desan = StreamDesanitizer(tm, max_input_length=100)
    desan.feed("x" * 90)
    with pytest.raises(ValueError, match=r"max_input_length=100"):
        desan.feed("x" * 20)


def test_stream_desanitizer_chars_processed_accumulates():
    from cloakllm.tokenizer import TokenMap
    tm = TokenMap()
    desan = StreamDesanitizer(tm)
    desan.feed("hello ")
    desan.feed("world")
    assert desan.chars_processed == 11


def test_bytes_processed_alias_warns_deprecated():
    """v0.6.3 P2-1: bytes_processed kept as DeprecationWarning alias."""
    import warnings
    from cloakllm.tokenizer import TokenMap
    tm = TokenMap()
    desan = StreamDesanitizer(tm)
    desan.feed("hello")
    with warnings.catch_warnings(record=True) as w:
        warnings.simplefilter("always")
        val = desan.bytes_processed
    assert val == 5
    deps = [x for x in w if issubclass(x.category, DeprecationWarning)]
    assert deps, "bytes_processed should emit DeprecationWarning"
    assert "chars_processed" in str(deps[0].message)


# --- Mock streaming chunk shape ---


class _MockChunk:
    def __init__(self, content="", finish_reason=None):
        self.choices = [_MockChoice(content, finish_reason)]


class _MockChoice:
    def __init__(self, content, finish_reason):
        self.delta = _MockDelta(content)
        self.finish_reason = finish_reason


class _MockDelta:
    def __init__(self, content):
        self.content = content


def _mock_stream_sync(chunks):
    def gen():
        for c in chunks:
            yield c
    return gen()


async def _mock_stream_async(chunks):
    for c in chunks:
        yield c


# --- OpenAI sync wrapper ---


def _setup_shield(tmp_path, name="audit"):
    cfg = ShieldConfig(
        log_dir=tmp_path / name,
        audit_enabled=True,
        compliance_mode="eu_ai_act_article12",
    )
    shield = Shield(cfg)
    return shield


def test_openai_sync_stream_writes_desanitize_audit_entry(tmp_path):
    """v0.6.3 NEW-3: writes one desanitize_stream entry on normal completion."""
    from cloakllm.integrations import openai_middleware

    shield = _setup_shield(tmp_path)
    sanitized, token_map = shield.sanitize("Email john@acme.com")

    chunks = [
        _MockChunk(content="Hello, "),
        _MockChunk(content="[EMAIL_0]"),
        _MockChunk(content=" — please respond.", finish_reason="stop"),
    ]
    stream = _mock_stream_sync(chunks)

    # P0-2: pass token_map and shield directly (new wrapper signature)
    out = list(openai_middleware._sync_stream_wrapper(stream, "gpt-4", token_map, shield))

    entries = _read_audit_entries(tmp_path / "audit")
    stream_entries = [e for e in entries if e["event_type"] == "desanitize_stream"]
    assert len(stream_entries) == 1
    e = stream_entries[0]
    assert e["entity_count"] == token_map.entity_count
    assert "EMAIL" in e["categories"]
    assert "[EMAIL_0]" in e["tokens_used"]
    assert "chars_processed" in e["metadata"]
    assert e["metadata"]["chars_processed"] > 0
    assert "stream_error" not in e["metadata"]


def test_openai_sync_stream_audit_entry_on_error(tmp_path):
    """Stream raising mid-flight still writes audit entry (with stream_error)."""
    from cloakllm.integrations import openai_middleware

    shield = _setup_shield(tmp_path)
    sanitized, token_map = shield.sanitize("Email john@acme.com")

    def err_stream():
        yield _MockChunk(content="partial ")
        raise RuntimeError("upstream LLM exploded")

    with pytest.raises(RuntimeError, match="exploded"):
        list(openai_middleware._sync_stream_wrapper(err_stream(), "gpt-4", token_map, shield))

    entries = _read_audit_entries(tmp_path / "audit")
    stream_entries = [e for e in entries if e["event_type"] == "desanitize_stream"]
    assert len(stream_entries) == 1
    assert stream_entries[0]["metadata"].get("stream_error") is True
    assert stream_entries[0]["metadata"].get("error_type") == "RuntimeError"


def test_openai_sync_stream_no_pii_now_writes_audit(tmp_path):
    """v0.6.3 P2-3: even when no PII, write a desanitize_stream entry
    (strict Article 12 — every interaction logged)."""
    from cloakllm.integrations import openai_middleware

    shield = _setup_shield(tmp_path)
    sanitized, token_map = shield.sanitize("plain text")
    assert token_map.entity_count == 0

    chunks = [_MockChunk(content="ok", finish_reason="stop")]
    list(openai_middleware._sync_stream_wrapper(_mock_stream_sync(chunks), "gpt-4", token_map, shield))

    entries = _read_audit_entries(tmp_path / "audit")
    stream_entries = [e for e in entries if e["event_type"] == "desanitize_stream"]
    assert len(stream_entries) == 1, "P2-3: even no-PII streams must log"
    e = stream_entries[0]
    assert e["entity_count"] == 0


def test_openai_sync_stream_audit_passes_b3_schema(tmp_path):
    """Every stream-side audit entry must pass the always-on B3 validator."""
    from cloakllm.integrations import openai_middleware
    from cloakllm.audit import _validate_audit_entry_schema

    shield = _setup_shield(tmp_path)
    sanitized, token_map = shield.sanitize("Email me at john@acme.com")

    chunks = [_MockChunk(content="x", finish_reason="stop")]
    list(openai_middleware._sync_stream_wrapper(_mock_stream_sync(chunks), "gpt-4", token_map, shield))

    entries = _read_audit_entries(tmp_path / "audit")
    for e in entries:
        e_v = {k: v for k, v in e.items() if k != "entry_hash"}
        _validate_audit_entry_schema(e_v)  # raises if invalid


# --- v0.6.3 P0-2: capture _shield BEFORE disable() ---


def test_openai_sync_stream_survives_shield_disable_mid_stream(tmp_path):
    """v0.6.3 P0-2: even if module-global _shield is nulled mid-stream,
    the wrapper uses its captured local reference and writes the audit entry.
    """
    from cloakllm.integrations import openai_middleware

    shield = _setup_shield(tmp_path)
    sanitized, token_map = shield.sanitize("john@acme.com")

    def stream_with_disable():
        yield _MockChunk(content="hi ")
        # Simulate disable() race: module-global goes to None mid-stream
        openai_middleware._shield = None
        yield _MockChunk(content="[EMAIL_0]", finish_reason="stop")

    try:
        list(openai_middleware._sync_stream_wrapper(stream_with_disable(), "gpt-4", token_map, shield))
        entries = _read_audit_entries(tmp_path / "audit")
        stream_entries = [e for e in entries if e["event_type"] == "desanitize_stream"]
        assert len(stream_entries) == 1, (
            "P0-2: audit must fire even if module _shield was nulled mid-stream "
            "(captured shield_local should be used)"
        )
    finally:
        openai_middleware._shield = None  # restore for other tests


# --- v0.6.3 P1-5: generator-close (consumer break) ---


def test_openai_sync_stream_generator_close_writes_audit(tmp_path):
    """v0.6.3 P1-5: when consumer breaks out of the loop (generator.close()),
    the finally block must fire and write the audit entry."""
    from cloakllm.integrations import openai_middleware

    shield = _setup_shield(tmp_path)
    sanitized, token_map = shield.sanitize("john@acme.com")

    chunks = [
        _MockChunk(content="hi "),
        _MockChunk(content="[EMAIL_0]"),
        _MockChunk(content=" more"),
        _MockChunk(content=" stuff", finish_reason="stop"),
    ]
    gen = openai_middleware._sync_stream_wrapper(_mock_stream_sync(chunks), "gpt-4", token_map, shield)

    # Consumer takes one chunk then breaks
    next(gen)
    gen.close()  # explicit close → triggers GeneratorExit → finally runs

    entries = _read_audit_entries(tmp_path / "audit")
    stream_entries = [e for e in entries if e["event_type"] == "desanitize_stream"]
    assert len(stream_entries) == 1, "P1-5: gen.close() must trigger audit write"


# --- v0.6.3 P1-4: async OpenAI + sync/async LiteLLM tests ---


def test_openai_async_stream_writes_desanitize_audit_entry(tmp_path):
    """v0.6.3 P1-4: async OpenAI wrapper writes entry on completion."""
    from cloakllm.integrations import openai_middleware

    shield = _setup_shield(tmp_path)
    sanitized, token_map = shield.sanitize("Email jane@acme.com")

    chunks = [
        _MockChunk(content="Hi "),
        _MockChunk(content="[EMAIL_0]", finish_reason="stop"),
    ]

    async def consume():
        agen = openai_middleware._async_stream_wrapper(_mock_stream_async(chunks), "gpt-4", token_map, shield)
        out = []
        async for c in agen:
            out.append(c)
        return out

    asyncio.run(consume())

    entries = _read_audit_entries(tmp_path / "audit")
    stream_entries = [e for e in entries if e["event_type"] == "desanitize_stream"]
    assert len(stream_entries) == 1
    e = stream_entries[0]
    assert "EMAIL" in e["categories"]
    assert e["entity_count"] == token_map.entity_count


def test_litellm_sync_stream_writes_desanitize_audit_entry(tmp_path):
    """v0.6.3 P1-4: LiteLLM sync wrapper writes entry on completion."""
    from cloakllm.integrations import litellm_middleware

    shield = _setup_shield(tmp_path)
    sanitized, token_map = shield.sanitize("Call +1-555-1234")

    chunks = [
        _MockChunk(content="Reaching "),
        _MockChunk(content="[PHONE_0]", finish_reason="stop"),
    ]

    list(litellm_middleware._sync_litellm_stream_wrapper(_mock_stream_sync(chunks), "claude-3", token_map, shield))

    entries = _read_audit_entries(tmp_path / "audit")
    stream_entries = [e for e in entries if e["event_type"] == "desanitize_stream"]
    assert len(stream_entries) == 1
    e = stream_entries[0]
    assert "PHONE" in e["categories"]
    assert e["model"] == "claude-3"


def test_litellm_async_stream_writes_desanitize_audit_entry(tmp_path):
    """v0.6.3 P1-4: LiteLLM async wrapper writes entry on completion."""
    from cloakllm.integrations import litellm_middleware

    shield = _setup_shield(tmp_path)
    sanitized, token_map = shield.sanitize("Email me at user@example.com")

    chunks = [
        _MockChunk(content="Reply to "),
        _MockChunk(content="[EMAIL_0]"),
        _MockChunk(content=".", finish_reason="stop"),
    ]

    async def consume():
        agen = litellm_middleware._async_litellm_stream_wrapper(_mock_stream_async(chunks), "claude-3", token_map, shield)
        out = []
        async for c in agen:
            out.append(c)
        return out

    asyncio.run(consume())

    entries = _read_audit_entries(tmp_path / "audit")
    stream_entries = [e for e in entries if e["event_type"] == "desanitize_stream"]
    assert len(stream_entries) == 1


def test_litellm_sync_stream_audit_on_error(tmp_path):
    """LiteLLM sync wrapper writes entry with stream_error on mid-stream raise."""
    from cloakllm.integrations import litellm_middleware

    shield = _setup_shield(tmp_path)
    sanitized, token_map = shield.sanitize("john@acme.com")

    def err_stream():
        yield _MockChunk(content="bad ")
        raise ValueError("oops")

    with pytest.raises(ValueError, match="oops"):
        list(litellm_middleware._sync_litellm_stream_wrapper(err_stream(), "claude-3", token_map, shield))

    entries = _read_audit_entries(tmp_path / "audit")
    stream_entries = [e for e in entries if e["event_type"] == "desanitize_stream"]
    assert len(stream_entries) == 1
    assert stream_entries[0]["metadata"].get("stream_error") is True
    assert stream_entries[0]["metadata"].get("error_type") == "ValueError"
