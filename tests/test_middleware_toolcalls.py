"""v0.11.4: middleware must sanitize PII in tool-call arguments (outbound) and
restore it (inbound), and enable() must print ASCII only.

Regression guard for the HIGH finding from the middleware multi-choice/tool-call
probe: _sanitize_messages only sanitized message `content`, so PII inside
assistant tool_calls[].function.arguments reached the provider verbatim in
multi-turn tool-use history. Also guards the emoji-print crash on non-UTF-8
consoles (the banner is now ASCII).
"""
from __future__ import annotations

import contextlib
import io
import json

import pytest

import cloakllm
from cloakllm import ShieldConfig
from cloakllm.integrations import openai_middleware as M


class _Fn:
    def __init__(self, name, args): self.name = name; self.arguments = args
class _TC:
    def __init__(self, args): self.id = "1"; self.type = "function"; self.function = _Fn("send", args)
class _Msg:
    def __init__(self, content, tool_calls=None): self.content = content; self.tool_calls = tool_calls
class _Choice:
    def __init__(self, content, tool_calls=None): self.message = _Msg(content, tool_calls)
class _Resp:
    def __init__(self, choices): self.choices = choices


def _make_client(capture, n_choices=2):
    class _Completions:
        def create(self, **kw):
            capture["messages"] = kw["messages"]
            sent_args = None
            for m in kw["messages"]:
                for tc in (m.get("tool_calls") or []):
                    sent_args = tc["function"]["arguments"]
            return _Resp([_Choice("ok", [_TC(sent_args)]) for _ in range(n_choices)])
    class _Chat:
        def __init__(self): self.completions = _Completions()
    class _Client:
        def __init__(self): self.chat = _Chat()
    return _Client()


@pytest.fixture(autouse=True)
def _quiet_enable(monkeypatch):
    # keep enable()'s banner out of the test log; the ASCII test captures it itself
    yield


def test_toolcall_args_sanitized_outbound_and_restored_in_all_choices():
    cap = {}
    client = _make_client(cap, n_choices=3)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cloakllm.enable_openai(client, ShieldConfig(audit_enabled=False))
    try:
        resp = client.chat.completions.create(model="gpt-4o", messages=[{
            "role": "assistant", "content": None,
            "tool_calls": [{"id": "1", "type": "function", "function": {
                "name": "send",
                "arguments": '{"to":"victim@example.com","ssn":"123-45-6789"}'}}]}])
        sent = json.dumps(cap["messages"])
        assert "victim@example.com" not in sent and "123-45-6789" not in sent, \
            "PII in tool_call arguments reached the provider"
        for ch in resp.choices:
            args = ch.message.tool_calls[0].function.arguments
            assert "victim@example.com" in args and "123-45-6789" in args, \
                "tool_call arguments not restored for a choice"
    finally:
        if hasattr(cloakllm, "disable_openai"):
            cloakllm.disable_openai(client)


def test_enable_banner_is_ascii_only():
    client = _make_client({})
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cloakllm.enable_openai(client, ShieldConfig(audit_enabled=False))
    if hasattr(cloakllm, "disable_openai"):
        cloakllm.disable_openai(client)
    out = buf.getvalue()
    assert out.isascii(), f"enable() banner has non-ASCII (crashes cp1255/cp932 consoles): {out!r}"


def test_legacy_function_call_arguments_sanitized():
    cap = {}
    client = _make_client(cap)
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        cloakllm.enable_openai(client, ShieldConfig(audit_enabled=False))
    try:
        client.chat.completions.create(model="gpt-4o", messages=[{
            "role": "assistant", "content": None,
            "function_call": {"name": "send", "arguments": '{"email":"x@y.com"}'}}])
        assert "x@y.com" not in json.dumps(cap["messages"])
    finally:
        if hasattr(cloakllm, "disable_openai"):
            cloakllm.disable_openai(client)
