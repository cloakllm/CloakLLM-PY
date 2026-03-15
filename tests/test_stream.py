"""Tests for StreamDesanitizer incremental streaming desanitization."""

import pytest
from cloakllm.tokenizer import TokenMap
from cloakllm.stream import StreamDesanitizer


def _make_token_map(**mappings):
    """Helper: create a TokenMap with given forward/reverse mappings.

    Usage: _make_token_map(**{"john@acme.com": "[EMAIL_0]", "John Smith": "[PERSON_0]"})
    """
    tm = TokenMap()
    for original, token in mappings.items():
        tm.forward[original] = token
        tm.reverse[token] = original
    return tm


class TestStreamDesanitizerBasic:
    def test_plain_text_passthrough(self):
        tm = _make_token_map(**{"john@acme.com": "[EMAIL_0]"})
        sd = StreamDesanitizer(tm)
        assert sd.feed("Hello world") == "Hello world"
        assert sd.flush() == ""

    def test_basic_streaming(self):
        tm = _make_token_map(**{"john@acme.com": "[EMAIL_0]"})
        sd = StreamDesanitizer(tm)
        assert sd.feed("Contact ") == "Contact "
        assert sd.feed("[EM") == ""
        assert sd.feed("AIL_0]") == "john@acme.com"
        assert sd.feed(" for details") == " for details"
        assert sd.flush() == ""

    def test_non_token_brackets(self):
        tm = TokenMap()
        sd = StreamDesanitizer(tm)
        assert sd.feed("array[0]") == "array[0]"

    def test_split_across_chunks(self):
        tm = _make_token_map(**{"John Smith": "[PERSON_0]"})
        sd = StreamDesanitizer(tm)
        assert sd.feed("Hi ") == "Hi "
        assert sd.feed("[") == ""
        assert sd.feed("PERSON") == ""
        assert sd.feed("_0") == ""
        assert sd.feed("]!") == "John Smith!"


class TestStreamDesanitizerEdgeCases:
    def test_case_insensitive(self):
        tm = _make_token_map(**{"jane@test.com": "[EMAIL_0]"})
        sd = StreamDesanitizer(tm)
        assert sd.feed("[email_0]") == "jane@test.com"

    def test_multiple_tokens(self):
        tm = _make_token_map(**{
            "john@acme.com": "[EMAIL_0]",
            "John Smith": "[PERSON_0]",
        })
        sd = StreamDesanitizer(tm)
        result = sd.feed("Hi [PERSON_0], your email is [EMAIL_0].")
        assert result == "Hi John Smith, your email is john@acme.com."
        assert sd.flush() == ""

    def test_flush_partial_buffer(self):
        tm = _make_token_map(**{"john@acme.com": "[EMAIL_0]"})
        sd = StreamDesanitizer(tm)
        assert sd.feed("text [UNKN") == "text "
        assert sd.flush() == "[UNKN"

    def test_max_buffer_overflow(self):
        tm = TokenMap()
        sd = StreamDesanitizer(tm)
        # Feed a [ followed by > 40 chars without ]
        long_text = "[" + "A" * 50
        result = sd.feed(long_text)
        # Should flush incrementally — all 51 chars emitted
        assert len(result) == 51
        assert sd.flush() == ""

    def test_empty_input(self):
        tm = _make_token_map(**{"john@acme.com": "[EMAIL_0]"})
        sd = StreamDesanitizer(tm)
        assert sd.feed("") == ""
        assert sd.flush() == ""

    def test_token_at_stream_end(self):
        tm = _make_token_map(**{"john@acme.com": "[EMAIL_0]"})
        sd = StreamDesanitizer(tm)
        assert sd.feed("Contact [EMAIL_0]") == "Contact john@acme.com"
        assert sd.flush() == ""

    def test_consecutive_tokens(self):
        tm = _make_token_map(**{
            "john@acme.com": "[EMAIL_0]",
            "Jane Doe": "[PERSON_0]",
        })
        sd = StreamDesanitizer(tm)
        assert sd.feed("[EMAIL_0][PERSON_0]") == "john@acme.comJane Doe"

    def test_bracket_in_normal_text(self):
        tm = _make_token_map(**{"john@acme.com": "[EMAIL_0]"})
        sd = StreamDesanitizer(tm)
        result = sd.feed("Use array[0] and list[1] for indexing")
        assert result == "Use array[0] and list[1] for indexing"

    def test_mixed_tokens_and_brackets(self):
        tm = _make_token_map(**{"john@acme.com": "[EMAIL_0]"})
        sd = StreamDesanitizer(tm)
        result = sd.feed("array[0] then [EMAIL_0] then obj[key]")
        assert result == "array[0] then john@acme.com then obj[key]"
