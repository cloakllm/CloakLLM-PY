"""v0.11.5: streaming desanitize must byte-equal batch desanitize for EVERY
chunking.

Regression guard for the StreamDesanitizer fullwidth-escape bug: when the
user's own text contained a literal [CATEGORY_N]-style token, sanitize escaped
it to FULLWIDTH brackets, and the stream emitted the escaped sequence in
fragments so _unescape never saw a whole [...] to convert back. The fuzz found
401/3216 mismatches, ALL on that injection case; normal PII was 100% clean.
The fix buffers fullwidth brackets across chunk boundaries too.
"""
from __future__ import annotations

import random

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.stream import StreamDesanitizer


@pytest.fixture(scope="module")
def shield():
    return Shield(ShieldConfig(audit_enabled=False))


TEXTS = [
    "[EMAIL_0] starts the line; ends with a@b.com",      # the injection case
    "Email a@b.com and SSN 123-45-6789 now.",
    "adjacent a@b.com c@d.com e@f.com tight",
    "two literals [PERSON_1] and [EMAIL_0], real x@y.com",
    "unicode cafe [SSN_0] resume jose@example.es end",
    "[TOKEN_LIKE_9] not a real token, email z@z.io",
]


def test_streaming_equals_batch_random_chunkings(shield):
    rng = random.Random(0xC0FFEE)
    for text in TEXTS:
        san, tm = shield.sanitize(text)
        batch = shield.desanitize(san, tm)
        for _ in range(300):
            sd = StreamDesanitizer(tm)
            out, i = [], 0
            while i < len(san):
                sz = rng.randint(1, 4)
                out.append(sd.feed(san[i:i + sz]))
                i += sz
            streamed = "".join(out) + sd.flush()
            assert streamed == batch, f"streamed != batch for {text!r}: {streamed!r}"


def test_streaming_equals_batch_extreme_chunkings(shield):
    for text in TEXTS:
        san, tm = shield.sanitize(text)
        batch = shield.desanitize(san, tm)
        for chunks in ([san], list(san)):  # whole-string + char-by-char
            sd = StreamDesanitizer(tm)
            streamed = "".join(sd.feed(c) for c in chunks) + sd.flush()
            assert streamed == batch


def test_injection_literal_roundtrips_streamed(shield):
    # the headline repro: a literal [EMAIL_0] in the user's text survives as a
    # LITERAL (never replaced with PII) in both batch and streamed paths.
    text = "[EMAIL_0] starts; ends a@b.com"
    san, tm = shield.sanitize(text)
    sd = StreamDesanitizer(tm)
    streamed = "".join(sd.feed(san[i:i + 2]) for i in range(0, len(san), 2)) + sd.flush()
    assert streamed == shield.desanitize(san, tm) == text
