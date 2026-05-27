"""v0.7.1 C7.1-1: minimal ULID generator (no runtime dep).

ULID (Universally Unique Lexicographically Sortable Identifier) -- 128 bits
total, encoded as a 26-character base32-Crockford string. First 48 bits are a
millisecond timestamp; the remaining 80 bits are cryptographically random.

Why ULID over UUID4 for `decision_id`:
  * 26 chars vs 36 (UUID4): smaller in JSONL audit logs at high volume
  * Lexicographically sortable by creation time -- auditors can sort
    `decision_id`s and get chronological order without parsing timestamps
  * Recognizable shape distinct from `event_id` (UUID4) -- at-a-glance
    distinguishes "per-decision audit anchor" from "per-entry write id"

Why ULID over UUID v7 (which has the same time-prefix property):
  * Smaller wire size (26 vs 36 chars)
  * No hyphens -- survives transport that mangles UUID dashes

References:
  * https://github.com/ulid/spec
  * https://github.com/oklog/ulid (reference Go implementation we mirror)

This module is intentionally NOT a full ULID implementation. We don't parse,
we don't decode timestamps from existing ULIDs, we don't enforce monotonicity
across calls in the same millisecond. We only generate. If callers need richer
ULID features, they can supply their own `decision_id` string -- CloakLLM
accepts any <= 64-char string.
"""

from __future__ import annotations

import os
import time

# Crockford's base32: removes I, L, O, U to avoid visual ambiguity
_CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

# Public format: 26 chars exactly (10 chars timestamp + 16 chars randomness)
ULID_LENGTH = 26


def generate_ulid() -> str:
    """Generate a fresh ULID -- 26-char Crockford-base32 string.

    First 10 chars encode milliseconds-since-epoch (48 bits).
    Last 16 chars are CSPRNG randomness (80 bits).

    Not monotonic within a single millisecond -- two ULIDs generated in the
    same ms will sort by their random suffix, not by call order. Acceptable
    for audit decision_id where exact intra-ms ordering doesn't matter.
    """
    timestamp_ms = int(time.time() * 1000) & ((1 << 48) - 1)
    rand_bits = int.from_bytes(os.urandom(10), "big")  # 80 bits

    # Combine: 48-bit ts in the high bits, 80-bit rand in the low bits
    full = (timestamp_ms << 80) | rand_bits

    # Encode as 26 chars Crockford-base32 from MSB to LSB
    chars = []
    for i in range(ULID_LENGTH - 1, -1, -1):
        chars.append(_CROCKFORD[(full >> (i * 5)) & 0x1F])
    return "".join(chars)


def is_valid_decision_id(value: str) -> bool:
    """Validate a `decision_id` candidate. Returns True if acceptable.

    Acceptance criteria (loose by design -- callers may supply existing IDs
    from upstream systems like UUID, integer keys, opaque tokens):
      * Non-empty string
      * Length 1..64 inclusive (the AuditEntry B3 cap)
      * No NUL bytes, no control characters
      * ASCII-printable (rejects bidi-formatting + other display-spoofing)
    """
    if not isinstance(value, str):
        return False
    if not 1 <= len(value) <= 64:
        return False
    for c in value:
        if ord(c) < 0x20 or ord(c) > 0x7E:
            return False
    return True
