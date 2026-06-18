"""
Canonical JSON serializer — single source of truth for hash/signature input.

Produces byte-identical output across Python and JavaScript SDKs. Used by:
- audit.py for the hash chain (`_compute_hash`)
- attestation.py for Ed25519 signature payloads (`_canonical_json`)

Properties:
- Sorted keys at every nesting level (lexicographic by Python's default str compare)
- No whitespace (separators=(",", ":"))
- ensure_ascii=False — UTF-8 preserved (matches JS `JSON.stringify` behavior)
- allow_nan=False — NaN/Infinity rejected (incompatible with strict JSON anyway)
- Object keys MUST be strings (rejects integer keys)

History: `_legacy_canonical_json` (the v0.6.0 `ensure_ascii=True` variant)
was REMOVED in v0.9.0 (LC-1 phase 2), completing the sunset announced in
v0.7.1 phase 1. Pre-v0.6.1 chains with non-ASCII content must be
re-archived under a v0.6.1..v0.8.x release. One canonicalizer, one hash
semantics.
"""

from __future__ import annotations

import json
from typing import Any


# v0.10.3 HIGH-5 (cross-SDK integrity): the JS canonicalizer rejects these
# object key names; Python must reject them too, or the same logical object
# hashes to different bytes in the two SDKs (Python's json.dumps would happily
# serialize "constructor" as a key, JS would not). These names never occur in
# legitimate hashed/attestation data (the audit schema validators block them
# upstream), so a hard error is safe and keeps the two canonicalizers in lock-step.
_FORBIDDEN_CANONICAL_KEYS = frozenset({"__proto__", "constructor", "prototype"})


def _reject_forbidden_keys(obj: Any) -> None:
    """Recursively raise if any dict key is a prototype-pollution vector."""
    if isinstance(obj, dict):
        for k in obj:
            if k in _FORBIDDEN_CANONICAL_KEYS:
                raise ValueError(
                    f"canonical_json: disallowed object key {k!r} "
                    f"(prototype-pollution vector; not permitted in canonical output)"
                )
            _reject_forbidden_keys(obj[k])
    elif isinstance(obj, (list, tuple)):
        for item in obj:
            _reject_forbidden_keys(item)


def canonical_json(obj: Any) -> str:
    """
    Canonical JSON encoding for cross-SDK hash/signature consistency.

    Raises:
        ValueError: if obj contains non-finite floats (NaN, +Inf, -Inf),
                    non-string object keys, or a prototype-pollution key name
                    (__proto__ / constructor / prototype) -- the last so Python
                    and JS canonical bytes never diverge on those keys.
    """
    _reject_forbidden_keys(obj)
    # json.dumps with allow_nan=False raises on NaN/Inf. ensure_ascii=False
    # keeps UTF-8 bytes (matches JS JSON.stringify output).
    return json.dumps(
        obj,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )
