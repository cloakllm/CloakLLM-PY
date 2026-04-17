"""
Canonical JSON conformance — verifies the Python serializer produces the exact
expected bytes for every entry in the shared cross-SDK fixture corpus.

The same corpus is consumed by `cloakllm-js/test/test_canonical_consistency.js`.
If the two implementations diverge, cross-language certificate/audit-chain
verification breaks for the divergent input shapes.

The fixture file MUST stay byte-identical between the two repos. CI verifies this.
"""

import json
from pathlib import Path

import pytest

from cloakllm._canonical import canonical_json, _legacy_canonical_json


FIXTURE_PATH = Path(__file__).parent / "fixtures" / "canonical_corpus.json"


def _load_corpus():
    with open(FIXTURE_PATH, encoding="utf-8") as f:
        return json.load(f)


@pytest.mark.parametrize("case", _load_corpus(), ids=lambda c: c["name"])
def test_canonical_json_matches_expected(case):
    actual = canonical_json(case["input"])
    assert actual == case["expected"], (
        f"\n  case:     {case['name']}"
        f"\n  expected: {case['expected']!r}"
        f"\n  actual:   {actual!r}"
    )


def test_canonical_json_rejects_nan():
    with pytest.raises(ValueError):
        canonical_json({"x": float("nan")})


def test_canonical_json_rejects_infinity():
    with pytest.raises(ValueError):
        canonical_json({"x": float("inf")})


def test_canonical_json_non_ascii_preserved_not_escaped():
    """Regression test for B1: ensure_ascii must be False."""
    out = canonical_json({"x": "café"})
    assert "café" in out
    assert "\\u" not in out  # should NOT have unicode escapes


def test_legacy_canonical_json_preserves_v060_behavior():
    """The legacy shim MUST escape non-ASCII (the v0.6.0 bug we're fixing)."""
    out = _legacy_canonical_json({"x": "café"})
    assert "\\u00e9" in out  # legacy escapes


def test_legacy_canonical_json_byte_identical_to_v060_format():
    """Verify the legacy shim output exactly matches what v0.6.0 produced."""
    # Format: sort_keys=True, separators=(",", ":"), ensure_ascii=True (default)
    expected = '{"a":1,"b":"caf\\u00e9"}'
    actual = _legacy_canonical_json({"b": "café", "a": 1})
    assert actual == expected
