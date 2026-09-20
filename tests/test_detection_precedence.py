"""Pass ordering in the detection pipeline is precedence.

A pass that claims a span keeps it, so the order of regex / LLM / NER decides
which category a value ends up labelled with. Until 2026-09-20 the order was
regex -> NER -> LLM, which meant a probabilistic name guess could take a span
out from under a category the USER had explicitly configured.

Found in the JS SDK, where compromise tags "PAT" in "Patient PAT-12345" as a
person and the custom PATIENT_ID category never got the span. Python had the
identical flaw and simply needed a different input to show it: spaCy is more
conservative about "PAT", but claims "John Smith-99" as one PERSON.

Nothing leaked either way -- the value is still tokenised -- but the person
asked for PATIENT_ID and silently got PERSON, which corrupts entity_details
and anything downstream keyed on the category.

These tests exercise the whole Shield, not LlmDetector on its own. The
pre-existing custom-category tests called the detector directly, which is
exactly why they could never see an ordering bug: there was no pipeline.
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.backends.ner import NerBackend


def _mock_http(entities):
    """Mock Ollama: /api/tags healthy, chat returns these entities."""
    def _open(req, timeout=None):
        url = req.full_url if hasattr(req, "full_url") else req.get_full_url()
        resp = MagicMock()
        if "/api/tags" in url:
            resp.read.return_value = b'{"models":[]}'
        else:
            resp.read.return_value = json.dumps(
                {"message": {"content": json.dumps({"entities": entities})}}
            ).encode()
        return resp
    return _open


def _ner_available(cfg) -> bool:
    try:
        return bool(NerBackend(cfg).detect("John Smith is here.", []))
    except Exception:
        return False


TEXT = "Patient John Smith-99 was admitted"
VALUE = "John Smith-99"


def test_ner_would_claim_the_span_on_its_own():
    """The premise. Without this the precedence test proves nothing."""
    cfg = ShieldConfig(audit_enabled=False)
    if not _ner_available(cfg):
        pytest.skip("spaCy model not installed")
    claims = NerBackend(cfg).detect(TEXT, [])
    assert any(d.category == "PERSON" and VALUE in d.text for d in claims), (
        "spaCy no longer claims this span, so the regression guard below is "
        "vacuous -- pick an input it does claim"
    )


def test_custom_category_outranks_a_ner_guess():
    cfg = ShieldConfig(
        audit_enabled=False,
        llm_detection=True,
        custom_llm_categories=[("PATIENT_ID", "Hospital patient ID")],
    )
    if not _ner_available(cfg):
        pytest.skip("spaCy model not installed")

    shield = Shield(cfg)
    with patch(
        "cloakllm.llm_detector.LlmDetector._http_open",
        side_effect=_mock_http([{"value": VALUE, "category": "PATIENT_ID"}]),
    ):
        sanitized, token_map = shield.sanitize(TEXT)

    assert "[PATIENT_ID_0]" in sanitized, (
        f"the user's own category must win over a NER guess: {sanitized}"
    )
    assert "[PERSON_" not in sanitized, f"NER shadowed the custom category: {sanitized}"
    assert VALUE not in sanitized

    restored = shield.desanitize("Record for [PATIENT_ID_0]", token_map)
    assert VALUE in restored


def test_ner_still_gets_names_the_llm_does_not_claim():
    """Reordering must not cost NER its own categories.

    The LLM pass excludes PERSON/ORG/GPE by prompt, so moving it ahead of NER
    cannot let it steal them -- but that is the kind of thing worth asserting
    rather than reasoning about.
    """
    cfg = ShieldConfig(
        audit_enabled=False,
        llm_detection=True,
        custom_llm_categories=[("PATIENT_ID", "Hospital patient ID")],
    )
    if not _ner_available(cfg):
        pytest.skip("spaCy model not installed")

    shield = Shield(cfg)
    with patch(
        "cloakllm.llm_detector.LlmDetector._http_open",
        side_effect=_mock_http([]),
    ):
        sanitized, _ = shield.sanitize("Sarah Johnson approved the transfer")

    assert "[PERSON_0]" in sanitized, sanitized


def test_regex_still_outranks_everything():
    """Regex is structural and stays first."""
    cfg = ShieldConfig(audit_enabled=False)
    shield = Shield(cfg)
    sanitized, _ = shield.sanitize("Mail John Smith at john@example.com")
    assert "[EMAIL_0]" in sanitized
    assert "john@example.com" not in sanitized
