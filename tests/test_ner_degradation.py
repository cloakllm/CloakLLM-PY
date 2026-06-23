"""v0.11.3: NER backend degrades gracefully when spaCy is unavailable/broken.

Regression guard for the resilience gap found during v0.11.2 Step 7: a spaCy
install that is present but broken (e.g. missing a transitive dep) raised
ImportError out of sanitize(), taking down PII protection that regex still
provides. NER is now best-effort: fail-open (regex-only + loud warning) by
default, fail-closed via ner_required=True.
"""
from __future__ import annotations

import sys
import warnings

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.backends.ner import NerBackend


def _break_spacy(monkeypatch):
    # `import spacy` with None in sys.modules raises ImportError -> simulates an
    # absent OR broken spaCy without uninstalling it.
    monkeypatch.setitem(sys.modules, "spacy", None)


def test_broken_spacy_degrades_not_raises(monkeypatch):
    _break_spacy(monkeypatch)
    backend = NerBackend(ShieldConfig(audit_enabled=False))
    with pytest.warns(RuntimeWarning, match="NER unavailable"):
        out = backend.detect("Contact Jane Doe at a@b.com", [])
    assert out == []  # no exception escaped; NER simply contributed nothing


def test_regex_still_protects_when_ner_broken(monkeypatch):
    _break_spacy(monkeypatch)
    shield = Shield(ShieldConfig(audit_enabled=False))
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")
        out, _ = shield.sanitize("email me at secret.person@example.com please")
    assert "[EMAIL_0]" in out and "secret.person@example.com" not in out


def test_ner_required_hard_fails_when_broken(monkeypatch):
    _break_spacy(monkeypatch)
    shield = Shield(ShieldConfig(audit_enabled=False, ner_required=True))
    with pytest.raises(RuntimeError, match="NER is required"):
        shield.sanitize("Contact Jane Doe at the office")


def test_degradation_is_one_time(monkeypatch):
    _break_spacy(monkeypatch)
    backend = NerBackend(ShieldConfig(audit_enabled=False))
    with pytest.warns(RuntimeWarning):
        backend.detect("first call", [])
    # second call must not raise and must not re-warn (cached _tried)
    with warnings.catch_warnings():
        warnings.simplefilter("error")  # any warning -> error
        assert backend.detect("second call", []) == []


def test_working_spacy_still_detects_person():
    # regression: with a healthy spaCy + model, NER still fires.
    shield = Shield(ShieldConfig(audit_enabled=False))
    if shield.detector._nlp is None and NerBackend(shield.config).nlp is None:
        pytest.skip("spaCy model not available in this environment")
    out, _ = shield.sanitize("Please escalate to Margaret Thatcher today")
    assert "[PERSON_0]" in out
