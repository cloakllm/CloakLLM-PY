"""v0.13.0 health edition: role-gated and header-line names, and surname
completion for one-word NER names.

Expected values are written out literally. The JS SDK has the same cases in
test/clinical-names.test.js, and the pattern strings are byte-identical
across the SDKs (test_patterns_are_identical_in_js, when node is available).
"""
import glob
import json
import os
import shutil
import subprocess

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.backends.regex import RegexBackend
from cloakllm.clinical_names import (
    HEADER_NAME_PATTERN, ROLE_NAME_PATTERN, extend_first_name,
)
from cloakllm.config import ShieldConfig as _Cfg


@pytest.fixture
def backend():
    return RegexBackend(_Cfg(audit_enabled=False, detect_role_names=True))


def found(backend, text):
    return [(d.category, d.text) for d in sorted(backend.detect(text, []), key=lambda d: d.start)]


@pytest.mark.parametrize("text, expected", [
    ("Patient Hector Vance. Mother Aisha Sato called.",
     [("PERSON", "Hector Vance"), ("PERSON", "Aisha Sato")]),
    ("Lucia Pruitt 876701408 11/02/1950 seen today.",
     [("PERSON", "Lucia Pruitt"), ("SSN", "876701408")]),
    ("PRUITT, LUCIA DOB 11/02/1950", [("PERSON", "PRUITT, LUCIA")]),
    ("Thomas Halvorsen F8437807 1941-07-23 - hypothyroid", [("PERSON", "Thomas Halvorsen")]),
    ("Draft a letter for Aisha Vance (Date of birth: 03/09/1985)", [("PERSON", "Aisha Vance")]),
    ("Seen: Mary Ann Smith DOB 1/2/1960", [("PERSON", "Mary Ann Smith")]),
    ("Pt name: Mary-Ann O'Neil", [("PERSON", "Mary-Ann O'Neil")]),
    ("Father Angus McDonald visited", [("PERSON", "Angus McDonald")]),
    ("Patient Ann Parkinson's daughter", [("PERSON", "Ann Parkinson")]),   # possessive not taken
    ("Name: John Q. Public", [("PERSON", "John Q. Public")]),
    ("Dr. Smith MD reviewed.", [("PERSON", "Smith")]),           # credential trimmed
    ("Signed by Dr. Ana Ruiz, MD", [("PERSON", "Ana Ruiz")]),
    ("Emergency contact: Raj Patel (son)", [("PERSON", "Raj Patel")]),
])
def test_names_are_detected(backend, text, expected):
    assert found(backend, text) == expected


@pytest.mark.parametrize("text", [
    "Patient Reports Chest Pain. Patient Portal access. Patient Education given.",
    "Brand Name Lipitor Tablets",                     # "Name" is a role only with a colon
    "Follow Up 11/02/2025 with labs",                 # template words heading a line
    "Discharge Date 10/02/2025",
    "2 Dr visits; patient tolerated the procedure",   # lowercase after the role
    "Mason Jar Lid 12345",                            # role word inside a word, mid-line
    "started Heart Failure DOBUTAMINE drip",   # label must be a whole word
])
def test_template_words_are_left_alone(backend, text):
    assert found(backend, text) == []


@pytest.mark.parametrize("text, start, end, expected_end", [
    ("Thomas Parkinson asks", 0, 6, 16),        # eponym surname completed
    ("Thomas Parkinson's disease", 0, 6, 6),    # possessive: the disease
    ("Thomas Monday", 0, 6, 6),                 # weekday
    ("Thomas MD", 0, 6, 6),                     # not Capitalised-lower
    ("Thomas Reports pain", 0, 6, 6),           # template word
    ("Thomas Smith Jones", 0, 12, 12),          # already two words
    ("Thomas, Smith", 0, 6, 6),                 # not directly following
])
def test_extend_first_name(text, start, end, expected_end):
    assert extend_first_name(text, start, end) == expected_end


def test_round_trip_and_off_by_default(tmp_path):
    text = "Lucia Pruitt 876701408. Mother Aisha Sato called."
    on = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set(), detect_role_names=True))
    clean, tm = on.sanitize(text)
    # Numbered in pass order: ROLE_NAME runs before HEADER_NAME.
    assert clean == "[PERSON_1] [SSN_0]. Mother [PERSON_0] called."
    assert on.desanitize(clean, tm) == text
    off = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set()))
    assert "Aisha Sato" in off.sanitize(text)[0]


def test_ner_surname_completion_through_a_shield(tmp_path):
    s = Shield(ShieldConfig(log_dir=tmp_path, detect_role_names=True))
    ner = next((b for b in s.detector._backends if b.name == "ner"), None)
    if ner is None or ner.nlp is None:
        pytest.skip("spaCy model not installed")
    clean, _ = s.sanitize("Thomas Parkinson asks whether his Parkinson's disease is worse.")
    assert "Parkinson asks" not in clean
    assert "Parkinson's disease" in clean


class _Ent:
    def __init__(self, start, end, label="PERSON"):
        self.start_char, self.end_char, self.label_ = start, end, label


def _fake_ner(config, ents):
    from cloakllm.backends.ner import NerBackend
    b = NerBackend(config)
    b._tried, b._nlp = True, (lambda text: type("Doc", (), {"ents": ents})())
    return b


def test_surname_completion_never_drops_the_first_name():
    """If an earlier pass already claimed the next word, the NER name stays
    short. Extending into the claimed span would make the overlap check drop
    the WHOLE detection -- and leak the first name."""
    text = "Thomas Parkinson asks"
    cfg = _Cfg(audit_enabled=False, detect_role_names=True)
    dets = _fake_ner(cfg, [_Ent(0, 6)]).detect(text, [(7, 16)])
    assert [(d.category, d.text) for d in dets] == [("PERSON", "Thomas")]
    dets = _fake_ner(cfg, [_Ent(0, 6)]).detect(text, [])
    assert [(d.category, d.text) for d in dets] == [("PERSON", "Thomas Parkinson")]
    off = _Cfg(audit_enabled=False)
    assert [d.text for d in _fake_ner(off, [_Ent(0, 6)]).detect(text, [])] == ["Thomas"]


def test_no_name_in_the_audit_log(tmp_path):
    Shield(ShieldConfig(log_dir=tmp_path, detect_role_names=True)).sanitize(
        "Lucia Pruitt 876701408. Patient Hector Vance. Thomas Parkinson asks.")
    raw = "".join(open(f, encoding="utf-8").read() for f in glob.glob(os.path.join(tmp_path, "*.jsonl")))
    assert raw
    for planted in ("Pruitt", "Vance", "Hector", "Parkinson"):
        assert planted not in raw, planted


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_patterns_are_identical_in_js():
    js = os.path.join(os.path.dirname(__file__), "..", "..", "cloakllm-js", "src", "clinical-names.js")
    if not os.path.exists(js):
        pytest.skip("sibling cloakllm-js checkout not present")
    mod = json.dumps(os.path.abspath(js))
    out = subprocess.run(
        ["node", "-e", f"const m=require({mod});process.stdout.write(JSON.stringify([m.ROLE_NAME_PATTERN,m.HEADER_NAME_PATTERN]))"],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == [ROLE_NAME_PATTERN, HEADER_NAME_PATTERN]
