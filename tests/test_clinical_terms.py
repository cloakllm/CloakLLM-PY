"""v0.13.0 health edition: the clinical-term veto for NER.

The veto may only make CloakLLM remove LESS, so every case that must still
be removed (a name next to a term, an all-caps header, a non-ASCII name) is
written out here. The JS SDK runs the same cases (test_js_agrees_on_every_case)
and has the same vocabulary (test_lists_and_patterns_are_identical_in_js).
"""
import json
import os
import shutil
import subprocess

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm import clinical_terms as ct
from cloakllm.config import ShieldConfig as _Cfg


def _case(text, span, expected, nth=0):
    start = -1
    for _ in range(nth + 1):
        start = text.index(span, start + 1)
    return (text, start, start + len(span), expected)


CASES = [
    # vetoed: clinical vocabulary, alone or with numbers/units
    _case("My INR was 3.5 yesterday", "INR", True),
    _case("Hx COPD, on furosemide", "Hx COPD", True),
    _case("LDL 138.0 mg/dL, order placed", "LDL 138.0", True),
    _case("Should we add a GLP-1 agent?", "GLP-1", True),
    _case("Statin started last month", "Statin", True),
    _case("Please include current apixaban dose.", "apixaban", True),
    _case("DOB 03/09/1985", "DOB", True),
    _case("Seen in the ED yesterday", "ED", True),
    # vetoed: the eponym inside a disease name
    _case("History of Crohn's disease and COPD", "Crohn", True),
    _case("their Graves' disease is stable", "Graves", True),
    _case("History of Cushing syndrome", "Cushing", True),
    _case("Mother had Bell's palsy", "Bell", True),
    _case("their Addison's disease affects", "Addison's", True),   # compromise keeps the 's
    _case("Mr. Addison's daughter called", "Addison's", False),
    # NOT vetoed: a name, or anything that might be one
    _case("Mr. Parkinson asks about his meds", "Parkinson", False),
    _case("Have Smith sign the consent", "Smith", False),
    _case("Dr Bell's office called", "Bell", False),
    _case("Janet INR was high", "Janet INR", False),
    _case("ED SMITH 12345", "ED", False),                    # all-caps header
    _case("SMITH ED 12345", "ED", False),
    _case("JANE DOE 1/2/1960", "DOE", False),                # all-caps header guard
    _case("Seen by Dr. DOE today", "DOE", False),            # DOE is a surname, not vocabulary
    _case("Ace Ventura", "Ace", False),                      # abbreviations are case-sensitive
    _case("Ms Smith", "Ms", False),
    _case("Room 4122", "4122", False),                       # numbers alone: not ours to veto
    _case("INR Zoë", "INR Zoë", False),             # non-ASCII letter: fail closed
    _case("INR 张伟", "INR 张伟", False),
]
IDS = [f"{i}-{'veto' if c[3] else 'keep'}" for i, c in enumerate(CASES)]


@pytest.mark.parametrize("text, start, end, expected", CASES, ids=IDS)
def test_is_clinical_span(text, start, end, expected):
    assert ct.is_clinical_span(text, start, end) is expected


class _Ent:
    def __init__(self, start, end, label):
        self.start_char, self.end_char, self.label_ = start, end, label


def _ner(config, ents):
    from cloakllm.backends.ner import NerBackend
    b = NerBackend(config)
    b._tried, b._nlp = True, (lambda text: type("Doc", (), {"ents": ents})())
    return b


def test_veto_applies_to_ner_only_and_only_when_switched_on():
    text = "Janet Novak. My INR was 3.5"
    ents = [_Ent(0, 11, "PERSON"), _Ent(16, 19, "ORG")]
    on = _ner(_Cfg(audit_enabled=False, protect_clinical_terms=True), ents).detect(text, [])
    assert [d.text for d in on] == ["Janet Novak"]
    off = _ner(_Cfg(audit_enabled=False), ents).detect(text, [])
    assert [d.text for d in off] == ["Janet Novak", "INR"]


def test_regex_detections_are_never_vetoed(tmp_path):
    # MRN is vocabulary, but a regex hit on the VALUE after it is untouched;
    # a custom pattern that claims a vocabulary word is the user's call.
    s = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set(), protect_clinical_terms=True,
                            detect_us_health_ids=True, custom_patterns=[("DRUG", r"\bapixaban\b")]))
    clean, _ = s.sanitize("MRN 48213377, on apixaban")
    assert clean == "MRN [MRN_0], on [DRUG_0]"


def test_through_a_shield_with_real_ner(tmp_path):
    s = Shield(ShieldConfig(log_dir=tmp_path, protect_clinical_terms=True))
    ner = next((b for b in s.detector._backends if b.name == "ner"), None)
    if ner is None or ner.nlp is None:
        pytest.skip("spaCy model not installed")
    text = "Hi, this is Janet Novak. My INR was 3.5 and my Crohn's disease is worse."
    clean, _ = s.sanitize(text)
    assert "Janet" not in clean and "Novak" not in clean
    assert "INR" in clean and "Crohn's disease" in clean


def _node(script):
    js = os.path.join(os.path.dirname(__file__), "..", "..", "cloakllm-js", "src", "clinical-terms.js")
    if shutil.which("node") is None or not os.path.exists(js):
        pytest.skip("node or sibling cloakllm-js checkout not present")
    code = f"const m=require({json.dumps(os.path.abspath(js))});" + script
    out = subprocess.run(["node", "-e", code], stdin=subprocess.DEVNULL, capture_output=True,
                         check=True).stdout
    return json.loads(out.decode("utf-8"))


def test_lists_and_patterns_are_identical_in_js():
    names = ["ABBREVIATIONS", "TERMS", "UNITS", "DISEASE_WORDS", "EPONYM_WORD_PATTERN",
             "EPONYM_TAIL_PATTERN", "TOKEN_PATTERN", "NUMBER_PATTERN", "CAPS_BEFORE_PATTERN",
             "CAPS_AFTER_PATTERN"]
    js = _node(f"process.stdout.write(JSON.stringify({json.dumps(names)}.map((n)=>m[n])))")
    py = [list(v) if isinstance(v, tuple) else v for v in (getattr(ct, n) for n in names)]
    assert js == py


def test_js_agrees_on_every_case():
    cases = json.dumps([[t, s, e] for t, s, e, _ in CASES])
    js = _node(f"process.stdout.write(JSON.stringify({cases}.map(([t,s,e])=>m.isClinicalSpan(t,s,e))))")
    assert js == [c[3] for c in CASES]
