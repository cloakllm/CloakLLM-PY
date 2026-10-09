"""v0.13.0 health edition: clinical dates and ages over 89 (HIPAA Safe Harbor).

Expected values are written out literally -- never computed by the code under
test. The JS SDK has the same cases in test/clinical-dates.test.js.
"""
import glob
import os

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.backends.regex import RegexBackend
from cloakllm.config import ShieldConfig as _Cfg


@pytest.fixture
def backend():
    return RegexBackend(_Cfg(audit_enabled=False, detect_dates=True, detect_ages_over_89=True))


def found(backend, text):
    return [(d.category, d.text) for d in sorted(backend.detect(text, []), key=lambda d: d.start)]


# ------------------------------------------------------------------ dates --

@pytest.mark.parametrize("text, expected", [
    ("Admitted 03/14/2026, discharged 3/21/26.", [("DATE", "03/14/2026"), ("DATE", "3/21/26")]),
    ("Seen 2026-03-14; f/u 4/2.", [("DATE", "2026-03-14"), ("DATE", "4/2")]),
    ("DOB: March 14, 1961. Surgery on 14 March 2026.",
     [("DATE", "March 14, 1961"), ("DATE", "14 March 2026")]),
    ("Symptoms since Feb 2026, last visit Jan 5th.", [("DATE", "Feb 2026"), ("DATE", "Jan 5th")]),
    ("dated 12-31-1999, LMP 1/15", [("DATE", "12-31-1999"), ("DATE", "1/15")]),
    ("On 2/29/2024 and Sept. 3rd, 2025", [("DATE", "2/29/2024"), ("DATE", "Sept. 3rd, 2025")]),
    ("started 03/2026", [("DATE", "03/2026")]),
])
def test_dates_are_detected(backend, text, expected):
    assert found(backend, text) == expected


@pytest.mark.parametrize("text", [
    "BP 120/80, strength 5/5 in all limbs, pain 4/10, take 1/2 tab, vision 20/20.",
    "HbA1c 8.9%, eGFR 52.4, version 1.2.3, order 2026091712.",
    "The patient may need it; March forward. 2/2 PNA.",
    "Feb 30 2026 is not a date, nor is 13/14/2026.",
    "f/u 4/2.5 mg",                # a number, not a date
    "s/p CABG 2019",               # year only is allowed under Safe Harbor
    "3/14 of patients improved",   # year-less, no date word before it
])
def test_clinical_look_alikes_are_left_alone(backend, text):
    assert found(backend, text) == []


# ------------------------------------------------------------------- ages --

def test_ages_over_89_in_every_form(backend):
    text = "93-year-old woman, aged 95, 92M, 91 yo F, in her late 90s, a nonagenarian."
    assert found(backend, text) == [
        ("AGE_90PLUS", "93-year-old"), ("AGE_90PLUS", "aged 95"), ("AGE_90PLUS", "92M"),
        ("AGE_90PLUS", "91 yo"), ("AGE_90PLUS", "in her late 90s"), ("AGE_90PLUS", "nonagenarian"),
    ]


@pytest.mark.parametrize("text", ["45-year-old man, aged 67.", "89 yo F", "temp 98 F", "T 99F"])
def test_ages_under_90_and_temperatures_are_left_alone(backend, text):
    assert found(backend, text) == []


def test_surname_ending_in_t_does_not_hide_an_age(backend):
    # The temperature guard once matched any word ending in "t". Found by the
    # clinical benchmark: "Ellen Lindqvist, 95-year-old" was missed.
    assert found(backend, "Ellen Lindqvist, 95-year-old") == [("AGE_90PLUS", "95-year-old")]


# ------------------------------------------------------------ output modes --

NOTE = "93-year-old admitted 03/14/2026, discharged 3/21/26, DOB March 14, 1931."


def _shield(tmp_path, **kw):
    return Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set(),
                               detect_dates=True, detect_ages_over_89=True, **kw))


def test_tokenize_mode_round_trips(tmp_path):
    shield = _shield(tmp_path)
    clean, tm = shield.sanitize(NOTE)
    assert clean == "[AGE_90PLUS_0] admitted [DATE_2], discharged [DATE_1], DOB [DATE_0]."
    assert shield.desanitize(clean, tm) == NOTE


def test_generalize_year_mode_is_the_safe_harbor_form(tmp_path):
    shield = _shield(tmp_path, date_mode="generalize_year")
    clean, tm = shield.sanitize(NOTE)
    assert clean == "90+-year-old admitted 2026, discharged [DATE_REDACTED], DOB 1931."
    # Irreversible: nothing stored, nothing restored.
    assert tm.reverse == {}
    assert shield.desanitize(clean, tm) == clean
    # entity_details names the category, never the value or its year.
    assert {e["token"] for e in tm.entity_details} == {"[DATE_GENERALIZED]", "[AGE_90PLUS_GENERALIZED]"}


def test_redact_mode_wins_over_generalize(tmp_path):
    shield = _shield(tmp_path, date_mode="generalize_year", mode="redact")
    clean, _ = shield.sanitize("admitted 03/14/2026")
    assert clean == "admitted [DATE_REDACTED]"


def test_date_shifting_is_refused_with_the_reason():
    with pytest.raises(ValueError, match="Safe Harbor"):
        ShieldConfig(date_mode="shift")


# ------------------------------------------------------------- compatibility --

def test_off_by_default(tmp_path):
    shield = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set()))
    clean, _ = shield.sanitize(NOTE)
    assert clean == NOTE


def test_custom_pattern_named_date_still_allowed():
    # DATE became a built-in in v0.13.0; a user's existing custom DATE pattern
    # must not start raising on upgrade.
    ShieldConfig(custom_patterns=[("DATE", r"\d{8}")])
    ShieldConfig(custom_llm_categories=[("AGE_90PLUS", "an age over 89")])


def test_no_dates_or_ages_in_the_audit_log(tmp_path):
    shield = _shield(tmp_path)
    shield.sanitize("93-year-old admitted 03/14/2026, DOB March 14, 1931, f/u 4/2.")
    raw = "".join(open(f, encoding="utf-8").read() for f in glob.glob(os.path.join(tmp_path, "*.jsonl")))
    assert raw, "expected an audit entry"
    for planted in ("03/14/2026", "March 14, 1931", "4/2", "93-year-old"):
        assert planted not in raw, planted
