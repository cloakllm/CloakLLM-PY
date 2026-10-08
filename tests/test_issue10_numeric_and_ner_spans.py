"""Regressions from cloakllm/CloakLLM#10 (v0.12.7).

A user running an agent over MongoDB records reported that

    {'_id': ObjectId('68cfeb61...'), 'market_value': 20042839.001880005,
     'name': 'Shawn Hardin'}

came out with the closing quote of the name swallowed into the token and
the ObjectId tagged as a place. Reproducing it found a third, wider defect
the report did not mention: parts of ordinary decimal numbers were detected
as personal data. In 6,016 plain decimals, 1,152 were tagged -- SSN for a
9-digit integer part, PHONE for "237.07924402", CREDIT_CARD for a Luhn-valid
16-digit fraction -- so numeric payloads reached the model corrupted.

Expected outputs below are written out literally; they are not computed by
the code under test.
"""
import random

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.backends.regex import RegexBackend
from cloakllm.config import ShieldConfig as _Cfg
from cloakllm.detector import clean_ner_span, in_decimal_number
from cloakllm.locale_patterns import LOCALE_PATTERNS

USER_PAYLOAD = (
    "[{'_id': ObjectId('68cfeb6153dc447c8de27511'), 'market_value': 20042839.001880005, "
    "'name': 'Shawn Hardin'}, {'_id': ObjectId('68cfeb6e53dc447c8de27523'), "
    "'name': 'Maria Lopez', 'market_value': 17246256.599931788}]"
)


@pytest.fixture
def regex():
    return RegexBackend(_Cfg(audit_enabled=False))


# ------------------------------------------------------------ decimals --

@pytest.mark.parametrize("number", [
    "20042839.001880005",        # the user's market_value (SSN on the fraction)
    "17246256.599931788",
    "764623112.909",             # SSN on the integer part
    "237.07924402",              # PHONE on the whole number
    "51350.4754678208288285",    # Luhn-valid 16-digit fraction -> CREDIT_CARD
    "6943335.6574100425578441",
    "47.6062095", "-122.3320708", "0.123456789",
])
def test_decimal_numbers_are_not_personal_data(regex, number):
    for text in (f"value {number}", f"{{'market_value': {number}}}"):
        assert regex.detect(text, []) == [], text


def test_random_decimals_are_never_tagged(regex):
    # 0.12.6 tagged 1,152 of 6,016 of these; 0 after the fix.
    rng = random.Random(7)
    for _ in range(3000):
        i = rng.randint(0, 10 ** rng.randint(1, 12))
        f = "".join(rng.choice("0123456789") for _ in range(rng.randint(1, 17)))
        text = f"value {i}.{f}"
        assert regex.detect(text, []) == [], text


@pytest.mark.parametrize("text, category, value", [
    # The gate must not cost recall: real data written next to dots.
    ("My SSN is 123-45-6789.", "SSN", "123-45-6789"),
    ("ssn: 123456789.", "SSN", "123456789"),
    ("Call 555.123.4567 today", "PHONE", "555.123.4567"),
    ("Toll free 1.800.555.1234.", "PHONE", "800.555.1234"),
    ("Reach me at +1.555.123.4567", "PHONE", "+1.555.123.4567"),
    ("phone: 555.1234567", "PHONE", "555.1234567"),       # single dot + keyword
    ("call me on 2125551234.", "PHONE", "2125551234"),
    ("My card is 4111111111111111.", "CREDIT_CARD", "4111111111111111"),
    ("Paid 12.50 with 4111111111111111", "CREDIT_CARD", "4111111111111111"),
    ("IBAN DE89370400440532013000.", "IBAN", "DE89370400440532013000"),
])
def test_real_values_next_to_dots_are_still_caught(regex, text, category, value):
    found = [(d.category, d.text) for d in regex.detect(text, [])]
    assert (category, value) in found, found


def test_custom_patterns_are_matched_as_written():
    # The decimal gate applies to CloakLLM's own patterns only. A user who
    # asked for nine digits gets nine digits, wherever they are.
    backend = RegexBackend(_Cfg(audit_enabled=False,
                                custom_patterns=[("ACCOUNT", r"\d{9}")]))
    found = [(d.category, d.text) for d in backend.detect("v 1.123456789", [])]
    assert ("ACCOUNT", "123456789") in found


@pytest.mark.parametrize("text, value, expected", [
    ("value 764623112.909", "764623112", True),        # integer part
    ("value 20042839.001880005", "001880005", True),   # fraction
    ("value 1.61318609139099", "09139099", True),      # from the middle
    ("value 4303163444.116372651676", "03163444.11", True),  # across the dot
    ("Toll free 1.800.555.1234", "800.555.1234", False),     # 3 dots: phone
    ("version 1.2.3456789", "3456789", False),               # 2 dots
    ("ssn: 123456789.", "123456789", False),                 # sentence period
    ("ip 10.0.0.123456", "123456", False),
])
def test_in_decimal_number(text, value, expected):
    start = text.index(value)
    assert in_decimal_number(text, start, start + len(value)) is expected


@pytest.mark.parametrize("locale", sorted(LOCALE_PATTERNS))
def test_decimals_are_not_tagged_under_any_locale(locale):
    # Several locale phone patterns have no digit boundary and matched from
    # the middle of a number: 0.12.6 tagged 11,139 of 6,000 decimals across
    # the locales. All must now be 0.
    backend = RegexBackend(_Cfg(audit_enabled=False, locale=locale))
    rng = random.Random(11)
    for _ in range(400):
        i = rng.randint(0, 10 ** rng.randint(1, 12))
        f = "".join(rng.choice("0123456789") for _ in range(rng.randint(1, 17)))
        text = f"value {i}.{f}"
        assert backend.detect(text, []) == [], (locale, text)


# ----------------------------------------------------------- NER spans --

@pytest.mark.parametrize("raw, expected", [
    ("'Shawn Hardin'", "Shawn Hardin"),
    ("Shawn Hardin'", "Shawn Hardin"),
    ('"Maria Lopez",', "Maria Lopez"),
    ("(Acme Inc.)", "Acme Inc."),        # the period is part of the name
    ("John (Jack) Smith", "John (Jack) Smith"),
    # An obfuscated email is not code. A first version of the rule rejected
    # square brackets and the hard corpus showed this leaking as a result.
    ("jane[at]example[dot]org", "jane[at]example[dot]org"),
])
def test_ner_span_edges_are_trimmed(raw, expected):
    span = clean_ner_span(raw, 0, len(raw))
    assert span is not None
    assert raw[span[0]:span[1]] == expected


@pytest.mark.parametrize("raw", [
    "ObjectId('68cfeb6153dc447c8de27511",
    "ObjectId('68cfeb6153dc447c8de27511')",
    "user_id=42",
    "Order 1234567",
    "'",
])
def test_ner_spans_that_are_code_are_dropped(raw):
    assert clean_ner_span(raw, 0, len(raw)) is None


# ----------------------------------------------------- end to end (NER) --

def test_user_payload_end_to_end(tmp_path):
    spacy = pytest.importorskip("spacy")
    try:
        spacy.load("en_core_web_sm")
    except OSError:
        pytest.skip("en_core_web_sm not installed")
    shield = Shield(ShieldConfig(log_dir=tmp_path))
    clean, token_map = shield.sanitize(USER_PAYLOAD)
    assert clean == (
        "[{'_id': ObjectId('68cfeb6153dc447c8de27511'), 'market_value': 20042839.001880005, "
        "'name': '[PERSON_1]'}, {'_id': ObjectId('68cfeb6e53dc447c8de27523'), "
        "'name': '[PERSON_0]', 'market_value': 17246256.599931788}]"
    )
    assert shield.desanitize(clean, token_map) == USER_PAYLOAD
