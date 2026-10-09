"""v0.13.0 health edition: US ZIP codes in address context (HIPAA Safe Harbor).

Expected values are written out literally. The JS SDK has the same cases in
test/clinical-geo.test.js.
"""
import glob
import os

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.backends.regex import RegexBackend
from cloakllm.config import ShieldConfig as _Cfg


@pytest.fixture
def backend():
    return RegexBackend(_Cfg(audit_enabled=False, detect_zip_codes=True))


def found(backend, text):
    return [(d.category, d.text) for d in sorted(backend.detect(text, []), key=lambda d: d.start)]


@pytest.mark.parametrize("text, expected", [
    ("Lives at 418 Maple Ave, Springfield, IL 62704.", [("ZIP", "62704")]),
    ("Address: 12 Oak St, Riverside, CA  92501-1234", [("ZIP", "92501-1234")]),
    ("Mail to Salem, Oregon 97301 or New York 10001", [("ZIP", "97301"), ("ZIP", "10001")]),
    ("ZIP: 30303; Zip code 60614; zip 02115; postal code 94110; ZIP+4 20500-0003",
     [("ZIP", "30303"), ("ZIP", "60614"), ("ZIP", "02115"), ("ZIP", "94110"), ("ZIP", "20500-0003")]),
])
def test_zip_in_address_context(backend, text, expected):
    assert found(backend, text) == expected


@pytest.mark.parametrize("text", [
    "Patient ID 12345, IN 47401 visits, OR 97201 cases, OK 73101",  # not "City, ST"
    "CPT 99213, order 2026091712, BNP 12345 pg/mL",                   # bare numbers
    "Springfield IL 62704",                                           # no comma: accepted miss
])
def test_no_zip_without_address_context(backend, text):
    assert found(backend, text) == []


TEXT = "ZIP: 92501-1234; zip code 97301; postal code 89301"


def test_tokenize_round_trips(tmp_path):
    shield = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set(), detect_zip_codes=True))
    clean, tm = shield.sanitize(TEXT)
    assert clean == "ZIP: [ZIP_2]; zip code [ZIP_1]; postal code [ZIP_0]"
    assert shield.desanitize(clean, tm) == TEXT


def test_zip3_is_the_safe_harbor_form(tmp_path):
    # 893 (Elko, NV) is on the HHS restricted list, so it becomes 000.
    # Label-only text: no city names, so name detection plays no part.
    shield = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set(),
                                 detect_zip_codes=True, zip_mode="zip3"))
    clean, tm = shield.sanitize(TEXT)
    assert clean == "ZIP: 925XX; zip code 973XX; postal code 000XX"
    assert tm.reverse == {}
    assert {e["token"] for e in tm.entity_details} == {"[ZIP_GENERALIZED]"}


def test_restricted_list_is_configurable(tmp_path):
    shield = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set(), detect_zip_codes=True,
                                 zip_mode="zip3", zip3_restricted={"925"}))
    clean, _ = shield.sanitize(TEXT)
    assert clean == "ZIP: 000XX; zip code 973XX; postal code 893XX"


def test_invalid_settings_are_refused():
    with pytest.raises(ValueError):
        ShieldConfig(zip_mode="zip5")
    with pytest.raises(ValueError):
        ShieldConfig(zip3_restricted={"93"})


def test_off_by_default(tmp_path):
    shield = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set()))
    clean, _ = shield.sanitize("Springfield, IL 62704")
    assert clean == "Springfield, IL 62704"


def test_no_zip_in_the_audit_log(tmp_path):
    shield = Shield(ShieldConfig(log_dir=tmp_path, detect_zip_codes=True))
    shield.sanitize("Springfield, IL 62704 and ZIP: 30303")
    raw = "".join(open(f, encoding="utf-8").read() for f in glob.glob(os.path.join(tmp_path, "*.jsonl")))
    assert raw
    for planted in ("62704", "30303"):
        assert planted not in raw, planted
