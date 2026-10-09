"""v0.13.0 health edition: US healthcare identifiers.

Expected values are written out literally. Test values are the issuers'
published examples or publicly voided numbers, never real identifiers:
NPI 1234567893 (CMS check-digit document), MBI 1EG4-TE5-MK73 (CMS), SSN
078-05-1120 (the voided Woolworth wallet-card number), DEA AB1234563
(constructed to pass the published check). The JS SDK has the same cases in
test/clinical-ids.test.js.
"""
import glob
import os

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.backends.regex import RegexBackend
from cloakllm.clinical_ids import dea_valid, npi_valid
from cloakllm.config import ShieldConfig as _Cfg


@pytest.fixture
def backend():
    return RegexBackend(_Cfg(audit_enabled=False, detect_us_health_ids=True))


def found(backend, text):
    return [(d.category, d.text) for d in sorted(backend.detect(text, []), key=lambda d: d.start)]


@pytest.mark.parametrize("text, expected", [
    ("MRN: 00482913, Med Rec No. H4875819, Patient ID 7734512, Chart # 5512345, CSN 223344556",
     [("MRN", "00482913"), ("MRN", "H4875819"), ("MRN", "7734512"), ("MRN", "5512345"), ("MRN", "223344556")]),
    ("Member ID: XJH448812934, Subscriber ID W123456789, Policy #MBR3708473355, Medicaid ID 12345678901",
     [("HEALTH_PLAN_ID", "XJH448812934"), ("HEALTH_PLAN_ID", "W123456789"),
      ("HEALTH_PLAN_ID", "MBR3708473355"), ("HEALTH_PLAN_ID", "12345678901")]),
    ("Acct # 88812345, Claim # 2026091712, Prior auth # PA4455661",
     [("ACCOUNT_NUMBER", "88812345"), ("ACCOUNT_NUMBER", "2026091712"), ("ACCOUNT_NUMBER", "PA4455661")]),
    ("License # A123456, DL # D1234567, NPI 1234567893",
     [("LICENSE_NUMBER", "A123456"), ("LICENSE_NUMBER", "D1234567"), ("NPI", "1234567893")]),
    ("Medicare MBI 1EG4-TE5-MK73; Medicare number 1EG4TE5MK73; card 1EG4-TE5-MK73",
     [("MEDICARE_MBI", "1EG4-TE5-MK73"), ("MEDICARE_MBI", "1EG4TE5MK73"), ("MEDICARE_MBI", "1EG4-TE5-MK73")]),
    ("HICN 078051120A and 078-05-1120-B1; DEA AB1234563",
     [("HICN", "078051120A"), ("HICN", "078-05-1120-B1"), ("DEA", "AB1234563")]),
    ("SSN ending in 6789; last 4 of SSN: 4321; last four of the patient's SSN is 9876; XXX-XX-5555",
     [("SSN_PARTIAL", "6789"), ("SSN_PARTIAL", "4321"), ("SSN_PARTIAL", "9876"), ("SSN_PARTIAL", "5555")]),
])
def test_identifiers_are_detected_value_only(backend, text, expected):
    assert found(backend, text) == expected


@pytest.mark.parametrize("text", [
    "per chart review 2019, encounter today, claim denied, account of events, Medicaid 2024",
    "hash 1AC4DE5FA73 and sha 1EG4TE5MK73 without context",   # MBI-shaped, no Medicare word
    "NPI 1234567890",          # wrong check digit
    "DEA AB1234567",           # wrong check digit
    "MRN pending; Policy # unknown; NPI 12345; last 4 visits 2024",
    "ICD-10 E11.65; CPT 99213",
])
def test_look_alikes_are_left_alone(backend, text):
    assert found(backend, text) == []


def test_check_digits_against_published_examples():
    assert npi_valid("1234567893") and not npi_valid("1234567890")
    assert dea_valid("AB1234563") and not dea_valid("AB1234567")


def test_label_stays_readable(tmp_path):
    shield = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set(), detect_us_health_ids=True))
    text = "MRN: 00482913, Member ID XJH448812934, NPI 1234567893"
    clean, tm = shield.sanitize(text)
    assert clean == "MRN: [MRN_0], Member ID [HEALTH_PLAN_ID_0], NPI [NPI_0]"
    assert shield.desanitize(clean, tm) == text


def test_off_by_default(tmp_path):
    shield = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set()))
    text = "MRN: 00482913, Member ID XJH448812934, Medicare 1EG4-TE5-MK73"
    clean, _ = shield.sanitize(text)
    assert clean == text


def test_custom_pattern_named_mrn_still_allowed():
    ShieldConfig(custom_patterns=[("MRN", r"MRN\d{6}")])


def test_no_identifiers_in_the_audit_log(tmp_path):
    shield = Shield(ShieldConfig(log_dir=tmp_path, detect_us_health_ids=True))
    shield.sanitize("MRN: 00482913, Member ID XJH448812934, MBI 1EG4-TE5-MK73, HICN 078051120A, "
                    "NPI 1234567893, DEA AB1234563, SSN ending in 6789")
    raw = "".join(open(f, encoding="utf-8").read() for f in glob.glob(os.path.join(tmp_path, "*.jsonl")))
    assert raw
    for planted in ("00482913", "XJH448812934", "1EG4-TE5-MK73", "078051120A", "1234567893", "AB1234563", "6789"):
        assert planted not in raw, planted
