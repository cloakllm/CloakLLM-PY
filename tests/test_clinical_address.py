"""v0.13.0 health edition: US street addresses and PO boxes (Safe Harbor B).

Expected values are written out literally. The JS SDK has the same cases in
test/clinical-address.test.js, and the pattern strings themselves are
byte-identical across the SDKs (checked in test_pattern_is_identical_in_js
when node is available).
"""
import glob
import json
import os
import shutil
import subprocess

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.backends.regex import RegexBackend
from cloakllm.clinical_geo import STREET_ADDRESS_PATTERN
from cloakllm.config import ShieldConfig as _Cfg


@pytest.fixture
def backend():
    return RegexBackend(_Cfg(audit_enabled=False, detect_street_addresses=True))


def found(backend, text):
    return [(d.category, d.text) for d in sorted(backend.detect(text, []), key=lambda d: d.start)]


@pytest.mark.parametrize("text, expected", [
    ("Lives at 418 Maple Ave, Springfield, IL 62704.", [("STREET_ADDRESS", "418 Maple Ave")]),
    ("Address: 12 Oak Street, Apt 4B, Riverside", [("STREET_ADDRESS", "12 Oak Street, Apt 4B")]),
    ("1600 Pennsylvania Avenue NW, 350 5th Ave, Suite 300 and 22B Baker St.",
     [("STREET_ADDRESS", "1600 Pennsylvania Avenue NW"), ("STREET_ADDRESS", "350 5th Ave, Suite 300"),
      ("STREET_ADDRESS", "22B Baker St.")]),
    ("Moved to 77 W Cedar Ct #12; mail to P.O. Box 1234 or PO Box 98",
     [("STREET_ADDRESS", "77 W Cedar Ct #12"), ("STREET_ADDRESS", "P.O. Box 1234"),
      ("STREET_ADDRESS", "PO Box 98")]),
    ("Send to 4500 MARTIN LUTHER KING JR BLVD and 10 1/2 Elm Rd",
     [("STREET_ADDRESS", "4500 MARTIN LUTHER KING JR BLVD"), ("STREET_ADDRESS", "10 1/2 Elm Rd")]),
])
def test_addresses_are_detected(backend, text, expected):
    assert found(backend, text) == expected


@pytest.mark.parametrize("text", [
    "walk 3 blocks down the road, take 2 tabs a day, 5 mg twice daily",  # no capitalised name + suffix
    "follow up in 2 weeks at the Main St clinic",   # lowercase words before a real suffix
    "seen by Dr. Smith on Main; 2 Dr visits; level 3 trauma; room 12",   # no street name before suffix
    "BP 120/80, I-95, Route 66, Highway 1",
    "HbA1c 8.9 St. Mary's Hospital",                                     # decimal, not a house number
    "418 maple ave",                                                     # all lowercase: accepted miss
])
def test_non_addresses_are_left_alone(backend, text):
    assert found(backend, text) == []


def test_round_trip_and_off_by_default(tmp_path):
    text = "Lives at 418 Maple Ave, Apt 2"
    on = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set(), detect_street_addresses=True))
    clean, tm = on.sanitize(text)
    assert clean == "Lives at [STREET_ADDRESS_0]"
    assert on.desanitize(clean, tm) == text
    off = Shield(ShieldConfig(log_dir=tmp_path, ner_entity_types=set()))
    assert off.sanitize(text)[0] == text


def test_no_address_in_the_audit_log(tmp_path):
    Shield(ShieldConfig(log_dir=tmp_path, detect_street_addresses=True)).sanitize(
        "Lives at 418 Maple Ave and P.O. Box 1234")
    raw = "".join(open(f, encoding="utf-8").read() for f in glob.glob(os.path.join(tmp_path, "*.jsonl")))
    assert raw
    for planted in ("418 Maple", "Box 1234"):
        assert planted not in raw, planted


@pytest.mark.skipif(shutil.which("node") is None, reason="node not installed")
def test_pattern_is_identical_in_js():
    js_dir = os.path.join(os.path.dirname(__file__), "..", "..", "cloakllm-js", "src", "clinical-geo.js")
    if not os.path.exists(js_dir):
        pytest.skip("sibling cloakllm-js checkout not present")
    out = subprocess.run(
        ["node", "-e", f"process.stdout.write(JSON.stringify(require({json.dumps(os.path.abspath(js_dir))}).STREET_ADDRESS_PATTERN))"],
        # stdin=DEVNULL: on Windows an inherited pipeline handle can make
        # the spawn fail intermittently with OSError (seen once, locally).
        stdin=subprocess.DEVNULL, capture_output=True, text=True, check=True).stdout
    assert json.loads(out) == STREET_ADDRESS_PATTERN
