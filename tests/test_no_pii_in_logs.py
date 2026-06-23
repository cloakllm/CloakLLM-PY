"""AUDIT-14(c): no-PII-in-logs adversarial audit.

The legal invariant ("CloakLLM audit logs must contain zero original PII") is
proven here the hard way: plant unique, valid-format PII sentinels, exercise
every audit-writing path + the error paths, then read the raw audit JSONL back
and assert NOT ONE planted sentinel appears verbatim (hashes of them are fine).

A failure here is a BLOCKER -- it is the product's central, legal promise, not
a feature. Born from the v0.11.2 detection-leak lesson: the sanitized text
being clean is not sufficient proof of the invariant; the written log is.
"""
from __future__ import annotations

import glob
import os
import tempfile

import pytest

from cloakllm import Shield, ShieldConfig

# Unique, valid-format sentinels (valid so they're detected; distinctive so a
# raw occurrence in a log is unambiguous).
SENTINELS = {
    "EMAIL": "zztop.sentinel.9f3a@plant-example.com",
    "SSN": "234-56-7890",
    "CARD": "4111111111111111",
    "IPV6": "2001:0db8:dead:beef::1234",
    "IBAN": "DE89 3704 0044 0532 0130 00",
    "CUSTOM": "PLANTSECRET-ABCDEF123456",
    "NAME": "Zylqwood Pemberton",
}
RAW = list(SENTINELS.values())
TEXT = (
    f"Email {SENTINELS['EMAIL']}, SSN {SENTINELS['SSN']}, card {SENTINELS['CARD']}, "
    f"ipv6 {SENTINELS['IPV6']}, iban {SENTINELS['IBAN']}, secret {SENTINELS['CUSTOM']}, "
    f"name {SENTINELS['NAME']}."
)
_CUSTOM = [("PLANT", r"PLANTSECRET-[A-Z0-9]+")]


def _read_audit(adir: str) -> str:
    return "".join(
        open(f, encoding="utf-8").read()
        for f in glob.glob(os.path.join(adir, "*.jsonl"))
    )


def _assert_no_raw(blob: str, where: str):
    for raw in RAW:
        assert raw not in blob, f"PLANTED PII leaked into {where}: {raw!r}"


# Each path: (label, config-kwargs, callable(shield, text), optional input override)
PATHS = [
    ("sanitize", {}, lambda s, t: s.sanitize(t), None),
    ("redact", {"mode": "redact"}, lambda s, t: s.sanitize(t), None),
    ("entity_hashing", {"entity_hashing": True, "entity_hash_key": "k" * 32},
     lambda s, t: s.sanitize(t), None),
    ("custom_pattern", {"custom_patterns": _CUSTOM}, lambda s, t: s.sanitize(t), None),
    ("desanitize", {}, lambda s, t: (lambda r: s.desanitize(r[0], r[1]))(s.sanitize(t)), None),
    ("analyze", {}, lambda s, t: s.analyze(t), None),
    ("context_analysis", {"context_analysis": True, "context_risk_threshold": 0.99},
     lambda s, t: s.sanitize(t), None),
    ("max_length_reject", {"max_input_length": 80},
     lambda s, t: s.sanitize(t), "x" * 200 + " " + TEXT),
    ("compliance_mode", {"compliance_mode": "eu_ai_act_article12"},
     lambda s, t: s.sanitize(t), None),
]


@pytest.mark.parametrize("label,kw,fn,inp", PATHS, ids=[p[0] for p in PATHS])
def test_no_planted_pii_in_audit_or_errors(tmp_path, label, kw, fn, inp):
    adir = str(tmp_path / label)
    cwd = os.getcwd()
    os.chdir(tmp_path)  # keep the "outside CWD" warning quiet + deterministic
    try:
        shield = Shield(ShieldConfig(audit_enabled=True, log_dir=adir, **kw))
        try:
            fn(shield, inp if inp is not None else TEXT)
        except Exception as e:  # noqa: BLE001 - error messages must not echo PII either
            _assert_no_raw(str(e), f"{label} exception message")
    finally:
        os.chdir(cwd)
    _assert_no_raw(_read_audit(adir), f"{label} audit log")


def test_sentinels_are_actually_detected():
    """Sanity: the audit test is only meaningful if the sentinels are detected
    and tokenized in the first place. (A detection miss would not leak raw into
    the log -- only its hash -- but we want the audit paths genuinely exercised.)"""
    shield = Shield(ShieldConfig(audit_enabled=False, custom_patterns=_CUSTOM))
    out, _ = shield.sanitize(TEXT)
    missed = [k for k, v in SENTINELS.items() if v in out]
    assert not missed, f"sentinels not detected (test would be vacuous): {missed}"


def test_detection_miss_still_does_not_leak_raw(tmp_path):
    """The invariant must hold even when detection MISSES PII: the log stores
    only one-way hashes of the original, never the text. Use a value the
    detector does not recognise and confirm it never appears raw in the log."""
    undetected = "totally-unrecognised-secret-7Qx"
    cwd = os.getcwd()
    os.chdir(tmp_path)
    try:
        adir = str(tmp_path / "a")
        shield = Shield(ShieldConfig(audit_enabled=True, log_dir=adir))
        shield.sanitize(f"note: {undetected} end")
        assert undetected not in _read_audit(adir), "undetected value leaked raw into the log"
    finally:
        os.chdir(cwd)
