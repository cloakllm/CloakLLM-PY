"""v0.11.2 detection-hardening regression tests.

Guards the leak fixes found by the hard-corpus benchmark: spaced/dashed credit
cards and IBANs were partially leaking (and miscategorised as PHONE), and IPv6
was entirely undetected -- all violations of the no-PII-in-logs invariant.
Reproduced here as sanitize() assertions so a regression can't sneak back.
"""
from __future__ import annotations

import re

import pytest

from cloakllm import Shield, ShieldConfig


@pytest.fixture(scope="module")
def shield():
    return Shield(ShieldConfig(audit_enabled=False))


def _sanitize(shield, text):
    out, _ = shield.sanitize(text)
    return out


def _cats(shield, text):
    dets, _ = shield.detector.detect(text)
    return {d.category for d in dets}


# --- credit cards: spaced / dashed / brand variants now fully captured ---

@pytest.mark.parametrize("text,card", [
    ("Pay 4111 1111 1111 1111 now", "4111 1111 1111 1111"),      # Visa, spaced
    ("card 4111-1111-1111-1111 ok", "4111-1111-1111-1111"),      # Visa, dashed
    ("contiguous 4111111111111111 end", "4111111111111111"),     # Visa, compact
    ("mc 5500 0000 0000 0004 done", "5500 0000 0000 0004"),      # Mastercard
    ("Amex 3782 822463 10005 charged", "3782 822463 10005"),     # Amex 4-6-5
    ("disc 6011 1111 1111 1117 ok", "6011 1111 1111 1117"),      # Discover
])
def test_credit_card_variants_detected(shield, text, card):
    assert "CREDIT_CARD" in _cats(shield, text)
    # and the value is fully removed -- no run of >=4 card digits survives
    out = _sanitize(shield, text)
    digits = re.sub(r"\D", "", card)
    assert digits[-4:] not in out, f"leaked trailing digits in {out!r}"
    assert "[CREDIT_CARD_" in out


# --- IBAN: spaced forms captured as one IBAN, not fragmented into PHONE ---

@pytest.mark.parametrize("text,iban", [
    ("Wire to DE89 3704 0044 0532 0130 00 today", "DE89 3704 0044 0532 0130 00"),
    ("IBAN GB29 NWBK 6016 1331 9268 19 please", "GB29 NWBK 6016 1331 9268 19"),
    ("compact DE89370400440532013000 ok", "DE89370400440532013000"),
])
def test_iban_variants_detected(shield, text, iban):
    assert "IBAN" in _cats(shield, text)
    out = _sanitize(shield, text)
    assert "PHONE" not in out and "[IBAN_" in out


# --- IPv6: previously undetected -> whole address leaked verbatim ---

@pytest.mark.parametrize("ip", [
    "2001:0db8:85a3::8a2e:0370:7334",
    "2001:db8::1",
    "fe80::1",
    "::1",
    "2001:db8:0:0:0:0:2:1",
])
def test_ipv6_detected(shield, ip):
    text = f"host {ip} connected"
    assert "IP_ADDRESS" in _cats(shield, text)
    assert ip not in _sanitize(shield, text), "IPv6 leaked verbatim"


def test_ipv4_still_detected(shield):
    assert "IP_ADDRESS" in _cats(shield, "from 192.168.0.14 ok")


# --- the headline leak, asserted end-to-end on the audit-facing output ---

def test_spaced_card_does_not_leak_into_sanitized_log(shield):
    out = _sanitize(shield, "Pay with 4111 1111 1111 1111 please")
    assert out == "Pay with [CREDIT_CARD_0] please"


# --- hard-negatives that must NOT become credit cards (precision) ---

@pytest.mark.parametrize("text", [
    "PO 1111-1111-1111-1111 internal",   # not a valid card prefix
    "ref 1234 5678 9012 3456 note",      # 1234 prefix is not a card BIN
])
def test_non_card_digit_groups_not_flagged_as_card(shield, text):
    assert "CREDIT_CARD" not in _cats(shield, text)


# --- CI guard: broad regression net over the hard corpus (the benchmark) ---

def test_hard_corpus_fair_scrub_threshold(shield):
    """On the FAIR slice (realistic / formatted / multilingual / embedded), the
    no-PII scrub rate must stay high and there must be ZERO partial leaks
    (the financial-PII partial-leak class this release fixed)."""
    from benchmarks.evaluate import load_corpus
    from benchmarks.report_hard import measure, HARD
    B, *_ = measure(shield, load_corpus(HARD))
    fair = B["fair"]
    scrub = fair["scrub"] / (fair["total"] or 1)
    assert scrub >= 0.90, f"FAIR scrub {scrub:.1%} < 90% (no-PII recall regressed)"
    assert fair["partial"] == 0, f"{fair['partial']} partial leak(s) on FAIR slice"
