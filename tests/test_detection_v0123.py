"""v0.12.3: credit-card issuer coverage and Luhn validation.

Two defects, found by pulling on one external review finding.

The serious one was a LEAK. The issuer list stopped at Visa, 5-series
Mastercard, Amex and Discover, so Luhn-valid cards on three live ranges
went through completely untouched:

  * Mastercard 2-series (2221-2720), issued since 2017
  * JCB (3528-3589)
  * UnionPay (62), the largest network in the world by volume

The recall benchmark could not have caught it: its corpus only contained
Visa, 5-series Mastercard and Amex. So the fixture set below is the actual
fix to the measurement gap, and the benchmark corpus was extended to match.

The second was the reported one: no Luhn check, so a number that merely
looked like a card was reported as one.

Numbers here are published test values or constructed to be Luhn-valid.
None is a real card.
"""

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.detector import luhn_valid


@pytest.fixture(scope="module")
def shield():
    # Regex only: this is about the card pattern, and a NER hit would make
    # the assertions mean something else.
    return Shield(ShieldConfig(audit_enabled=False, ner_entity_types=set()))


def categories(shield, text):
    _, token_map = shield.sanitize(text)
    return list(getattr(token_map, "categories", []) or [])


def caught(shield, number):
    return "CREDIT_CARD" in categories(shield, "card %s here" % number)


# ------------------------------------------------------------------- luhn

@pytest.mark.parametrize("number", [
    "4111111111111111", "5500000000000004", "378282246310005",
    "2221000000000009", "3530111333300000", "6212345678901232",
    "4111 1111 1111 1111", "4111-1111-1111-1111",
])
def test_luhn_accepts_valid_numbers(number):
    assert luhn_valid(number)


@pytest.mark.parametrize("number", [
    "4111111111111112",     # the standard test Visa, check digit broken
    "5500000000000005",
    "378282246310006",
    "2221000000000008",
])
def test_luhn_rejects_broken_check_digits(number):
    assert not luhn_valid(number)


def test_luhn_ignores_separators():
    assert luhn_valid("4111 1111 1111 1111") == luhn_valid("4111111111111111")


def test_luhn_rejects_runs_too_short_to_be_a_card():
    # 12 is the shortest card in circulation; below that a "valid" checksum
    # is just arithmetic.
    assert not luhn_valid("00000000000")       # 11 digits
    assert not luhn_valid("")


# ----------------------------------------------------- issuer coverage (LEAK)

@pytest.mark.parametrize("issuer,number", [
    ("Visa 16",              "4111111111111111"),
    ("Mastercard 5-series",  "5500000000000004"),
    ("Mastercard 2-series",  "2221000000000009"),
    ("Amex",                 "378282246310005"),
    ("Discover 6011",        "6011111111111117"),
    ("Discover 65",          "6511111111111112"),
    ("Discover 644",         "6441111111111117"),
    ("JCB",                  "3530111333300000"),
    ("UnionPay 16",          "6212345678901232"),
    ("UnionPay 19",          "6212345678901234569"),
    ("Diners 36, 14 digits", "36011111111113"),
    ("Diners 38, 14 digits", "38123456789011"),
    ("Diners 300-305",       "30011111111119"),
])
def test_every_supported_issuer_is_caught(shield, issuer, number):
    # Each of these is Luhn-valid, so a miss is a card reaching the provider.
    assert luhn_valid(number), "fixture is not Luhn-valid: %s" % number
    assert caught(shield, number), "%s leaked: %s" % (issuer, number)


@pytest.mark.parametrize("number", [
    "2221000000000009",     # first of the Mastercard 2-series range
    "2720990000000007",     # last of it
    "3528000000000007",     # first JCB
    "3589000000000003",     # last JCB
])
def test_range_edges_are_inside(shield, number):
    assert caught(shield, number)


def test_just_outside_the_mastercard_range_is_not_a_card(shield):
    # 2220 is below the 2221-2720 range. Luhn-valid, and still not a card:
    # the range boundary has to be exact or the prefix check means nothing.
    assert luhn_valid("2220000000000000")
    assert not caught(shield, "2220000000000000")


def test_spaced_and_dashed_forms_still_work(shield):
    for text in ("4111 1111 1111 1111", "4111-1111-1111-1111",
                 "2221 0000 0000 0009", "3782 822463 10005"):
        assert caught(shield, text), text


def test_mixed_separators_are_not_a_card(shield):
    # The backreferenced separator is what stops arbitrary digit runs from
    # matching; keep it honest.
    assert not caught(shield, "4111 1111-1111 1111")


# --------------------------------------------------------- Luhn as a gate (FP)

@pytest.mark.parametrize("number", [
    "4111111111111112",
    "5500000000000005",
    "2221000000000008",
    "6212345678901233",
])
def test_card_shaped_numbers_with_a_bad_checksum_are_rejected(shield, number):
    assert not luhn_valid(number)
    assert not caught(shield, number)


def test_a_rejected_card_is_not_relabelled_as_something_else(shield):
    # Rejecting on Luhn leaves the span uncovered, so a following pattern
    # could claim it. Silently turning a false CREDIT_CARD into a false
    # PHONE would not be a fix.
    assert categories(shield, "ref 4111111111111112 here") == []


# ---------------------------------------------- false positives, as a NUMBER

# Things a developer has in a chat window all day. The project measures
# character-level scrub (recall) and had no false-positive measurement at
# all, which is why a missing Luhn check was invisible to every gate.
#
# Two numbers come out of this corpus and they are not the same number:
# CREDIT_CARD false positives regex-only (what this release fixed, now 0),
# and false positives across every category in the default config (what a
# user actually experiences, currently 3). Both are asserted below.
NOT_PII = [
    ("ISBN-13", "see isbn 9780306406157"),
    ("ISBN-13 hyphenated", "isbn 978-0-306-40615-7"),
    ("non-Luhn 16 digit", "ref 4111111111111112"),
    ("order id, 16 digit", "order 1234567890123456"),
    ("order id, 14 digit", "order 12345678901234"),
    ("two ms timestamps", "window 1726660800000 to 1726747200000"),
    ("big int in json", '{"id": 4532015112830367}'),
    ("IMEI", "imei 490154203237518"),
    ("UPS tracking", "tracking 1Z999AA10123456784"),
    ("long account number", "acct 12345678901234567"),
    ("git sha", "sha a1b2c3d4e5f6"),
    ("uuid", "id 550e8400-e29b-41d4-a716-446655440000"),
    ("semver-ish build", "build 20260919.1234567890123"),
]


@pytest.mark.parametrize("label,text", NOT_PII)
def test_ordinary_developer_strings_are_not_cards(shield, label, text):
    assert "CREDIT_CARD" not in categories(shield, text), label


def test_credit_card_false_positive_rate_is_zero_on_the_corpus(shield):
    # Stated as a number so a regression shows up as one. The first modal
    # that fires on something obviously not a card is what makes a user
    # stop believing the next one.
    #
    # Read the scope honestly: this counts CREDIT_CARD false positives, and
    # `shield` here is regex-only. It is not the false-positive rate a user
    # experiences. See the next test for that.
    hits = [label for label, text in NOT_PII
            if "CREDIT_CARD" in categories(shield, text)]
    assert hits == [], "credit-card false positives: %s" % hits


def test_the_default_config_false_positive_rate_is_recorded():
    # The number above is the one this release moved, but it is not the one
    # a user sees: NER is on by default, and it tags a git SHA as a PERSON
    # and a bare word as an ORG. A build number is read as a PHONE even
    # regex-only.
    #
    # None of that is new or caused by this release -- it is visible only
    # because the corpus now exists. Pinned here so the next person to work
    # on false positives starts from a measured number rather than
    # rediscovering it, and so a regression in ANY category shows up.
    from cloakllm import Shield, ShieldConfig

    # v0.12.4 removed "semver-ish build" from this set: its 8-digit prefix
    # used to be read as a PHONE, and the contiguous-phone context gate
    # drops bare digit runs with no keyword near them. The set shrinking is
    # the gate working -- and this assertion going red is it being noticed
    # rather than absorbed.
    default = Shield(ShieldConfig(audit_enabled=False))
    hits = sorted(label for label, text in NOT_PII
                  if categories(default, text))
    assert hits == ["git sha", "non-Luhn 16 digit"], (
        "the default-config false-positive set changed: %s" % hits)


# --------------------------------------------------------- documented gaps

@pytest.mark.parametrize("number", [
    "5018111111111112",   # Maestro 50
    "6718111111111113",   # Maestro 67
])
def test_maestro_is_deliberately_not_covered(shield, number):
    # Maestro spans 50 and 56-69 at 12-19 digits, which overlaps most other
    # issuers and a great many ordinary numbers. Luhn alone admits one in
    # ten candidates, so covering it would buy a little recall for a lot of
    # false positives. Asserted so it stays a decision rather than becoming
    # something nobody remembers choosing.
    assert luhn_valid(number)
    assert not caught(shield, number)
