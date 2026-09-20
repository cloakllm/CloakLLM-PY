"""v0.12.4: contiguous phone numbers, and a detection guard that fails closed.

Two changes, both about the same thing -- a category quietly not being
detected.

**Contiguous phones.** A number written without separators was completely
undetected, including every bare US 10-digit number. The naive fix is to
match bare digit runs, and it is a trap: roughly 64% of random 10-digit ids
satisfy NANP shape, so "2026091912" is simultaneously a plausible
Washington DC number and a plausible invoice id. Measured against the
false-positive corpus introduced in v0.12.3, a bare-run pattern lit up 6 of
12 developer strings.

What works, measured: E.164 ungated (a leading "+" is a declaration, not an
inference) plus NANP-shaped runs gated on a nearby keyword. 6/6 recall,
0/12 false positives.

**The guard.** Failing the ReDoS safety check used to SKIP the pattern,
leaving the process running with that category's detection switched off and
only a warning to say so. For a built-in that is fail-open in a tool whose
job is not to miss things, so it now raises.
"""

import re
import warnings

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.backends.regex import PatternSafetyError, RegexBackend
from cloakllm.detector import has_phone_context


@pytest.fixture(scope="module")
def shield():
    return Shield(ShieldConfig(audit_enabled=False, ner_entity_types=set()))


def categories(shield, text):
    _, token_map = shield.sanitize(text)
    return list(getattr(token_map, "categories", []) or [])


def is_phone(shield, text):
    return "PHONE" in categories(shield, text)


# ------------------------------------------------------ the gap this closes

@pytest.mark.parametrize("text", [
    "call 4155550199 tomorrow",
    "phone: 2125551234",
    "dial 14155550199 now",
    "contact 4155550199",
    # Short filler words between the keyword and the number are allowed,
    # because this is how people write. Strict adjacency caught only 3 of 9
    # realistic phrasings; allowing two words of up to four characters
    # caught 8, with no new false positives.
    "reach me on 2125551234",
    "call him at 4155550199",
    "contact us on 2125551234",
    "mobile is 4155550199",
    "text me at 4155550199",
    # "number" is allowed explicitly, being far too common to miss.
    "phone number is 2125551234",
    "my cell number 4155550199",
])
def test_contiguous_numbers_with_context_are_caught(shield, text):
    assert is_phone(shield, text), text


@pytest.mark.parametrize("text", [
    "the number is +442071838750",
    "reachable at +14155550199",
    "+61291234567 is the Sydney office",
])
def test_e164_needs_no_keyword(shield, text):
    # A leading "+" is the writer declaring this is a phone number. Nothing
    # else is shaped that way, so it does not need the context gate.
    assert is_phone(shield, text), text


# ------------------------------------------------------- no regressions

@pytest.mark.parametrize("text", [
    "call 555 010 4422 today",
    "call 415-555-0199 today",
    "06 12 34 56 78 is French",
    "(415) 555-0199 x42",
    "415.555.0199",
    "tel +1-415-555-0199",
])
def test_separated_forms_still_work(shield, text):
    # Verified purely additive before the change: the only all-digit match
    # the previous pattern made anywhere in the corpora was "14159265",
    # the digits of pi, which was itself a false positive.
    assert is_phone(shield, text), text


# --------------------------------------------------------- the FP corpus

NOT_PHONES = [
    ("order id 10", "order 1234567890 shipped"),
    ("order id, high lead", "order 9876543210 shipped"),
    ("order id 12", "order 123456789012 shipped"),
    ("unix seconds", "ts 1726660800 utc"),
    ("unix millis", "ts 1726660800000 utc"),
    ("account 17", "acct 12345678901234567 closed"),
    ("build number", "build 20260919123456 ok"),
    ("ISBN-13", "isbn 9780306406157 here"),
    ("card", "card 4111111111111111 ok"),
    ("tracking", "tracking 9400110200881234567890"),
    ("invoice, DC-shaped", "invoice 2026091912 paid"),
    ("ticket, phone-shaped", "ticket 5551234567 closed"),
    ("pi digits", "Pi is 3.14159265 and so on"),
    # The "number" connector must not open the gate on its own. These are
    # the strings that make allowing it safe or unsafe, so they are the
    # ones worth pinning.
    ("order number", "order number 1234567890 shipped"),
    ("invoice number", "invoice number 2026091912 paid"),
    ("ticket number", "ticket number 5551234567 closed"),
    ("reference number", "reference number 9876543210 filed"),
    ("tracking number", "tracking number 9400110200881234"),
    # A phone keyword far from the number, with real words in between.
    ("keyword, distant number", "call about order 9876543210"),
    ("keyword, longer sentence",
     "we had to call the supplier and quote 9876543210"),
]


@pytest.mark.parametrize("label,text", NOT_PHONES)
def test_developer_strings_are_not_phones(shield, label, text):
    assert not is_phone(shield, text), label


def test_phone_false_positive_rate_is_zero_on_the_corpus(shield):
    hits = [label for label, text in NOT_PHONES if is_phone(shield, text)]
    assert hits == [], "phone false positives: %s" % hits


def test_the_gate_also_removed_an_existing_false_positive(shield):
    # "Pi is 3.14159265" used to be reported as a PHONE -- it was on the
    # hard-negatives list. It is an all-digit run with no keyword, so the
    # gate drops it. A leak fix that also removes noise.
    assert not is_phone(shield, "Pi is 3.14159265 and the ratio was 16:9")


# ----------------------------------------------------------- the context gate

def test_the_keyword_must_be_adjacent_not_merely_present():
    # "call about order 9876543210" is about an order, not a phone number.
    # A gate satisfied by a keyword anywhere in the sentence would be
    # satisfied by almost any customer-service message.
    text = "call about order 9876543210"
    assert not has_phone_context(text, text.index("9876543210"))

    close = "call 9876543210"
    assert has_phone_context(close, close.index("9876543210"))


@pytest.mark.parametrize("keyword", [
    "call", "called", "calling", "phone", "telephone", "tel", "mobile",
    "cell", "fax", "contact", "reach", "dial", "ring", "whatsapp", "sms",
])
def test_each_keyword_opens_the_gate(keyword):
    text = "%s 4155550199" % keyword
    assert has_phone_context(text, text.index("4155550199")), keyword


def test_punctuation_between_keyword_and_number_is_allowed():
    for text in ("phone: 4155550199", "tel. 4155550199", "mobile - 4155550199"):
        assert has_phone_context(text, text.index("4155550199")), text


# -------------------------------------------------------- documented limits

@pytest.mark.parametrize("label,text", [
    ("bare US 10 with no keyword at all", "4155550199"),
    ("international, contiguous, no +", "call 442071838750 please"),
])
def test_known_limits_are_asserted_not_forgotten(shield, label, text):
    # Both are real misses and both are deliberate. A bare run with no
    # context is indistinguishable from an id; a contiguous international
    # number without a "+" has neither a declaration nor NANP structure to
    # go on. Asserted so closing either is a decision rather than a
    # surprise.
    assert not is_phone(shield, text), label


def test_an_invalid_nanp_exchange_is_correctly_rejected(shield):
    # 555-010-4422 cannot exist: an exchange code may not start with 0.
    # Worth pinning because this number was carried for a while as an
    # example of the gap, and rejecting it is correct rather than a miss.
    assert not is_phone(shield, "call 5550104422 today")


# ------------------------------------------------ the guard now fails closed

def test_a_catastrophic_builtin_raises_instead_of_being_skipped(monkeypatch):
    # The old behaviour was to warn and carry on with that category's
    # detection silently switched off. In a PII tool that is the worst
    # available outcome, and a built-in cannot be provoked by user input --
    # it is our own regression.
    monkeypatch.setattr(RegexBackend, "_measure_regex_safety",
                        staticmethod(lambda rx: 2.0))
    with pytest.raises(PatternSafetyError, match="Refusing to start"):
        RegexBackend(ShieldConfig())


def test_a_merely_slow_machine_can_still_start(monkeypatch):
    # The built-in budget is 1s, not 100ms, precisely so that fail-closed
    # does not turn slow hardware into an install that cannot start. EMAIL
    # costs ~16ms of CPU here, so a 100ms budget left only ~6x of headroom.
    monkeypatch.setattr(RegexBackend, "_measure_regex_safety",
                        staticmethod(lambda rx: 0.5))
    backend = RegexBackend(ShieldConfig())
    assert backend._compiled_patterns


def test_the_builtin_budget_is_looser_than_the_custom_one():
    # They measure different things: a boundary against a regex we did not
    # write, versus a regression canary on ones we did.
    assert RegexBackend._BUILTIN_SAFETY_BUDGET > RegexBackend._SAFETY_BUDGET


def test_real_builtins_have_real_headroom():
    # If this gets tight, the fail-closed decision needs revisiting.
    backend = RegexBackend(ShieldConfig())
    worst = max(RegexBackend._measure_regex_safety(p)
                for _, p in backend._compiled_patterns)
    assert worst < RegexBackend._BUILTIN_SAFETY_BUDGET / 10, (
        "worst built-in is %.0f ms of CPU against a %.0f ms budget"
        % (worst * 1000, RegexBackend._BUILTIN_SAFETY_BUDGET * 1000))


def test_a_users_own_regex_cannot_stop_the_sdk_starting(monkeypatch):
    real = RegexBackend._measure_regex_safety

    def selective(rx):
        return 0.5 if rx.pattern == "SLOWCUSTOM" else real(rx)

    monkeypatch.setattr(RegexBackend, "_measure_regex_safety",
                        staticmethod(selective))
    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        backend = RegexBackend(ShieldConfig(
            custom_patterns=[("X", "SLOWCUSTOM")]))

    assert "X" not in [n for n, _ in backend._compiled_patterns]
    assert any("Custom pattern" in str(w.message) for w in caught)


def test_a_skipped_locale_pattern_warns_instead_of_failing_silently(monkeypatch):
    # This branch used to be a bare `pass`: a locale's detection would
    # simply not happen, with nothing said. Same fail-open, volume at zero.
    from cloakllm import locale_patterns

    monkeypatch.setitem(locale_patterns.LOCALE_PATTERNS, "xx",
                        [("SLOW_XX", "hint", "SLOWLOCALE")])
    real = RegexBackend._measure_regex_safety
    monkeypatch.setattr(
        RegexBackend, "_measure_regex_safety",
        staticmethod(lambda rx: 0.5 if rx.pattern == "SLOWLOCALE" else real(rx)))

    with warnings.catch_warnings(record=True) as caught:
        warnings.simplefilter("always")
        RegexBackend(ShieldConfig(locale="xx"))

    assert any("locale pattern 'SLOW_XX'" in str(w.message) for w in caught)


# ------------------------------------------------------------- ReDoS safety

def test_the_new_phone_pattern_is_cheap():
    from cloakllm.detector import PATTERNS
    compiled = re.compile(PATTERNS["PHONE"][1])
    worst = RegexBackend._measure_regex_safety(compiled)
    assert worst < 0.01, "%.1f ms of CPU" % (worst * 1000)
