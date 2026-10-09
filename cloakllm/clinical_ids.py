"""US healthcare identifiers (v0.13.0, health edition).

Off by default: ShieldConfig.detect_us_health_ids. Sources and rationale:
reports/CloakLLM Health US identifiers.md (workspace) and
PLAN_health_edition.md.

Two kinds of identifier, handled very differently:

LABEL-GATED -- no national format exists, so a value is an identifier only
because of the label in front of it. Medical record numbers, encounter and
accession numbers (MRN), account / claim / authorization numbers
(ACCOUNT_NUMBER), member, subscriber, policy and Medicaid IDs
(HEALTH_PLAN_ID), licence numbers (LICENSE_NUMBER), NPI. The pattern matches
LABEL + VALUE, but only the VALUE (the pattern's single capture group, which
always ends the match) is detected and replaced: "MRN: 00482913" becomes
"MRN: [MRN_0]", so the reader still knows what was there. Detecting these
values without a label would turn every lab value and order number into
"personal data" -- the 0.12.x decimal-number bug at scale.

STRUCTURAL -- a published layout or check digit:
  MEDICARE_MBI  11 characters, fixed letter/digit positions, letters exclude
                S L O I B Z, no check digit (CMS). Upper-case hex strings can
                fit the layout ("1AC4DE5FA73"), so the UNDASHED form needs a
                Medicare word nearby; the dashed card form (1EG4-TE5-MK73)
                does not.
  HICN          the pre-2020 Medicare number: an SSN plus a beneficiary code
                suffix ("078051120A", "078-05-1120-B1"). The SSN pattern
                cannot see it, because the suffix removes the word boundary.
  DEA           2 letters + 7 digits; (d1+d3+d5) + 2*(d2+d4+d6) ends in d7.
  NPI           10 digits starting 1 or 2, Luhn computed with the 80840
                prefix (CMS). Label-gated as well: one random 10-digit number
                in ten passes Luhn, and a leading 2 overlaps phone numbers.
  SSN_PARTIAL   "last 4 6789", "SSN ending in 6789", "XXX-XX-6789". HHS:
                the last four digits of an SSN still fail Safe Harbor.

Mirrors cloakllm-js src/clinical-ids.js exactly. Patterns avoid named groups,
inline flags and possessive quantifiers so one source compiles in both SDKs;
case-insensitive patterns spell both cases out in character classes.
"""
from __future__ import annotations

import re

# Separator between a label and its value: "MRN 1", "MRN: 1", "MRN #1",
# "Med Rec No. 1", "Policy# 1". Bounded on purpose (ReDoS budget).
_SEP = r"\s{0,3}(?:[:#=]\s{0,3})?(?:(?:[Nn]o\.?|[Nn]umber|#)\s{0,3}[:#]?\s{0,3})?"

# Values that can follow a label. All must contain at least 4 digits' worth
# of identifier and end at a non-word, non-dash boundary.
_ID_VALUE = r"([A-Za-z]{0,4}-?\d[\dA-Za-z]{2,15}(?:-\d{1,6})?)(?![\w-])"
_NPI_VALUE = r"([12]\d{9})(?!\d)"

# Labels. Written with explicit case alternatives instead of a global
# ignore-case flag, so values stay case-exact and both SDKs compile the same
# text. Order inside each alternation: longest first.
_MRN_LABELS = (
    r"(?:[Mm]edical\s[Rr]ecord(?:\s(?:[Nn]umber|[Nn]o\.?|#))?|[Mm]ed\.?\s?[Rr]ec\.?|"
    r"MRN|MR#|[Pp]atient\s(?:ID|[Nn]umber|[Nn]o\.?|#)|[Pp]t\.?\s?(?:ID|#)|PID|"
    r"[Cc]hart\s?(?:#|[Nn]o\.?|[Nn]umber)|CSN|FIN|[Ee]ncounter\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|"
    r"[Vv]isit\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|[Aa]ccession\s?(?:#|[Nn]o\.?|[Nn]umber)?)"
)
_ACCOUNT_LABELS = (
    r"(?:[Aa]ccount\s?(?:#|[Nn]o\.?|[Nn]umber)|[Aa]cct\.?|HAR|"
    r"[Cc]laim\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|(?:[Pp]rior\s)?[Aa]uth(?:orization)?\s?(?:#|[Nn]o\.?|[Nn]umber)|"
    r"[Rr]ef(?:erence)?\s?(?:#|[Nn]o\.?|[Nn]umber))"
)
_PLAN_LABELS = (
    r"(?:[Mm]ember\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|[Ss]ubscriber\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|"
    r"[Pp]olicy\s?(?:ID|#|[Nn]o\.?|[Nn]umber)|[Ii]nsurance\s(?:ID|#|[Nn]o\.?|[Nn]umber)|"
    r"[Mm]edicaid(?:\s(?:ID|#|[Nn]o\.?|[Nn]umber))?|CIN|R[Xx]\s?ID|"
    r"[Bb]eneficiary\s(?:ID|#|[Nn]o\.?|[Nn]umber)|[Pp]lan\sID)"
)
_LICENSE_LABELS = (
    r"(?:[Dd]river'?s\s[Ll]icen[cs]e(?:\s(?:#|[Nn]o\.?|[Nn]umber))?|"
    r"[Ll]icen[cs]e\s?(?:#|[Nn]o\.?|[Nn]umber)|[Ll]ic\.?\s?(?:#|[Nn]o\.?)|DL\s?#)"
)
_NPI_LABELS = r"(?:NPI)"

_B = r"(?<![A-Za-z0-9])"   # label must start a word

MRN_PATTERN = _B + _MRN_LABELS + _SEP + _ID_VALUE
ACCOUNT_PATTERN = _B + _ACCOUNT_LABELS + _SEP + _ID_VALUE
HEALTH_PLAN_PATTERN = _B + _PLAN_LABELS + _SEP + _ID_VALUE
LICENSE_PATTERN = _B + _LICENSE_LABELS + _SEP + _ID_VALUE
NPI_PATTERN = _B + _NPI_LABELS + _SEP + _NPI_VALUE

# MBI: C A AN N A AN N A A N N; letters exclude S L O I B Z (CMS).
_A = r"[AC-HJKMNP-RT-Y]"
_AN = r"[AC-HJKMNP-RT-Y0-9]"
MBI_PATTERN = (
    r"(?<![A-Za-z0-9-])[1-9]" + _A + _AN + r"\d-?" + _A + _AN + r"\d-?" + _A + _A
    + r"\d\d(?![A-Za-z0-9-])"
)

# HICN: SSN-valid digits + beneficiary identification code suffix.
HICN_PATTERN = (
    r"(?<![\w-])(?!000|666|9\d\d)\d{3}-?(?!00)\d{2}-?(?!0000)\d{4}-?[A-Z][A-Z0-9]?(?![\w-])"
)

# DEA: registrant-type letter, then a letter (surname initial) or 9, 7 digits.
DEA_PATTERN = r"(?<![A-Za-z0-9])[ABCDEFGHJKLMPRSTUX][A-Z9]\d{7}(?![A-Za-z0-9])"

# Partial SSN: labelled last four, or the masked display form.
SSN_PARTIAL_PATTERN = (
    r"(?:(?<![A-Za-z0-9])(?:SSN|SS#|[Ss]ocial\s[Ss]ecurity(?:\s[Nn]umber)?)\s{0,3}(?:#|[Nn]o\.?)?\s{0,3}:?\s{0,3}"
    r"(?:[Ee]nding(?:\s[Ii]n)?|[Ll]ast\s(?:4|[Ff]our)(?:\s[Dd]igits)?|[Xx*]{3}-?[Xx*]{2}-?)\s{0,3}:?\s{0,3}|"
    # "last 4 of SSN: 4321", "last four of the patient's SSN 4321"
    r"(?<![A-Za-z0-9])[Ll]ast\s(?:4|[Ff]our)(?:\s[Dd]igits)?\sof\s(?:(?:his|her|their|the|[Pp]t'?s|[Pp]atient'?s)\s){0,2}"
    r"(?:SSN|SS#|[Ss]ocial\s[Ss]ecurity(?:\s[Nn]umber)?)\s{0,3}(?:is\s)?:?\s{0,3}|"
    r"(?<![A-Za-z0-9])(?:[Xx]{3}|\*{3})-(?:[Xx]{2}|\*{2})-)(\d{4})(?!\d)"
)

# Categories whose pattern matches LABEL + VALUE; only the final capture
# group (the value) is detected.
VALUE_GROUP_CATEGORIES = frozenset({
    "MRN", "ACCOUNT_NUMBER", "HEALTH_PLAN_ID", "LICENSE_NUMBER", "NPI", "SSN_PARTIAL",
})

US_HEALTH_ID_CATEGORIES = frozenset({
    "MRN", "ACCOUNT_NUMBER", "HEALTH_PLAN_ID", "LICENSE_NUMBER", "NPI",
    "MEDICARE_MBI", "HICN", "DEA", "SSN_PARTIAL",
})

_MEDICARE_CONTEXT_RE = re.compile(
    r"(?:[Mm]edicare|MBI|HICN|[Bb]eneficiary)\W{0,12}(?:\w+\W{1,3}){0,2}$"
)
_MEDICARE_CONTEXT_WINDOW = 40


def npi_valid(value: str) -> bool:
    """CMS NPI check digit: Luhn over the 9 base digits with the 80840
    prefix, i.e. plain Luhn plus 24."""
    if len(value) != 10 or not value.isdigit() or value[0] not in "12":
        return False
    total = 24
    for i, ch in enumerate(reversed(value[:9])):
        d = int(ch)
        if i % 2 == 0:          # rightmost base digit is doubled
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return (10 - total % 10) % 10 == int(value[9])


def dea_valid(value: str) -> bool:
    """DEA registration number check digit."""
    digits = value[2:]
    if len(value) != 9 or not digits.isdigit():
        return False
    d = [int(c) for c in digits]
    total = d[0] + d[2] + d[4] + 2 * (d[1] + d[3] + d[5])
    return total % 10 == d[6]


def mbi_accepted(text: str, start: int, end: int) -> bool:
    """The dashed card form stands alone; the undashed form needs a Medicare
    word shortly before it (hex strings can fit the undashed layout)."""
    if text.count("-", start, end) == 2:
        return True
    before = text[max(0, start - _MEDICARE_CONTEXT_WINDOW):start]
    return bool(_MEDICARE_CONTEXT_RE.search(before))


def accept(name: str, text: str, start: int, end: int) -> bool:
    """Code-side gate for the structural categories (regex proposes, code
    disposes). start/end are the detected value's span."""
    value = text[start:end]
    if name in ("MRN", "ACCOUNT_NUMBER", "HEALTH_PLAN_ID", "LICENSE_NUMBER"):
        # A labelled value needs at least five digits, so a year ("per
        # chart 2019", "Medicaid 2024") can never qualify.
        return sum(c.isdigit() for c in value) >= 5
    if name == "NPI":
        return npi_valid(value)
    if name == "DEA":
        return dea_valid(value)
    if name == "MEDICARE_MBI":
        return mbi_accepted(text, start, end)
    return True
