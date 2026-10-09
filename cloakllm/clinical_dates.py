"""Clinical date and age detection (v0.13.0, health edition).

Under HIPAA Safe Harbor (45 CFR 164.514(b)(2)(i)(C)), every element of a date
more specific than the year is an identifier -- birth, admission, discharge,
procedure, lab and test dates alike -- and so is any age over 89. Before this
module CloakLLM removed none of them: 0 of 36 non-birth patient dates on the
synthetic clinical benchmark (benchmarks/clinical).

Both categories are OFF by default (ShieldConfig.detect_dates,
ShieldConfig.detect_ages_over_89), so default behaviour does not change.

The regex proposes, code disposes -- the same split as the Luhn and decimal
gates. A pattern match is accepted only if:
  * it is a real calendar date (no 2/30, month 1-12);
  * a date written WITHOUT a year ("3/14") has a date word right before it
    ("on", "since", "admitted", "DOB", ...): bare "5/5" or "1/2" is far more
    often a strength grade, a fraction or a dose than a date;
  * it is not a clinical ratio ("5/5 strength", "4/10 pain", "1/2 tab").
Ages are matched only in age context ("93-year-old", "aged 93", "93M") and
only when 90 or more. Ages of 89 and under are not identifiers under Safe
Harbor, and removing them destroys clinical meaning.

Mirrors cloakllm-js src/clinical-dates.js exactly. The patterns avoid named
groups and possessive quantifiers so the same source compiles in both.
"""
from __future__ import annotations

import re
from typing import Optional

_MONTH = (r"(?:Jan(?:uary)?|Feb(?:ruary)?|Mar(?:ch)?|Apr(?:il)?|May|June?|July?|"
          r"Aug(?:ust)?|Sep(?:t(?:ember)?)?|Oct(?:ober)?|Nov(?:ember)?|Dec(?:ember)?)")
_DAY = r"(?:0?[1-9]|[12]\d|3[01])"
_MON = r"(?:0?[1-9]|1[0-2])"
_YEAR4 = r"(?:19|20)\d{2}"
_YEAR = r"(?:(?:19|20)\d{2}|\d{2})"
_ORD = r"(?:st|nd|rd|th)?"
# Numeric dates must not sit inside a longer token of digits, slashes, dots
# or dashes (version strings, NDC codes, phone fragments, ratios).
_NB = r"(?<![\w/.-])"
_NA = r"(?![\w/-])"

DATE_PATTERN = "|".join([
    # 03/14/2026, 3/14/26, 03-14-2026
    _NB + _MON + "/" + _DAY + "/" + _YEAR + _NA,
    _NB + _MON + "-" + _DAY + "-" + _YEAR + _NA,
    # 2026-03-14, 2026/03/14
    _NB + _YEAR4 + r"[-/](?:0[1-9]|1[0-2])[-/](?:0[1-9]|[12]\d|3[01])" + _NA,
    # 03/2026 (month and year)
    _NB + _MON + "/" + _YEAR4 + _NA,
    # March 14, 2026 / Mar. 14th / March 14 2026
    r"\b" + _MONTH + r"\.?\s" + _DAY + _ORD + r"(?:,?\s" + _YEAR4 + r")?\b",
    # 14 March 2026 / 14th of March
    r"\b" + _DAY + _ORD + r"\s(?:of\s)?" + _MONTH + r"\.?(?:,?\s" + _YEAR4 + r")?\b",
    # March 2026
    r"\b" + _MONTH + r"\.?,?\s" + _YEAR4 + r"\b",
    # 3/14 (month/day, no year): only with a date word before it (see below).
    # A full stop may follow (end of sentence) but not a full stop and a digit
    # (4/2.5 is a number).
    _NB + _MON + "/" + _DAY + r"(?![\w/%-])(?!\.\d)",
])

_AGE_NUM = r"(?:9\d|1[01]\d)"
AGE_PATTERN = "|".join([
    # 93-year-old, 93 year old, 93 yo, 93 y/o, 93 y.o., 93 yrs
    r"\b" + _AGE_NUM + r"(?:\s?-\s?|\s)?(?:years?[\s-]old|yrs?(?:\s?old)?|y/o|y\.o\.|yo)(?![A-Za-z])",
    # aged 93, age 93, Age: 93
    r"\b[Aa]ge[d]?\s?:?\s?" + _AGE_NUM + r"\b",
    # 93M, 93F, 93yoF, 93 yo M
    r"\b" + _AGE_NUM + r"(?:yo|y/o)?[MF]\b",
    r"\b" + _AGE_NUM + r"\s(?:yo|y/o)\s?[MF]\b",
    # in her 90s, in his late 90s
    r"\bin\s(?:his|her|their)\s(?:early\s|mid\s|mid-|late\s)?(?:90|100)s\b",
    r"\b[Nn]onagenarian\b|\b[Cc]entenarian\b",
])

# Words that make a year-less "3/14" a date. Must sit directly before it.
_DATE_CONTEXT_RE = re.compile(
    r"(?:\bon|\bsince|\bfrom|\buntil|\btill|\bby|\bdated?|\bseen|\badmitted|\badm|"
    r"\bdischarged|\bd/c|\bDOS|\bDOB|\bLMP|\bEDD|\bscheduled|\bappt|\bf/u|"
    r"\bfollow[- ]?up|\bvisit|\bsurgery|\bprocedure|\blast|\bnext|\bstart(?:ed|ing)?|"
    r"\bbegan|\bdue)\W{0,3}$",
    re.IGNORECASE,
)
_DATE_CONTEXT_WINDOW = 22

# A number pair followed by one of these is a clinical ratio or grade.
_RATIO_AFTER_RE = re.compile(
    r"\s?(?:strength|pain|tab|tabs|tablet|of\b|dose|scale|ratio|split|units?\b|ml\b|mg\b|"
    r"cm\b|mm\b|hpf\b|lpf\b|vision|murmur|systolic|diastolic)",
    re.IGNORECASE,
)

_MONTHS = {m: i for i, m in enumerate(
    ["jan", "feb", "mar", "apr", "may", "jun", "jul", "aug", "sep", "oct", "nov", "dec"], start=1)}
_DAYS_IN_MONTH = [31, 29, 31, 30, 31, 30, 31, 31, 30, 31, 30, 31]
_FOUR_DIGIT_YEAR_RE = re.compile(r"(?<!\d)((?:19|20)\d{2})(?!\d)")


def _parse_month_day(match: str) -> tuple[Optional[int], Optional[int]]:
    """Month and day from a matched date, when the form has both."""
    word = re.search(r"[A-Za-z]{3,}", match)
    nums = [int(n) for n in re.findall(r"\d+", match)]
    if word:
        month = _MONTHS.get(word.group(0)[:3].lower())
        day = next((n for n in nums if n <= 31 and not (1900 <= n <= 2099)), None)
        return month, day
    if re.match(r"(?:19|20)\d{2}[-/]", match):          # ISO: year first
        return nums[1], nums[2]
    if len(nums) == 2 and nums[1] >= 1900:              # 03/2026
        return nums[0], None
    return nums[0], nums[1]                             # US: month first


def is_valid_date(text: str, start: int, end: int) -> bool:
    """Accept a DATE pattern match only if it is really a date."""
    match = text[start:end]
    month, day = _parse_month_day(match)
    if month is None or not 1 <= month <= 12:
        return False
    if day is not None and not 1 <= day <= _DAYS_IN_MONTH[month - 1]:
        return False
    numeric = not re.search(r"[A-Za-z]", match)
    has_year = bool(re.search(r"\d+\D+\d+\D+\d+|(?:19|20)\d{2}", match))
    if numeric and _RATIO_AFTER_RE.match(text, end):
        return False
    if numeric and not has_year:
        before = text[max(0, start - _DATE_CONTEXT_WINDOW):start]
        if not _DATE_CONTEXT_RE.search(before):
            return False
    return True


# \b matters: without it any word ending in "t" ("Lindqvist, 95-year-old")
# looked like a temperature label and hid the age. Found by the clinical
# benchmark.
_TEMPERATURE_BEFORE_RE = re.compile(r"(?:\btemp|\bt|\u00b0)\W{0,3}$", re.IGNORECASE)


def is_age_over_89(text: str, start: int, end: int) -> bool:
    """Accept an AGE_90PLUS match only in a real age context."""
    if _TEMPERATURE_BEFORE_RE.search(text, max(0, start - 8), start):
        return False
    nums = [int(n) for n in re.findall(r"\d+", text[start:end])]
    return not nums or nums[0] >= 90


def generalize(category: str, value: str) -> str:
    """Safe Harbor form of a detected date or age.

    A date keeps only its four-digit year. A date with no four-digit year
    (3/14, 3/14/26) keeps nothing: a two-digit year is ambiguous and the
    month and day are exactly what Safe Harbor removes. An age over 89
    becomes "90+" in place, so "93-year-old" reads "90+-year-old".

    Not implemented, and stated in the docs: Safe Harbor also suppresses a
    YEAR when it implies an age over 89 (a 1910 birth year). That needs the
    note's own date to compute and is left to the reviewer.
    """
    if category == "DATE":
        m = _FOUR_DIGIT_YEAR_RE.search(value)
        return m.group(1) if m else "[DATE_REDACTED]"
    if category == "AGE_90PLUS":
        return re.sub(r"\d+", "90+", value, count=1) if re.search(r"\d", value) else "aged 90+"
    raise ValueError(f"no Safe Harbor generalization for category {category!r}")


GENERALIZED_CATEGORIES = frozenset({"DATE", "AGE_90PLUS"})
