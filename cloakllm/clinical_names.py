"""Role-gated and header-line names (v0.13.0, health edition).

Off by default: ShieldConfig.detect_role_names. On the synthetic clinical
benchmark, 16 of 180 names were not fully removed by NER alone. They fell
into three patterns, which this module targets:

  * a name after a role word -- "Patient Hector Vance.", "Mother Aisha
    Sato" -- where NER took only part of it, or none of it;
  * a name heading a line of identifiers -- "Lucia Pruitt 876701408 ..." --
    where NER sees no sentence around it;
  * a surname that is also a disease eponym -- "Thomas Parkinson ... his
    Parkinson's disease" -- where NER removed only the first name, leaving
    the surname behind.

The first two are regex rules (ROLE + NAME; only the name is detected). They
are emitted as PERSON, so a name gets the same kind of token whichever rule
finds it. The third is surname completion, applied to NER results in the
NER backends (extend_first_name).

Words that follow a role word in templates but are not names ("Patient
Portal", "Patient Reports", "Dr. Smith MD") are trimmed or rejected by
trim_name. A word missing from that list is over-removal, not a leak.

Mirrors cloakllm-js src/clinical-names.js exactly; the pattern strings are
byte-identical (tests/test_clinical_names.py checks this).
"""
from __future__ import annotations

import re

# Honorifics: a single surname is enough ("Mr. Vance", "Dr. Cho").
_HONORIFIC = r"(?:Mr|Mrs|Ms|Mx|Miss|Dr|Prof)\.?"
# Roles: need at least first + last name ("Patient Hector Vance").
# "Name" counts only as a form label, i.e. with a colon after it.
_ROLE = (
    r"(?:[Pp]atient(?:\s[Nn]ame)?|[Pp]t\.?(?:\s[Nn]ame)?|[Nn]ame(?=\s{0,2}:)|[Mm]other|[Ff]ather|"
    r"[Mm]om|[Dd]ad|[Ss]pouse|[Ww]ife|[Hh]usband|[Ss]on|[Dd]aughter|[Ss]ister|[Bb]rother|"
    r"[Gg]uardian|[Cc]aregiver|[Pp]artner|[Ss]igned\sby|[Ee]mergency\s[Cc]ontact)"
)
# One name word: Capitalised (O'Brien, McDonald, Smith-Jones) or ALL CAPS
# (headers). An apostrophe only as a prefix: "Parkinson's" is not a name word.
_NAME = r"(?:(?:[A-Z]'|Ma?c)?[A-Z][a-z]+(?:-[A-Z]?[a-z]+)?|[A-Z]{2,}(?:['-][A-Z]{2,})?)"
_INITIAL = r"(?:\s[A-Z]\.)?"
_SEP = r"\s{0,2}:?\s{0,2}"

# Exactly one of the two groups takes part in a match; it ends the match.
ROLE_NAME_PATTERN = (
    r"(?<![A-Za-z])(?:" + _HONORIFIC + r"\s{0,2}(" + _NAME + r"(?:" + _INITIAL + r"\s" + _NAME + r"){0,2})"
    + r"|" + _ROLE + _SEP + r"(" + _NAME + _INITIAL + r"\s" + _NAME + r"(?:\s" + _NAME + r")?))"
    + r"(?![A-Za-z])"
)

_DOB_MRN_LABEL = r"(?:DOB|D\.O\.B\.|MRN|[Dd]ate\sof\s[Bb]irth)(?![A-Za-z])"

# Two branches, one group each:
#  * "Lucia Pruitt 876701408 ..." / "SMITH, JOHN 1/2/1960": a name at the
#    start of the text or of a line, directly followed by an ID (5+ digits,
#    up to 3 letters first), a date, or a DOB/MRN label;
#  * "... for Aisha Vance (Date of birth: ...)": a full name anywhere,
#    directly followed by a DOB/MRN label.
HEADER_NAME_PATTERN = (
    r"(?:^|(?<=\n))[ \t]{0,4}(" + _NAME + r",?\s" + _NAME + r")"
    r"(?=[ \t]{1,4}(?:[A-Z]{0,3}\d{5,}|\d{1,2}/\d{1,2}/\d{2,4}|\d{4}-\d{2}-\d{2}|" + _DOB_MRN_LABEL + r"))"
    r"|(?<![A-Za-z])(" + _NAME + _INITIAL + r"\s" + _NAME + r"(?:\s" + _NAME + r")?)"
    r"(?=\s{1,2}\(?" + _DOB_MRN_LABEL + r")"
)

# Words that follow a role word, or head a line, in templates. A match
# containing one (after trailing trims) is not a name.
_STOP = frozenset({
    "ID", "Id", "Portal", "Education", "Instructions", "Information", "Info", "Name", "Number",
    "No", "Care", "Safety", "History", "Record", "Records", "Consent", "Summary", "Report",
    "Reports", "Reported", "States", "Stated", "Denies", "Denied", "Presents", "Presented",
    "Tolerated", "Complains", "Arrived", "Admits", "Admitted", "Visits", "Visit", "Notes",
    "Note", "Plan", "Status", "Satisfaction", "Experience", "Advocate", "Services", "Account",
    "Address", "Phone", "Email", "Signature", "Date", "Medications", "Allergies", "Location",
    "Room", "Bed", "Unit", "Type", "Class", "Follow", "Up", "Lab", "Labs", "Results", "Vitals",
    "Order", "Orders", "Discharge", "Admission", "Is", "Was", "Has", "Had", "The", "And", "Or",
    "Not", "To", "In", "On", "At", "With", "Of", "For",
})

# Trailing words trimmed off a name match, and never taken as a surname by
# extend_first_name.
_NOT_A_SURNAME = frozenset({
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday", "Saturday", "Sunday",
    "January", "February", "March", "April", "May", "June", "July", "August",
    "September", "October", "November", "December", "MD", "DO", "RN", "NP", "PA",
    "PhD", "DDS", "Hospital", "Clinic", "Center", "Medical", "Health", "Street", "Avenue",
    "Road",
}) | _STOP

_WORD_RE = re.compile(r"[A-Za-z]+(?:['-][A-Za-z]+)?")
_FOLLOWING_SURNAME_RE = re.compile(r" ((?:[A-Z]'|Ma?c)?[A-Z][a-z]+(?:-[A-Z]?[a-z]+)?)(?![A-Za-z'])")


def trim_name(text: str, start: int, end: int):
    """Return the end of the name in text[start:end], or None if not a name.

    Trailing credentials, weekdays and template words are trimmed ("Dr.
    Smith MD" -> "Smith"); a template word anywhere else rejects the match
    ("Patient Reports Chest Pain").
    """
    words = list(_WORD_RE.finditer(text, start, end))
    while words and words[-1].group() in _NOT_A_SURNAME:
        words.pop()
    if not words or any(w.group() in _STOP for w in words):
        return None
    return words[-1].end()


def extend_first_name(text: str, start: int, end: int) -> int:
    """Surname completion for a ONE-word NER PERSON span.

    "Thomas Parkinson asks..." where NER returned only "Thomas": extend the
    span over the directly following capitalised word, unless that word is
    a weekday, month, credential, place word or template word. Never over a
    possessive ("Parkinson's" is the disease, not the name).
    Returns the (possibly new) end offset.
    """
    if " " in text[start:end].strip():
        return end
    m = _FOLLOWING_SURNAME_RE.match(text, end)
    if not m or m.group(1) in _NOT_A_SURNAME:
        return end
    return m.end(1)


# Pattern keys -> the category they emit.
CATEGORY_ALIAS = {"ROLE_NAME": "PERSON", "HEADER_NAME": "PERSON"}
ROLE_NAME_CATEGORIES = frozenset(CATEGORY_ALIAS)
