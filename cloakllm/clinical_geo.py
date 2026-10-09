"""US ZIP codes in address context (v0.13.0, health edition).

HIPAA Safe Harbor (45 CFR 164.514(b)(2)(i)(B)) removes every geographic unit
smaller than a state, ZIP codes included. The initial three digits may stay
only where that three-digit area holds more than 20,000 people; otherwise
they become 000. Off by default: ShieldConfig.detect_zip_codes.

A ZIP is detected ONLY in address context -- after a state, or after a ZIP
label. A bare five-digit number is far more often a CPT code, a lab value or
an order number than a ZIP, and treating it as one would rebuild the decimal-
number bug of 0.12.x. State abbreviations must sit in a normal "City, ST"
address ("Springfield, IL 62704"): without that, "Patient ID 12345" reads as
Idaho, and IN, OR, OK, ME, HI are ordinary words. Full state names do not
need the comma.

Only the ZIP itself is detected (the pattern's single capture group, which
ends the match); the city and state stay readable.

Mirrors cloakllm-js src/clinical-geo.js exactly.
"""
from __future__ import annotations

_STATE_ABBR = (
    "AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|"
    "NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY|DC|PR|GU|VI|AS|MP"
)
_STATE_NAMES = (
    r"Alabama|Alaska|Arizona|Arkansas|California|Colorado|Connecticut|Delaware|Florida|Georgia|"
    r"Hawaii|Idaho|Illinois|Indiana|Iowa|Kansas|Kentucky|Louisiana|Maine|Maryland|Massachusetts|"
    r"Michigan|Minnesota|Mississippi|Missouri|Montana|Nebraska|Nevada|New\sHampshire|New\sJersey|"
    r"New\sMexico|New\sYork|North\sCarolina|North\sDakota|Ohio|Oklahoma|Oregon|Pennsylvania|"
    r"Rhode\sIsland|South\sCarolina|South\sDakota|Tennessee|Texas|Utah|Vermont|Virginia|Washington|"
    r"West\sVirginia|Wisconsin|Wyoming|District\sof\sColumbia|Puerto\sRico"
)
_ZIP_VALUE = r"(\d{5}(?:-\d{4})?)(?![\d-])"

# A state abbreviation counts only as "City, ST": a capitalised word, then the
# comma. A bare comma is not enough -- "12345, IN 47401 visits" and "OR 97201
# cases" are not addresses.
ZIP_PATTERN = (
    r"(?:(?<![A-Za-z])[A-Z][A-Za-z.'-]*,\s?(?:" + _STATE_ABBR + r")\.?\s{1,2}"
    + r"|\b(?:" + _STATE_NAMES + r")\s{1,2}"
    + r"|(?<![A-Za-z0-9])(?:ZIP|Zip|zip)(?:\s?(?:[Cc]ode|\+4))?\s{0,3}[:#]?\s{0,3}"
    + r"|(?<![A-Za-z0-9])[Pp]ostal\s[Cc]ode\s{0,3}[:#]?\s{0,3}"
    + r")" + _ZIP_VALUE
)

# --- Street addresses (Safe Harbor (B): "street address") -------------------
#
# House number + optional direction + 1-4 street-name words + a REQUIRED
# street suffix, then an optional unit. The suffix and the capitalised name
# words are the false-positive guard: without them "walk 3 blocks down the
# road" is an address. Accepted miss, stated in the docs: an all-lowercase
# address ("418 maple ave") is not caught.
#
# Category STREET_ADDRESS, not ADDRESS: ADDRESS belongs to the optional LLM
# pass, and the registry keeps regex and LLM categories apart.
_SUFFIXES = [
    "Street", "St", "Avenue", "Ave", "Av", "Road", "Rd", "Boulevard", "Blvd", "Drive", "Dr",
    "Lane", "Ln", "Court", "Ct", "Way", "Place", "Pl", "Parkway", "Pkwy", "Circle", "Cir",
    "Terrace", "Ter", "Highway", "Hwy", "Trail", "Trl", "Square", "Sq", "Loop", "Pike",
    "Plaza", "Plz", "Alley", "Aly", "Crescent", "Cres", "Ridge", "Rdg",
]
# Both "Ave" and "AVE" (an all-caps address); explicit, so both SDKs compile
# the same text without an ignore-case flag.
_SUFFIX = "(?:" + "|".join(sorted({s for x in _SUFFIXES for s in (x, x.upper())},
                                  key=lambda s: (-len(s), s))) + r")\b\.?"
_HOUSE = r"(?<![\w./-])\d{1,6}[A-Za-z]?(?:\s1/2)?"
_DIRECTION = r"(?:(?:North|South|East|West|NE|NW|SE|SW|N|S|E|W)\.?\s)?"
_NAME_WORD = r"(?:[A-Z][a-z]+|[A-Z]{2,}|\d{1,3}(?:st|nd|rd|th))"
_UNIT = (r"(?:,?\s(?:Apt|Apartment|Unit|Suite|Ste|Fl|Floor|Rm|Room|Bldg|APT|UNIT|SUITE|STE)\.?\s?#?\s?[A-Za-z0-9-]{1,6}"
         r"|,?\s#\s?[A-Za-z0-9-]{1,6})?")
_POST_DIRECTION = r"(?:\s(?:NE|NW|SE|SW|N|S|E|W)\b\.?)?"   # "Pennsylvania Avenue NW"
STREET_ADDRESS_PATTERN = (
    _HOUSE + r"\s" + _DIRECTION + _NAME_WORD + r"(?:\s" + _NAME_WORD + r"){0,3}\s" + _SUFFIX
    + _POST_DIRECTION + _UNIT
    + r"|(?<![A-Za-z])P\.?\s?O\.?\s?[Bb]ox\s\d{1,6}"
)


# HHS OCR de-identification guidance, FAQ 3.1: the three-digit ZIP areas with
# 20,000 or fewer people, from Census 2000. HHS itself says to use newer data
# when it exists, so this is a DEFAULT, overridable via
# ShieldConfig.zip3_restricted -- never a constant to rely on blindly.
DEFAULT_ZIP3_RESTRICTED = frozenset({
    "036", "059", "063", "102", "203", "556", "692", "790", "821",
    "823", "830", "831", "878", "879", "884", "890", "893",
})


def zip3(value: str, restricted=None) -> str:
    """Safe Harbor form of a ZIP: its first three digits, or 000 for a
    restricted area. The trailing XX shows the reader it was truncated."""
    restricted = DEFAULT_ZIP3_RESTRICTED if restricted is None else restricted
    prefix = value[:3]
    return ("000" if prefix in restricted else prefix) + "XX"
