"""
Locale-specific PII regex patterns.

Each locale defines additional regex patterns that supplement the
universal patterns (EMAIL, SSN, CREDIT_CARD, etc.). Patterns are
designed for low false-positive rates with validation where possible.
"""

LOCALE_PATTERNS: dict[str, list[tuple[str, str, str]]] = {
    # Format: (category_name, hint_keyword, regex_pattern)

    "de": [
        # German mobile: +49 15x/16x/17x or 015x/016x/017x
        ("PHONE_DE", "phone", r"(?:\+49\s?|0)[1][5-7]\d[\s\-]?\d{3,4}[\s\-]?\d{4}"),
        # German landline: +49 or 0 + area code + number
        ("PHONE_DE_LAND", "phone", r"(?:\+49\s?|0)[2-9]\d{1,4}[\s\-\/]?\d{3,8}"),
        # German VAT ID: DE + 9 digits
        ("VAT_DE", "vat", r"\bDE\d{9}\b"),
    ],

    "fr": [
        # French phone: +33 X XX XX XX XX or 0X XX XX XX XX
        ("PHONE_FR", "phone", r"(?:\+33\s?|0)[1-9](?:[\s\.\-]?\d{2}){4}"),
        # French NIR (social security): 1/2 + YY + MM + dept + commune + order + key
        ("NIR_FR", "national_id",
         r"\b[12]\s?\d{2}\s?(?:0[1-9]|1[0-2])\s?(?:\d{2}|2[AB])\s?\d{3}\s?\d{3}\s?\d{2}\b"),
    ],

    "es": [
        # Spanish phone: +34 or 6/7/8/9 + 8 digits
        ("PHONE_ES", "phone", r"(?:\+34\s?)?[6-9]\d{2}[\s\-]?\d{2,3}[\s\-]?\d{2,3}[\s\-]?\d{2,3}"),
        # Spanish DNI: 8 digits + check letter
        ("DNI_ES", "national_id", r"\b\d{8}[A-HJ-NP-TV-Z]\b"),
        # Spanish NIE: X/Y/Z + 7 digits + check letter
        ("NIE_ES", "national_id", r"\b[XYZ]\d{7}[A-HJ-NP-TV-Z]\b"),
    ],

    "nl": [
        # Dutch phone: +31 or 06 mobile
        ("PHONE_NL", "phone", r"(?:\+31\s?[1-9]\d|06)[\s\-]?\d{4}[\s\-]?\d{4}"),
        # Dutch postal code: 4 digits + 2 letters (e.g., 1234 AB)
        ("POSTAL_NL", "postal_code", r"\b\d{4}\s?[A-Z]{2}\b"),
        # Dutch BSN: 9 digits (citizen service number) — validated with context anchor
        ("BSN_NL", "national_id",
         r"(?i)(?:bsn|burgerservicenummer|sofi)[\s:]*(\d{9})\b"),
    ],

    "he": [
        # Israeli mobile: 05X-XXX-XXXX
        ("PHONE_IL", "phone", r"(?:\+972[\s\-]?|0)5[0-9][\s\-]?\d{3}[\s\-]?\d{4}"),
        # Israeli landline: 0X-XXXXXXX
        ("PHONE_IL_LAND", "phone", r"(?:\+972[\s\-]?|0)[2-489][\s\-]?\d{7}"),
    ],

    "zh": [
        # Chinese National ID: 18 digits (6 region + 8 birthdate + 3 seq + 1 check)
        # Must come before PHONE_CN to prevent partial matches on IDs
        ("NATIONAL_ID_CN", "national_id",
         r"\b\d{6}(?:19|20)\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])\d{3}[\dXx]\b"),
        # Chinese mobile: 1XX-XXXX-XXXX
        ("PHONE_CN", "phone", r"(?:\+86\s?)?1[3-9]\d[\s\-]?\d{4}[\s\-]?\d{4}"),
    ],

    "ja": [
        # Japanese mobile: 070/080/090-XXXX-XXXX
        ("PHONE_JP", "phone", r"(?:\+81\s?|0)[789]0[\s\-]?\d{4}[\s\-]?\d{4}"),
        # Japanese landline
        ("PHONE_JP_LAND", "phone", r"(?:\+81\s?|0)[1-9]\d{0,3}[\s\-]?\d{2,4}[\s\-]?\d{4}"),
        # Japanese My Number: 12 digits (with context anchor to reduce FP)
        ("MY_NUMBER_JP", "national_id",
         r"(?i)(?:マイナンバー|my\s?number)[\s:]*(\d{12})\b"),
    ],

    "ru": [
        # Russian mobile: +7 9XX or 8 9XX + 7 digits
        ("PHONE_RU", "phone",
         r"(?:\+7|8)[\s\-]?\(?9\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"),
        # Russian landline: +7 or 8 + area code + number
        ("PHONE_RU_LAND", "phone",
         r"(?:\+7|8)[\s\-]?\(?[3-8]\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2}"),
        # SNILS (social insurance): XXX-XXX-XXX XX
        ("SNILS_RU", "national_id",
         r"\b\d{3}-\d{3}-\d{3}\s\d{2}\b"),
        # INN (Tax ID): context-anchored (bare 10/12 digits too broad)
        ("INN_RU", "national_id",
         r"(?i)(?:инн|inn)[\s:]*(\d{10}(?:\d{2})?)\b"),
    ],

    "ko": [
        # Korean mobile: 010-XXXX-XXXX or +82-10-XXXX-XXXX
        ("PHONE_KR", "phone",
         r"(?:\+82[\s\-]?)?0?1[016789][\s\-]?\d{3,4}[\s\-]?\d{4}"),
        # Korean landline: 02-XXXX-XXXX (Seoul) or 0XX-XXX-XXXX
        ("PHONE_KR_LAND", "phone",
         r"(?:\+82[\s\-]?)?0[2-6]\d?[\s\-]?\d{3,4}[\s\-]?\d{4}"),
        # Resident Registration Number: YYMMDD-XXXXXXX (13 digits)
        ("RRN_KR", "national_id",
         r"\b\d{2}(?:0[1-9]|1[0-2])(?:0[1-9]|[12]\d|3[01])[\s\-]\d{7}\b"),
    ],

    "it": [
        # Italian mobile: +39 3XX XXXXXXX
        ("PHONE_IT", "phone",
         r"(?:\+39[\s\-]?)?3\d{2}[\s\-]?\d{6,7}"),
        # Italian landline: +39 0X(X) XXXXXXXX
        ("PHONE_IT_LAND", "phone",
         r"(?:\+39[\s\-]?)?0\d{1,3}[\s\-]?\d{4,8}"),
        # Codice Fiscale: 16-char alphanumeric (LLLLLL##L##L###L)
        ("CODICE_FISCALE_IT", "national_id",
         r"\b[A-Z]{6}\d{2}[ABCDEHLMPRST](?:[0-4]\d|[5-7][01])[A-Z]\d{3}[A-Z]\b"),
    ],

    "pl": [
        # Polish mobile: +48 or 0 + 9 digits
        ("PHONE_PL", "phone",
         r"(?:\+48[\s\-]?)?\d{3}[\s\-]?\d{3}[\s\-]?\d{3}"),
        # PESEL (national ID): 11 digits with date-encoded first 6
        ("PESEL_PL", "national_id",
         r"(?i)(?:pesel)[\s:]*(\d{2}(?:[02468][1-9]|[13579][012])(?:0[1-9]|[12]\d|3[01])\d{5})\b"),
        # NIP (tax ID): XXX-XXX-XX-XX or XXX-XX-XX-XXX (with context anchor)
        ("NIP_PL", "national_id",
         r"(?i)(?:nip)[\s:]*(\d{3}-?\d{3}-?\d{2}-?\d{2})\b"),
    ],

    "pt": [
        # Portuguese phone: +351 9XX XXX XXX (mobile)
        ("PHONE_PT", "phone",
         r"(?:\+351[\s\-]?)?9[1236]\d[\s\-]?\d{3}[\s\-]?\d{3}"),
        # Brazilian phone: +55 (XX) 9XXXX-XXXX (mobile)
        ("PHONE_BR", "phone",
         r"(?:\+55[\s\-]?)?\(?[1-9]\d\)?[\s\-]?9?\d{4}[\s\-]?\d{4}"),
        # Brazilian CPF: XXX.XXX.XXX-XX (formatted only — bare 11 digits too broad)
        ("CPF_BR", "national_id",
         r"\b\d{3}\.\d{3}\.\d{3}-\d{2}\b"),
    ],

    "hi": [
        # Indian mobile: +91 or 0 + 10 digits starting with 6-9
        ("PHONE_IN", "phone",
         r"(?:\+91[\s\-]?)?[6-9]\d{4}[\s\-]?\d{5}"),
        # PAN card: 5 letters (4th restricted) + 4 digits + 1 letter
        ("PAN_IN", "national_id",
         r"\b[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]\b"),
        # Aadhaar: 12 digits in 4-4-4 format (context-anchored)
        ("AADHAAR_IN", "national_id",
         r"(?i)(?:aadhaar|आधार|uidai)[\s:]*([2-9]\d{3}[\s\-]?\d{4}[\s\-]?\d{4})\b"),
    ],
}
