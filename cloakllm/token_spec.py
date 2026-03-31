"""
CloakLLM Token Specification — canonical constants and validation.

This module is the single source of truth for token format, category
registry, and validation logic. Other modules (tokenizer, stream,
config) import from here instead of defining their own constants.

See TOKEN_SPEC.md in the hub repo for the full formal specification.
"""

from __future__ import annotations

import re

# --- Token format ---

# Canonical regex for matching CloakLLM tokens (with inner capture group)
CLOAKLLM_TOKEN_PATTERN = r"\[([A-Z][A-Z0-9_]*_(?:\d+|REDACTED))\]"
CLOAKLLM_TOKEN_REGEX = re.compile(CLOAKLLM_TOKEN_PATTERN)

# Parsing regex with named groups
_PARSE_PATTERN = re.compile(
    r"^\[(?P<category>[A-Z][A-Z0-9_]*)_(?P<suffix>\d+|REDACTED)\]$"
)

# Maximum token length (including brackets), used for streaming buffer
MAX_TOKEN_LENGTH = 40

# --- Escaping ---

ESCAPED_OPEN = "\uFF3B"
ESCAPED_CLOSE = "\uFF3D"

# --- Category name validation ---

CATEGORY_NAME_PATTERN = re.compile(r"^[A-Z][A-Z0-9_]*$")

# --- Built-in category registry ---

# Regex categories (Pass 1)
REGEX_CATEGORIES = frozenset({
    "EMAIL", "SSN", "CREDIT_CARD", "PHONE", "IP_ADDRESS",
    "API_KEY", "AWS_KEY", "JWT", "IBAN", "IL_ID",
})

# NER categories (Pass 2)
NER_CATEGORIES = frozenset({
    "PERSON", "ORG", "GPE", "FAC", "NORP", "MISC",
})

# LLM categories (Pass 3)
LLM_CATEGORIES = frozenset({
    "ADDRESS", "DATE_OF_BIRTH", "MEDICAL", "FINANCIAL",
    "NATIONAL_ID", "BIOMETRIC", "USERNAME", "PASSWORD", "VEHICLE",
})

# Locale-specific categories
LOCALE_CATEGORIES = frozenset({
    "PHONE_DE", "PHONE_DE_LAND", "VAT_DE",
    "PHONE_FR", "NIR_FR",
    "PHONE_ES", "DNI_ES", "NIE_ES",
    "PHONE_NL", "BSN_NL", "POSTAL_NL",
    "PHONE_IL", "PHONE_IL_LAND",
    "PHONE_CN", "NATIONAL_ID_CN",
    "PHONE_JP", "PHONE_JP_LAND", "MY_NUMBER_JP",
    "PHONE_RU", "PHONE_RU_LAND", "INN_RU", "SNILS_RU",
    "PHONE_KR", "PHONE_KR_LAND", "RRN_KR",
    "PHONE_IT", "PHONE_IT_LAND", "CODICE_FISCALE_IT",
    "PHONE_PL", "NIP_PL", "PESEL_PL",
    "PHONE_PT", "PHONE_BR", "CPF_BR",
    "PHONE_IN", "AADHAAR_IN", "PAN_IN",
})

# All built-in categories combined
BUILTIN_CATEGORIES = REGEX_CATEGORIES | NER_CATEGORIES | LLM_CATEGORIES | LOCALE_CATEGORIES

# Reserved categories that custom patterns must not use
RESERVED_CATEGORIES = BUILTIN_CATEGORIES


# --- Validation functions ---

def validate_token(token: str) -> bool:
    """Return True if the string is a valid CloakLLM token."""
    if len(token) > MAX_TOKEN_LENGTH:
        return False
    return _PARSE_PATTERN.match(token) is not None


def parse_token(token: str) -> tuple[str, str] | None:
    """Parse a token string into (category, suffix) or return None."""
    m = _PARSE_PATTERN.match(token)
    if m is None:
        return None
    return m.group("category"), m.group("suffix")


def is_redacted_token(token: str) -> bool:
    """Return True if the token is a redacted token ([CATEGORY_REDACTED])."""
    result = parse_token(token)
    if result is None:
        return False
    return result[1] == "REDACTED"


def validate_category_name(name: str) -> bool:
    """Check if a category name is valid (format only, no collision check)."""
    return CATEGORY_NAME_PATTERN.match(name) is not None
