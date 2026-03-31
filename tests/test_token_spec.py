"""Tests for the CloakLLM Token Specification module."""

import pytest

from cloakllm.token_spec import (
    BUILTIN_CATEGORIES,
    CATEGORY_NAME_PATTERN,
    CLOAKLLM_TOKEN_PATTERN,
    CLOAKLLM_TOKEN_REGEX,
    ESCAPED_CLOSE,
    ESCAPED_OPEN,
    LOCALE_CATEGORIES,
    LLM_CATEGORIES,
    MAX_TOKEN_LENGTH,
    NER_CATEGORIES,
    REGEX_CATEGORIES,
    RESERVED_CATEGORIES,
    is_redacted_token,
    parse_token,
    validate_category_name,
    validate_token,
)


class TestValidateToken:
    """Tests for validate_token()."""

    def test_simple_tokens(self):
        assert validate_token("[EMAIL_0]")
        assert validate_token("[PERSON_1]")
        assert validate_token("[CREDIT_CARD_99]")
        assert validate_token("[SSN_0]")

    def test_redacted_tokens(self):
        assert validate_token("[EMAIL_REDACTED]")
        assert validate_token("[PERSON_REDACTED]")
        assert validate_token("[CREDIT_CARD_REDACTED]")

    def test_multi_word_categories(self):
        assert validate_token("[DATE_OF_BIRTH_0]")
        assert validate_token("[IP_ADDRESS_3]")
        assert validate_token("[API_KEY_REDACTED]")

    def test_category_with_digits(self):
        assert validate_token("[PHONE2_0]")
        assert validate_token("[V1_0]")

    def test_invalid_lowercase(self):
        assert not validate_token("[email_0]")
        assert not validate_token("[Person_1]")

    def test_invalid_missing_brackets(self):
        assert not validate_token("EMAIL_0")
        assert not validate_token("[EMAIL_0")
        assert not validate_token("EMAIL_0]")

    def test_invalid_empty(self):
        assert not validate_token("")
        assert not validate_token("[]")

    def test_invalid_no_suffix(self):
        assert not validate_token("[EMAIL]")

    def test_invalid_starts_with_digit(self):
        assert not validate_token("[1EMAIL_0]")

    def test_invalid_starts_with_underscore(self):
        assert not validate_token("[_EMAIL_0]")

    def test_invalid_special_chars(self):
        assert not validate_token("[EMAIL-ADDR_0]")
        assert not validate_token("[EMAIL.ADDR_0]")

    def test_too_long(self):
        long_cat = "A" * 38  # [A...A_0] = 38 + 4 = 42 > 40
        assert not validate_token(f"[{long_cat}_0]")

    def test_max_length_boundary(self):
        # Exactly 40 chars: [AAAA...A_0] where category has 36 chars
        cat = "A" * 36  # [A*36_0] = 1 + 36 + 1 + 1 + 1 = 40
        assert validate_token(f"[{cat}_0]")
        cat2 = "A" * 37  # 41 chars
        assert not validate_token(f"[{cat2}_0]")

    def test_negative_counter(self):
        # Regex doesn't match negative numbers
        assert not validate_token("[EMAIL_-1]")

    def test_counter_with_leading_zeros(self):
        # Currently allows leading zeros (spec says non-negative integer)
        assert validate_token("[EMAIL_00]")
        assert validate_token("[EMAIL_01]")


class TestParseToken:
    """Tests for parse_token()."""

    def test_basic(self):
        assert parse_token("[EMAIL_0]") == ("EMAIL", "0")
        assert parse_token("[PERSON_42]") == ("PERSON", "42")

    def test_redacted(self):
        assert parse_token("[SSN_REDACTED]") == ("SSN", "REDACTED")

    def test_multi_word(self):
        assert parse_token("[DATE_OF_BIRTH_3]") == ("DATE_OF_BIRTH", "3")
        assert parse_token("[IP_ADDRESS_REDACTED]") == ("IP_ADDRESS", "REDACTED")

    def test_invalid_returns_none(self):
        assert parse_token("not a token") is None
        assert parse_token("[email_0]") is None
        assert parse_token("") is None
        assert parse_token("[EMAIL]") is None


class TestIsRedactedToken:
    """Tests for is_redacted_token()."""

    def test_redacted(self):
        assert is_redacted_token("[EMAIL_REDACTED]")
        assert is_redacted_token("[PERSON_REDACTED]")

    def test_not_redacted(self):
        assert not is_redacted_token("[EMAIL_0]")
        assert not is_redacted_token("[PERSON_1]")

    def test_invalid(self):
        assert not is_redacted_token("not a token")
        assert not is_redacted_token("")


class TestValidateCategoryName:
    """Tests for validate_category_name()."""

    def test_valid(self):
        assert validate_category_name("EMAIL")
        assert validate_category_name("CREDIT_CARD")
        assert validate_category_name("DATE_OF_BIRTH")
        assert validate_category_name("V2")
        assert validate_category_name("A")

    def test_invalid_lowercase(self):
        assert not validate_category_name("email")
        assert not validate_category_name("Email")

    def test_invalid_starts_with_digit(self):
        assert not validate_category_name("1EMAIL")

    def test_invalid_starts_with_underscore(self):
        assert not validate_category_name("_EMAIL")

    def test_invalid_special_chars(self):
        assert not validate_category_name("EMAIL-ADDR")
        assert not validate_category_name("EMAIL ADDR")

    def test_empty(self):
        assert not validate_category_name("")


class TestCategoryRegistry:
    """Tests for built-in category sets."""

    def test_builtin_is_union(self):
        assert BUILTIN_CATEGORIES == (
            REGEX_CATEGORIES | NER_CATEGORIES | LLM_CATEGORIES | LOCALE_CATEGORIES
        )

    def test_reserved_equals_builtin(self):
        assert RESERVED_CATEGORIES == BUILTIN_CATEGORIES

    def test_no_overlap_regex_ner(self):
        assert REGEX_CATEGORIES & NER_CATEGORIES == set()

    def test_no_overlap_regex_llm(self):
        assert REGEX_CATEGORIES & LLM_CATEGORIES == set()

    def test_no_overlap_ner_llm(self):
        assert NER_CATEGORIES & LLM_CATEGORIES == set()

    def test_all_names_valid(self):
        for cat in BUILTIN_CATEGORIES:
            assert validate_category_name(cat), f"{cat} is not a valid category name"

    def test_known_categories_present(self):
        assert "EMAIL" in REGEX_CATEGORIES
        assert "PERSON" in NER_CATEGORIES
        assert "ADDRESS" in LLM_CATEGORIES
        assert "PHONE_DE" in LOCALE_CATEGORIES


class TestTokenRegex:
    """Tests for the canonical token regex."""

    def test_finds_tokens_in_text(self):
        text = "Hello [PERSON_0], your email is [EMAIL_1]."
        matches = CLOAKLLM_TOKEN_REGEX.findall(text)
        assert matches == ["PERSON_0", "EMAIL_1"]

    def test_finds_redacted(self):
        text = "Contact [EMAIL_REDACTED] for info."
        matches = CLOAKLLM_TOKEN_REGEX.findall(text)
        assert matches == ["EMAIL_REDACTED"]

    def test_no_match_lowercase(self):
        text = "This [email_0] is not a token."
        matches = CLOAKLLM_TOKEN_REGEX.findall(text)
        assert matches == []


class TestConstants:
    """Tests for module constants."""

    def test_max_token_length(self):
        assert MAX_TOKEN_LENGTH == 40

    def test_escaped_brackets(self):
        assert ESCAPED_OPEN == "\uFF3B"
        assert ESCAPED_CLOSE == "\uFF3D"


class TestConfigIntegration:
    """Tests for config validation using token_spec."""

    def test_custom_category_reserved_name_rejected(self):
        from cloakllm.config import ShieldConfig
        with pytest.raises(ValueError, match="conflicts with built-in"):
            ShieldConfig(custom_llm_categories=[("EMAIL", "email addresses")])

    def test_custom_category_invalid_format_rejected(self):
        from cloakllm.config import ShieldConfig
        with pytest.raises(ValueError, match="Must match"):
            ShieldConfig(custom_llm_categories=[("lowercase", "bad")])

    def test_custom_category_valid_name_accepted(self):
        from cloakllm.config import ShieldConfig
        config = ShieldConfig(custom_llm_categories=[("MY_CUSTOM_TYPE", "custom")])
        assert len(config.custom_llm_categories) == 1
