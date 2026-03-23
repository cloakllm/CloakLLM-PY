"""Tests for multi-language PII detection."""
import pytest
from cloakllm import Shield, ShieldConfig


class TestLocaleConfig:
    def test_default_locale_is_en(self):
        config = ShieldConfig(audit_enabled=False)
        assert config.locale == "en"
        assert config.spacy_model == "en_core_web_sm"

    def test_locale_auto_selects_model(self):
        config = ShieldConfig(audit_enabled=False, locale="de")
        assert config.spacy_model == "de_core_news_sm"

    def test_locale_explicit_model_override(self):
        config = ShieldConfig(audit_enabled=False, locale="de", spacy_model="de_core_news_lg")
        assert config.spacy_model == "de_core_news_lg"

    def test_locale_multi_selects_xx_model(self):
        config = ShieldConfig(audit_enabled=False, locale="multi")
        assert config.spacy_model == "xx_ent_wiki_sm"

    def test_unknown_locale_keeps_default_model(self):
        config = ShieldConfig(audit_enabled=False, locale="xx")
        assert config.spacy_model == "en_core_web_sm"


class TestLocaleRegexPatterns:
    """Test locale-specific regex detection (no spaCy needed)."""

    def test_german_phone(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="de"))
        sanitized, tm = shield.sanitize("Rufen Sie an: +49 171 1234567")
        assert "[PHONE_DE_0]" in sanitized

    def test_german_vat(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="de"))
        sanitized, tm = shield.sanitize("USt-IdNr: DE123456789")
        assert "[VAT_DE_0]" in sanitized

    def test_french_phone(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="fr"))
        sanitized, tm = shield.sanitize("Appelez le +33 1 23 45 67 89")
        assert "[PHONE_FR_0]" in sanitized

    def test_french_nir(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="fr"))
        sanitized, tm = shield.sanitize("Mon NIR: 1 85 01 75 123 456 78")
        assert "[NIR_FR_0]" in sanitized

    def test_spanish_dni(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="es"))
        sanitized, tm = shield.sanitize("Mi DNI es 12345678A")
        assert "[DNI_ES_0]" in sanitized

    def test_spanish_nie(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="es"))
        sanitized, tm = shield.sanitize("NIE: X1234567A")
        assert "[NIE_ES_0]" in sanitized

    def test_dutch_phone(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="nl"))
        sanitized, tm = shield.sanitize("Bel 06 1234 5678")
        assert "[PHONE_NL_0]" in sanitized

    def test_dutch_postal(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="nl"))
        sanitized, tm = shield.sanitize("Adres: 1234 AB Amsterdam")
        assert "[POSTAL_NL_0]" in sanitized

    def test_israeli_mobile(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="he"))
        sanitized, tm = shield.sanitize("טלפון: 054-123-4567")
        assert "[PHONE_IL_0]" in sanitized

    def test_chinese_mobile(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="zh"))
        sanitized, tm = shield.sanitize("手机号: 13912345678")
        assert "[PHONE_CN_0]" in sanitized

    def test_chinese_national_id(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="zh"))
        sanitized, tm = shield.sanitize("身份证号: 110101199001011234")
        assert "[NATIONAL_ID_CN_0]" in sanitized

    def test_japanese_mobile(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="ja"))
        sanitized, tm = shield.sanitize("電話番号: 090-1234-5678")
        assert "[PHONE_JP_0]" in sanitized

    def test_russian_phone(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="ru"))
        sanitized, tm = shield.sanitize("Позвоните: +7 (912) 345-67-89")
        assert "[PHONE_RU_0]" in sanitized

    def test_russian_snils(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="ru"))
        sanitized, tm = shield.sanitize("СНИЛС: 123-456-789 01")
        assert "[SNILS_RU_0]" in sanitized

    def test_korean_phone(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="ko"))
        sanitized, tm = shield.sanitize("전화번호: 010-1234-5678")
        assert "[PHONE_KR_0]" in sanitized

    def test_korean_rrn(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="ko"))
        sanitized, tm = shield.sanitize("주민등록번호: 900315-1234567")
        assert "[RRN_KR_0]" in sanitized

    def test_italian_codice_fiscale(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="it"))
        sanitized, tm = shield.sanitize("Codice Fiscale: RSSMRA85M01H501U")
        assert "[CODICE_FISCALE_IT_0]" in sanitized

    def test_italian_phone(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="it"))
        sanitized, tm = shield.sanitize("Telefono: +39 320 1234567")
        assert "[PHONE_IT_0]" in sanitized

    def test_polish_phone(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="pl"))
        sanitized, tm = shield.sanitize("Telefon: +48 512 345 678")
        assert "[PHONE_PL_0]" in sanitized

    def test_brazilian_cpf(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="pt"))
        sanitized, tm = shield.sanitize("CPF: 123.456.789-09")
        assert "[CPF_BR_0]" in sanitized

    def test_portuguese_phone(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="pt"))
        sanitized, tm = shield.sanitize("Telefone: +351 912 345 678")
        assert "[PHONE_PT_0]" in sanitized

    def test_indian_pan(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="hi"))
        sanitized, tm = shield.sanitize("PAN: ABCPD1234E")
        assert "[PAN_IN_0]" in sanitized

    def test_indian_phone(self):
        shield = Shield(ShieldConfig(audit_enabled=False, locale="hi"))
        sanitized, tm = shield.sanitize("Phone: +91 98765 43210")
        assert "[PHONE_IN_0]" in sanitized

    def test_locale_en_no_locale_patterns(self):
        """English locale should not add locale-specific patterns."""
        shield = Shield(ShieldConfig(audit_enabled=False, locale="en"))
        # DNI format should NOT be detected in English locale
        sanitized, tm = shield.sanitize("Code 12345678A")
        assert "[DNI_ES" not in sanitized

    def test_universal_patterns_still_work(self):
        """Locale patterns supplement, not replace, universal patterns."""
        shield = Shield(ShieldConfig(audit_enabled=False, locale="de"))
        sanitized, tm = shield.sanitize("Email: hans@example.de, Phone: +49 171 1234567")
        assert "[EMAIL_0]" in sanitized
        assert "[PHONE_DE_0]" in sanitized


class TestNerLabelMapping:
    """Test NER label normalization for non-English models."""

    def test_per_mapped_to_person(self):
        """PER (WikiNER: de, fr, es, it, pt, ru) should be mapped to PERSON."""
        from cloakllm.detector import _NER_LABEL_MAP
        assert _NER_LABEL_MAP["PER"] == "PERSON"

    def test_loc_mapped_to_gpe(self):
        from cloakllm.detector import _NER_LABEL_MAP
        assert _NER_LABEL_MAP["LOC"] == "GPE"

    def test_korean_labels_mapped(self):
        """KLUE labels (ko)."""
        from cloakllm.detector import _NER_LABEL_MAP
        assert _NER_LABEL_MAP["PS"] == "PERSON"
        assert _NER_LABEL_MAP["OG"] == "ORG"
        assert _NER_LABEL_MAP["LC"] == "GPE"

    def test_polish_labels_mapped(self):
        """NKJP labels (pl)."""
        from cloakllm.detector import _NER_LABEL_MAP
        assert _NER_LABEL_MAP["persName"] == "PERSON"
        assert _NER_LABEL_MAP["orgName"] == "ORG"
        assert _NER_LABEL_MAP["placeName"] == "GPE"
        assert _NER_LABEL_MAP["geogName"] == "GPE"

    def test_ontonotes_labels_pass_through(self):
        """OntoNotes labels (en, nl, zh, ja) pass through unchanged."""
        from cloakllm.detector import _NER_LABEL_MAP
        assert _NER_LABEL_MAP["PERSON"] == "PERSON"
        assert _NER_LABEL_MAP["ORG"] == "ORG"
        assert _NER_LABEL_MAP["GPE"] == "GPE"
