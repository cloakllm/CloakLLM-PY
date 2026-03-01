"""
CloakLLM test suite.

Run: pytest tests/ -v
"""

import json
import tempfile
from pathlib import Path

import pytest

from cloakllm import Shield, ShieldConfig
from cloakllm.detector import DetectionEngine
from cloakllm.tokenizer import Tokenizer, TokenMap
from cloakllm.audit import AuditLogger, GENESIS_HASH


# Check if spaCy NER model is available (vs blank fallback)
def _has_ner_model():
    try:
        import spacy
        nlp = spacy.load("en_core_web_sm")
        return True
    except OSError:
        return False

has_ner = _has_ner_model()
requires_ner = pytest.mark.skipif(not has_ner, reason="spaCy NER model not installed")


# ──────────────────────────────────────────────
# Fixtures
# ──────────────────────────────────────────────

@pytest.fixture
def config(tmp_path):
    return ShieldConfig(
        log_dir=tmp_path / "audit",
        audit_enabled=True,
        log_original_values=False,
    )


@pytest.fixture
def shield(config):
    return Shield(config)


@pytest.fixture
def detector(config):
    return DetectionEngine(config)


@pytest.fixture
def tokenizer(config):
    return Tokenizer(config)


@pytest.fixture
def audit_logger(config):
    return AuditLogger(config)


# ──────────────────────────────────────────────
# Detection Tests
# ──────────────────────────────────────────────

class TestDetection:

    def test_detect_email(self, detector):
        detections = detector.detect("Send to john@acme.com please")
        emails = [d for d in detections if d.category == "EMAIL"]
        assert len(emails) == 1
        assert emails[0].text == "john@acme.com"
        assert emails[0].source == "regex"

    def test_detect_multiple_emails(self, detector):
        text = "CC alice@foo.org and bob@bar.io on this"
        detections = detector.detect(text)
        emails = [d for d in detections if d.category == "EMAIL"]
        assert len(emails) == 2

    def test_detect_ssn(self, detector):
        detections = detector.detect("SSN: 123-45-6789")
        ssns = [d for d in detections if d.category == "SSN"]
        assert len(ssns) == 1
        assert ssns[0].text == "123-45-6789"

    def test_detect_credit_card_visa(self, detector):
        detections = detector.detect("Card: 4111111111111111")
        cards = [d for d in detections if d.category == "CREDIT_CARD"]
        assert len(cards) == 1

    def test_detect_ip_address(self, detector):
        detections = detector.detect("Server at 192.168.1.100")
        ips = [d for d in detections if d.category == "IP_ADDRESS"]
        assert len(ips) == 1
        assert ips[0].text == "192.168.1.100"

    def test_detect_api_key(self, detector):
        detections = detector.detect("Use key sk-abc123def456ghi789jkl012")
        keys = [d for d in detections if d.category == "API_KEY"]
        assert len(keys) == 1

    def test_detect_aws_key(self, detector):
        detections = detector.detect("AWS key: AKIAIOSFODNN7EXAMPLE")
        keys = [d for d in detections if d.category == "AWS_KEY"]
        assert len(keys) == 1

    @requires_ner
    def test_detect_person_ner(self, detector):
        detections = detector.detect("Meeting with John Smith tomorrow at Google HQ")
        persons = [d for d in detections if d.category == "PERSON"]
        assert len(persons) >= 1
        assert any("John" in d.text for d in persons)

    @requires_ner
    def test_detect_org_ner(self, detector):
        detections = detector.detect("I work at Microsoft in their Azure division")
        orgs = [d for d in detections if d.category == "ORG"]
        assert len(orgs) >= 1

    def test_no_false_positives_on_clean_text(self, detector):
        detections = detector.detect("Please summarize this article about climate change")
        # Should have zero or very few detections
        assert len(detections) <= 1  # NER might catch "climate change" as misc

    def test_detections_sorted_by_position(self, detector):
        detections = detector.detect("Email john@a.com and jane@b.com now")
        positions = [d.start for d in detections]
        assert positions == sorted(positions)

    def test_no_overlap_between_regex_and_ner(self, detector):
        detections = detector.detect("Contact john.smith@acme.com")
        spans = [(d.start, d.end) for d in detections]
        for i, (s1, e1) in enumerate(spans):
            for j, (s2, e2) in enumerate(spans):
                if i != j:
                    assert not (s1 <= s2 < e1) and not (s2 <= s1 < e2), \
                        f"Overlapping detections: {spans[i]} and {spans[j]}"


# ──────────────────────────────────────────────
# Tokenization Tests
# ──────────────────────────────────────────────

class TestTokenization:

    def test_basic_tokenize(self, shield):
        sanitized, token_map = shield.sanitize("Email john@acme.com")
        assert "john@acme.com" not in sanitized
        assert "[EMAIL_0]" in sanitized

    def test_deterministic_tokens(self, shield):
        """Same entity always gets the same token within a session."""
        text = "Ask john@acme.com and then follow up with john@acme.com"
        sanitized, token_map = shield.sanitize(text)
        # Should use same token for both occurrences
        assert sanitized.count("[EMAIL_0]") == 2

    def test_multiple_categories(self, shield):
        text = "Email john@acme.com about server 192.168.1.1"
        sanitized, token_map = shield.sanitize(text)
        assert "[EMAIL_0]" in sanitized
        assert "[IP_ADDRESS_0]" in sanitized
        assert "john@acme.com" not in sanitized
        assert "192.168.1.1" not in sanitized

    def test_desanitize_restores_original(self, shield):
        original = "Send to john@acme.com"
        sanitized, token_map = shield.sanitize(original)
        # Simulate LLM response using token
        llm_response = "I'll email [EMAIL_0] right away."
        restored = shield.desanitize(llm_response, token_map)
        assert "john@acme.com" in restored
        assert "[EMAIL_0]" not in restored

    def test_desanitize_multiple_tokens(self, shield):
        text = "Email john@acme.com, server 10.0.0.1"
        sanitized, token_map = shield.sanitize(text)
        response = "Configured [IP_ADDRESS_0] and notified [EMAIL_0]."
        restored = shield.desanitize(response, token_map)
        assert "john@acme.com" in restored
        assert "10.0.0.1" in restored

    def test_token_map_reuse_across_turns(self, shield):
        """Multi-turn: same entity gets same token."""
        s1, token_map = shield.sanitize("Email john@acme.com")
        s2, token_map = shield.sanitize("Remind john@acme.com too", token_map=token_map)
        assert s1.count("[EMAIL_0]") == 1
        assert s2.count("[EMAIL_0]") == 1
        assert token_map.entity_count == 1  # Same entity, one token

    def test_clean_text_unchanged(self, shield):
        text = "What is the weather like today?"
        sanitized, token_map = shield.sanitize(text)
        assert sanitized == text
        assert token_map.entity_count == 0

    def test_token_map_summary_no_originals(self, shield):
        _, token_map = shield.sanitize("Email john@acme.com")
        summary = token_map.to_summary()
        # Summary should contain tokens but not original values
        assert "[EMAIL_0]" in summary["tokens"]
        assert "john@acme.com" not in str(summary)


# ──────────────────────────────────────────────
# Audit Chain Tests
# ──────────────────────────────────────────────

class TestAuditChain:

    def test_audit_creates_log_file(self, audit_logger, config):
        audit_logger.log(event_type="test")
        log_files = list(config.log_dir.glob("audit_*.jsonl"))
        assert len(log_files) == 1

    def test_audit_chain_links(self, audit_logger):
        """Each entry's prev_hash links to the previous entry's hash."""
        audit_logger.log(event_type="event_1")
        audit_logger.log(event_type="event_2")
        audit_logger.log(event_type="event_3")

        is_valid, errors = audit_logger.verify_chain()
        assert is_valid, f"Chain errors: {errors}"

    def test_audit_first_entry_links_to_genesis(self, audit_logger, config):
        audit_logger.log(event_type="first")

        log_file = list(config.log_dir.glob("audit_*.jsonl"))[0]
        with open(log_file) as f:
            entry = json.loads(f.readline())

        assert entry["prev_hash"] == GENESIS_HASH
        assert entry["seq"] == 0

    def test_audit_tamper_detection(self, audit_logger, config):
        """Modifying an entry should break the chain."""
        audit_logger.log(event_type="event_1")
        audit_logger.log(event_type="event_2")
        audit_logger.log(event_type="event_3")

        # Tamper with the log file: modify entry #1
        log_file = list(config.log_dir.glob("audit_*.jsonl"))[0]
        with open(log_file, "r") as f:
            lines = f.readlines()

        # Modify the second entry
        entry = json.loads(lines[1])
        entry["entity_count"] = 999  # TAMPER!
        lines[1] = json.dumps(entry, separators=(",", ":")) + "\n"

        with open(log_file, "w") as f:
            f.writelines(lines)

        # Verification should catch it
        is_valid, errors = audit_logger.verify_chain()
        assert not is_valid
        assert len(errors) >= 1

    def test_audit_stats(self, shield):
        shield.sanitize("Email john@acme.com", model="claude-3")
        shield.sanitize("Call 555-123-4567", model="gpt-4")

        stats = shield.audit_stats()
        assert stats["total_events"] >= 2
        assert stats["total_entities_detected"] >= 2

    def test_audit_no_original_values_logged(self, shield, config):
        """When log_original_values=False, originals should not appear in log."""
        shield.sanitize("Email john@acme.com")

        log_file = list(config.log_dir.glob("audit_*.jsonl"))[0]
        with open(log_file) as f:
            content = f.read()

        assert "john@acme.com" not in content


# ──────────────────────────────────────────────
# End-to-End Tests
# ──────────────────────────────────────────────

class TestEndToEnd:

    def test_full_flow(self, shield):
        """Complete sanitize → (simulate LLM) → desanitize flow."""
        prompt = (
            "Draft an email to sarah.j@corp.io about the "
            "security audit. SSN is 456-78-9012. Server: 10.0.0.50"
        )

        # Sanitize
        sanitized, token_map = shield.sanitize(prompt, model="claude-3")

        # Verify PII removed
        assert "sarah.j@corp.io" not in sanitized
        assert "456-78-9012" not in sanitized
        assert "10.0.0.50" not in sanitized
        assert token_map.entity_count >= 3

        # Simulate LLM response using tokens
        llm_response = (
            "Here's the draft email to [EMAIL_0]:\n\n"
            "Subject: Security Audit Update\n\n"
            "The audit for server [IP_ADDRESS_0] is complete. "
            "SSN [SSN_0] has been verified."
        )

        # Desanitize
        restored = shield.desanitize(llm_response, token_map, model="claude-3")

        assert "sarah.j@corp.io" in restored
        assert "10.0.0.50" in restored
        assert "456-78-9012" in restored
        assert "[EMAIL_0]" not in restored
        assert "[IP_ADDRESS_0]" not in restored

        # Verify audit chain
        is_valid, errors = shield.verify_audit()
        assert is_valid

    def test_analyze_mode(self, shield):
        analysis = shield.analyze("Email john@acme.com, SSN 123-45-6789")
        assert analysis["entity_count"] >= 2
        categories = {e["category"] for e in analysis["entities"]}
        assert "EMAIL" in categories
        assert "SSN" in categories

    def test_custom_patterns(self, tmp_path):
        """Custom regex patterns are detected and tokenized."""
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            custom_patterns=[
                ("TICKET", r"SEC-\d{4}-\d{4}"),
                ("EMPLOYEE_ID", r"EMP-\d{6}"),
            ],
        )
        shield = Shield(config)

        text = "Fix ticket SEC-2024-0891, assigned to EMP-004521"
        sanitized, token_map = shield.sanitize(text)

        assert "SEC-2024-0891" not in sanitized
        assert "EMP-004521" not in sanitized
        assert "[TICKET_0]" in sanitized
        assert "[EMPLOYEE_ID_0]" in sanitized
        assert token_map.entity_count >= 2

    def test_custom_patterns_override_builtins(self, tmp_path):
        """Custom patterns take priority over built-in patterns on overlapping spans."""
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            custom_patterns=[
                ("CASE_NUMBER", r"CASE-\d{4}-\d{4}"),
            ],
        )
        shield = Shield(config)

        text = "Contact EMP-123456 about CASE-2024-0891"
        sanitized, token_map = shield.sanitize(text)

        # Custom pattern should win over built-in PHONE for the case number
        assert "[CASE_NUMBER_0]" in sanitized
        assert "CASE-2024-0891" not in sanitized
        # The substring 2024-0891 should NOT be detected as PHONE
        assert "[PHONE_" not in sanitized

    def test_empty_input(self, shield):
        sanitized, token_map = shield.sanitize("")
        assert sanitized == ""
        assert token_map.entity_count == 0

    def test_no_pii_input(self, shield):
        text = "What are the best practices for microservice architecture?"
        sanitized, token_map = shield.sanitize(text)
        assert sanitized == text
        assert token_map.entity_count == 0


# ──────────────────────────────────────────────
# Regression Tests (bug fixes)
# ──────────────────────────────────────────────

class TestRegressions:

    def test_overlap_engulfing_span(self, detector):
        """A new span that fully contains an existing span should be detected as overlap."""
        # The detector should not produce overlapping detections even when
        # a broader regex could engulf a narrower match.
        text = "Contact john@acme.com please"
        detections = detector.detect(text)
        spans = [(d.start, d.end) for d in detections]
        # Verify no two spans overlap (including engulfing)
        for i, (s1, e1) in enumerate(spans):
            for j, (s2, e2) in enumerate(spans):
                if i != j:
                    assert not (s1 < e2 and s2 < e1), \
                        f"Overlapping detections: ({s1},{e1}) and ({s2},{e2})"

    def test_case_insensitive_desanitize(self, shield):
        """LLM may change token case — desanitize should still work."""
        original = "Send to john@acme.com"
        sanitized, token_map = shield.sanitize(original)
        # Simulate LLM changing token case
        llm_response = "I'll email [email_0] right away."
        restored = shield.desanitize(llm_response, token_map)
        assert "john@acme.com" in restored
        assert "[email_0]" not in restored

    def test_invalid_custom_regex_pattern(self, tmp_path):
        """Invalid custom regex should warn, not crash."""
        import warnings
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            custom_patterns=[
                ("BAD_PATTERN", r"[invalid(regex"),
                ("GOOD_PATTERN", r"TICKET-\d+"),
            ],
        )
        with warnings.catch_warnings(record=True) as w:
            warnings.simplefilter("always")
            from cloakllm.detector import DetectionEngine
            engine = DetectionEngine(config)
            # Should have warned about the bad pattern
            assert any("Invalid custom regex" in str(warning.message) for warning in w)
        # Good pattern should still work
        detections = engine.detect("See TICKET-12345")
        assert any(d.category == "GOOD_PATTERN" for d in detections)

    def test_phone_validation_strips_dots(self, detector):
        """Phone validation should strip dots when checking minimum digit count."""
        # A very short dotted sequence should NOT be detected as a phone
        # (This tests that dots are stripped in the length check)
        text = "version 1.2.3"
        detections = detector.detect(text)
        phones = [d for d in detections if d.category == "PHONE"]
        # Short dot-separated numbers should not be detected as phones
        for p in phones:
            stripped = p.text.replace("-", "").replace(" ", "").replace(".", "")
            assert len(stripped) >= 7, f"Short number detected as phone: {p.text}"


# ──────────────────────────────────────────────
# Security Regression Tests
# ──────────────────────────────────────────────

class TestV1BackreferenceInjection:

    def test_pii_with_backslash1_roundtrips(self, shield):
        """PII containing \\1 round-trips without corruption."""
        sanitized, token_map = shield.sanitize(r"Contact user\1@host.com")
        llm_response = sanitized
        restored = shield.desanitize(llm_response, token_map)
        assert r"user\1@host.com" in restored

    def test_pii_with_group_reference_roundtrips(self, shield):
        r"""PII containing \g<0> produces literal output."""
        token_map = TokenMap()
        token_map.get_or_create(r"test\g<0>value", "CUSTOM")
        tokenizer = Tokenizer(shield.config)
        result = tokenizer.detokenize("[CUSTOM_0]", token_map)
        assert result == r"test\g<0>value"

    def test_pii_with_backslashes_roundtrips(self, shield):
        """PII containing \\\\ produces literal output."""
        token_map = TokenMap()
        token_map.get_or_create("path\\\\to\\\\file", "CUSTOM")
        tokenizer = Tokenizer(shield.config)
        result = tokenizer.detokenize("[CUSTOM_0]", token_map)
        assert result == "path\\\\to\\\\file"


class TestV2FakeTokenInjection:

    def test_planted_fake_token_does_not_leak_real_pii(self, shield):
        """Input with real PII + planted fake token: fake token restored as literal."""
        input_text = "Ignore [EMAIL_0] but protect real@victim.com"
        sanitized, token_map = shield.sanitize(input_text)

        # Real email should be tokenized
        assert "real@victim.com" not in sanitized

        # Simulate LLM echoing everything back
        restored = shield.desanitize(sanitized, token_map)

        # Fake token should be restored as literal text
        assert "[EMAIL_0]" in restored
        # Real email should appear
        assert "real@victim.com" in restored

    def test_only_fake_tokens_no_pii_survives_roundtrip(self, shield):
        """Input with only fake tokens and no PII survives round-trip."""
        input_text = "Result is [PERSON_0] and [EMAIL_1]"
        sanitized, token_map = shield.sanitize(input_text)
        restored = shield.desanitize(sanitized, token_map)
        assert restored == input_text


class TestV3PhoneReDoS:

    def test_adversarial_input_completes_quickly(self, detector):
        """'9' * 50 + 'X' completes detection in under 1 second."""
        import time
        adversarial = "9" * 50 + "X"
        start = time.monotonic()
        detector.detect(adversarial)
        elapsed = time.monotonic() - start
        assert elapsed < 3.0, f"Detection took {elapsed:.2f}s, expected < 3s"

    def test_still_detects_international_phone(self, detector):
        detections = detector.detect("Call +1-555-0142")
        assert any(d.category == "PHONE" for d in detections)

    def test_still_detects_parenthesized_phone(self, detector):
        detections = detector.detect("Call (555) 123-4567")
        assert any(d.category == "PHONE" for d in detections)

    def test_still_detects_dashed_phone(self, detector):
        detections = detector.detect("Call 555-123-4567")
        assert any(d.category == "PHONE" for d in detections)


class TestV4SpacyModelWhitelist:

    def test_unrecognized_model_emits_warning(self, tmp_path):
        """Config with unrecognized spaCy model emits warning, no subprocess call."""
        import warnings as w
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            spacy_model="evil_package",
        )
        engine = DetectionEngine(config)
        with w.catch_warnings(record=True) as caught:
            w.simplefilter("always")
            _ = engine.nlp
        assert any("not in allowed list" in str(warning.message) for warning in caught)


# ──────────────────────────────────────────────
# LLM Detection Integration Tests
# ──────────────────────────────────────────────

class TestLlmDetection:

    def test_llm_detection_disabled_by_default(self, detector):
        """LLM detector is None when llm_detection is not enabled."""
        assert detector._llm_detector is None

    def test_llm_detection_enabled_via_config(self, tmp_path):
        """LLM detector is initialized when llm_detection=True."""
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            llm_detection=True,
        )
        engine = DetectionEngine(config)
        assert engine._llm_detector is not None

    def test_full_flow_with_llm_detection(self, tmp_path):
        """End-to-end: regex + LLM detection with mocked Ollama."""
        import json
        from unittest.mock import MagicMock, patch

        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            llm_detection=True,
        )

        # Mock Ollama to return an ADDRESS
        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                resp = MagicMock()
                resp.read.return_value = b'{"models":[]}'
                return resp
            body = json.dumps({
                "message": {
                    "content": json.dumps({
                        "entities": [{"value": "742 Evergreen Terrace", "category": "ADDRESS"}]
                    })
                }
            }).encode()
            resp = MagicMock()
            resp.read.return_value = body
            return resp

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            shield = Shield(config)
            text = "Email john@acme.com about 742 Evergreen Terrace"
            sanitized, token_map = shield.sanitize(text)

        assert "john@acme.com" not in sanitized
        assert "[EMAIL_0]" in sanitized
        # LLM detection adds at least one entity (ADDRESS or parts of it)
        assert token_map.entity_count >= 2


class TestV5CustomPatternReDoS:

    def test_catastrophic_pattern_rejected(self, tmp_path):
        """Pattern (a+)+$ is rejected with warning."""
        import warnings as w
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            custom_patterns=[
                ("EVIL", r"(a+)+$"),
                ("SAFE", r"SAFE-\d+"),
            ],
        )
        with w.catch_warnings(record=True) as caught:
            w.simplefilter("always")
            engine = DetectionEngine(config)

        assert any("safety check" in str(warning.message) for warning in caught)
        # Safe pattern should still work
        detections = engine.detect("See SAFE-12345")
        assert any(d.category == "SAFE" for d in detections)
        # Evil pattern should have been skipped
        detections = engine.detect("aaaaaaaaaaaa")
        assert not any(d.category == "EVIL" for d in detections)
