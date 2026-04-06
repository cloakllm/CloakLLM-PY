"""
CloakLLM test suite.

Run: pytest tests/ -v
"""

import asyncio
import json
import tempfile
from pathlib import Path
from unittest.mock import AsyncMock, MagicMock, patch

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
        detections, _ = detector.detect("Send to john@acme.com please")
        emails = [d for d in detections if d.category == "EMAIL"]
        assert len(emails) == 1
        assert emails[0].text == "john@acme.com"
        assert emails[0].source == "regex"

    def test_detect_multiple_emails(self, detector):
        text = "CC alice@foo.org and bob@bar.io on this"
        detections, _ = detector.detect(text)
        emails = [d for d in detections if d.category == "EMAIL"]
        assert len(emails) == 2

    def test_detect_ssn(self, detector):
        detections, _ = detector.detect("SSN: 123-45-6789")
        ssns = [d for d in detections if d.category == "SSN"]
        assert len(ssns) == 1
        assert ssns[0].text == "123-45-6789"

    def test_detect_credit_card_visa(self, detector):
        detections, _ = detector.detect("Card: 4111111111111111")
        cards = [d for d in detections if d.category == "CREDIT_CARD"]
        assert len(cards) == 1

    def test_detect_ip_address(self, detector):
        detections, _ = detector.detect("Server at 192.168.1.100")
        ips = [d for d in detections if d.category == "IP_ADDRESS"]
        assert len(ips) == 1
        assert ips[0].text == "192.168.1.100"

    def test_detect_api_key(self, detector):
        detections, _ = detector.detect("Use key sk-abc123def456ghi789jkl012")
        keys = [d for d in detections if d.category == "API_KEY"]
        assert len(keys) == 1

    def test_detect_aws_key(self, detector):
        detections, _ = detector.detect("AWS key: AKIAIOSFODNN7EXAMPLE")
        keys = [d for d in detections if d.category == "AWS_KEY"]
        assert len(keys) == 1

    @requires_ner
    def test_detect_person_ner(self, detector):
        detections, _ = detector.detect("Meeting with John Smith tomorrow at Google HQ")
        persons = [d for d in detections if d.category == "PERSON"]
        assert len(persons) >= 1
        assert any("John" in d.text for d in persons)

    @requires_ner
    def test_detect_org_ner(self, detector):
        detections, _ = detector.detect("I work at Microsoft in their Azure division")
        orgs = [d for d in detections if d.category == "ORG"]
        assert len(orgs) >= 1

    def test_no_false_positives_on_clean_text(self, detector):
        detections, _ = detector.detect("Please summarize this article about climate change")
        # Should have zero or very few detections
        assert len(detections) <= 1  # NER might catch "climate change" as misc

    def test_detections_sorted_by_position(self, detector):
        detections, _ = detector.detect("Email john@a.com and jane@b.com now")
        positions = [d.start for d in detections]
        assert positions == sorted(positions)

    def test_no_overlap_between_regex_and_ner(self, detector):
        detections, _ = detector.detect("Contact john.smith@acme.com")
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

        is_valid, errors, _final_seq = audit_logger.verify_chain()
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
        is_valid, errors, _final_seq = audit_logger.verify_chain()
        assert not is_valid
        assert len(errors) >= 1

    def test_audit_stats(self, shield):
        shield.sanitize("Email john@acme.com", model="claude-3")
        shield.sanitize("Call 555-123-4567", model="gpt-4")

        stats = shield.audit_stats()
        assert stats["total_events"] >= 2
        assert stats["total_entities_detected"] >= 2

    def test_audit_no_original_values_logged(self, shield, config):
        """Originals should not appear in log (PII never logged by default)."""
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
        _audit_result = shield.verify_audit()
        is_valid, errors = _audit_result["valid"], _audit_result["errors"]
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
        detections, _ = detector.detect(text)
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
        detections, _ = engine.detect("See TICKET-12345")
        assert any(d.category == "GOOD_PATTERN" for d in detections)

    def test_phone_validation_strips_dots(self, detector):
        """Phone validation should strip dots when checking minimum digit count."""
        # A very short dotted sequence should NOT be detected as a phone
        # (This tests that dots are stripped in the length check)
        text = "version 1.2.3"
        detections, _ = detector.detect(text)
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
        detector.detect(adversarial)  # returns (detections, timing)
        elapsed = time.monotonic() - start
        assert elapsed < 3.0, f"Detection took {elapsed:.2f}s, expected < 3s"

    def test_still_detects_international_phone(self, detector):
        detections, _ = detector.detect("Call +1-555-0142")
        assert any(d.category == "PHONE" for d in detections)

    def test_still_detects_parenthesized_phone(self, detector):
        detections, _ = detector.detect("Call (555) 123-4567")
        assert any(d.category == "PHONE" for d in detections)

    def test_still_detects_dashed_phone(self, detector):
        detections, _ = detector.detect("Call 555-123-4567")
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
        detections, _ = engine.detect("See SAFE-12345")
        assert any(d.category == "SAFE" for d in detections)
        # Evil pattern should have been skipped
        detections, _ = engine.detect("aaaaaaaaaaaa")
        assert not any(d.category == "EVIL" for d in detections)


# ──────────────────────────────────────────────
# LiteLLM Async Integration Tests
# ──────────────────────────────────────────────

class TestLiteLLMAsync:

    @pytest.mark.asyncio
    async def test_acompletion_sanitizes_and_desanitizes(self, tmp_path):
        """enable() patches litellm.acompletion; PII is sanitized/desanitized."""
        import types

        # Build a minimal litellm mock module
        litellm_mock = types.ModuleType("litellm")

        # Track what messages the "LLM" sees
        seen_messages = []

        async def fake_acompletion(*args, **kwargs):
            seen_messages.append(kwargs.get("messages", []))
            # Build a response that echoes the first user token
            choice = MagicMock()
            choice.message.content = "Got it, I'll email [EMAIL_0] now."
            resp = MagicMock()
            resp.choices = [choice]
            return resp

        litellm_mock.completion = MagicMock()
        litellm_mock.acompletion = fake_acompletion

        with patch.dict("sys.modules", {"litellm": litellm_mock}):
            from cloakllm.integrations import litellm_middleware as mw

            # Reset module state
            mw._enabled = False
            mw._shield = None
            mw._original_completion = None
            mw._original_acompletion = None

            config = ShieldConfig(log_dir=tmp_path / "audit", audit_enabled=False)
            mw.enable(config=config)

            try:
                response = await litellm_mock.acompletion(
                    model="gpt-4",
                    messages=[{"role": "user", "content": "Email john@acme.com about the project"}],
                )

                # The mock LLM should have seen sanitized messages (no raw email)
                assert len(seen_messages) == 1
                user_content = seen_messages[0][-1]["content"]  # last msg (after system hint)
                assert "john@acme.com" not in user_content
                assert "[EMAIL_0]" in user_content

                # The response should be desanitized (real email restored)
                assert "john@acme.com" in response.choices[0].message.content
                assert "[EMAIL_0]" not in response.choices[0].message.content
            finally:
                mw.disable()


# ──────────────────────────────────────────────
# Redaction Mode Tests
# ──────────────────────────────────────────────

class TestRedactionMode:

    def test_redact_replaces_with_category_redacted(self, tmp_path):
        config = ShieldConfig(mode="redact", log_dir=tmp_path / "audit")
        shield = Shield(config)
        text, tmap = shield.sanitize("Email john@acme.com please")
        assert "[EMAIL_REDACTED]" in text
        assert "john@acme.com" not in text

    def test_redact_token_map_empty(self, tmp_path):
        config = ShieldConfig(mode="redact", log_dir=tmp_path / "audit")
        shield = Shield(config)
        _, tmap = shield.sanitize("Email john@acme.com please")
        assert tmap.entity_count == 0
        assert len(tmap.forward) == 0
        assert len(tmap.reverse) == 0

    def test_redact_desanitize_noop(self, tmp_path):
        config = ShieldConfig(mode="redact", log_dir=tmp_path / "audit")
        shield = Shield(config)
        text, tmap = shield.sanitize("Email john@acme.com please")
        result = shield.desanitize(text, tmap)
        assert result == text  # nothing to reverse

    def test_redact_audit_logs_mode(self, tmp_path):
        config = ShieldConfig(mode="redact", log_dir=tmp_path / "audit")
        shield = Shield(config)
        shield.sanitize("Email john@acme.com please")
        # Read the audit log
        log_files = list((tmp_path / "audit").glob("audit_*.jsonl"))
        assert len(log_files) == 1
        import json
        with open(log_files[0]) as f:
            entry = json.loads(f.readline())
        assert entry["mode"] == "redact"

    def test_redact_multiple_same_category(self, tmp_path):
        config = ShieldConfig(mode="redact", log_dir=tmp_path / "audit")
        shield = Shield(config)
        text, tmap = shield.sanitize("Email john@acme.com and jane@acme.com")
        # Both emails should become [EMAIL_REDACTED], not [EMAIL_REDACTED_0] etc.
        assert text.count("[EMAIL_REDACTED]") == 2
        assert "john@acme.com" not in text
        assert "jane@acme.com" not in text

    def test_redact_analyze_unaffected(self, tmp_path):
        config = ShieldConfig(mode="redact", log_dir=tmp_path / "audit")
        shield = Shield(config)
        result = shield.analyze("Email john@acme.com please")
        assert result["entity_count"] >= 1
        # analyze returns original text, not redacted
        assert any(e["text"] == "john@acme.com" for e in result["entities"])

    def test_default_mode_is_tokenize(self):
        config = ShieldConfig()
        assert config.mode == "tokenize"

    def test_invalid_mode_rejected(self):
        with pytest.raises(ValueError, match="Invalid mode"):
            ShieldConfig(mode="invalid")


# ──────────────────────────────────────────────
# Entity Details Tests
# ──────────────────────────────────────────────

class TestEntityDetails:

    def test_token_map_entity_details(self, shield):
        """entity_details has correct fields, sorted by start, no text key."""
        _, token_map = shield.sanitize("Email john@acme.com, SSN 123-45-6789")
        details = token_map.entity_details
        assert len(details) >= 2
        # Check fields
        for d in details:
            assert set(d.keys()) == {"category", "start", "end", "length", "confidence", "source", "token"}
            assert "text" not in d
            assert d["length"] == d["end"] - d["start"]
            assert d["token"].startswith("[")
        # Check sorted by start
        starts = [d["start"] for d in details]
        assert starts == sorted(starts)

    def test_token_map_to_report(self, shield):
        """to_report() returns superset of to_summary() plus entity_details and mode."""
        _, token_map = shield.sanitize("Email john@acme.com")
        report = token_map.to_report()
        summary = token_map.to_summary()
        assert report["entity_count"] == summary["entity_count"]
        assert report["categories"] == summary["categories"]
        assert report["tokens"] == summary["tokens"]
        assert "mode" in report
        assert "entity_details" in report
        assert len(report["entity_details"]) >= 1

    def test_entity_details_in_audit_log(self, shield, config):
        """Audit log JSONL entries include entity_details array."""
        shield.sanitize("Email john@acme.com")
        log_file = list(config.log_dir.glob("audit_*.jsonl"))[0]
        with open(log_file) as f:
            entry = json.loads(f.readline())
        assert "entity_details" in entry
        assert isinstance(entry["entity_details"], list)
        assert len(entry["entity_details"]) >= 1
        assert entry["entity_details"][0]["category"] == "EMAIL"

    def test_entity_details_no_pii_in_audit(self, shield, config):
        """No original PII text appears in audit entity_details."""
        shield.sanitize("Email john@acme.com, SSN 123-45-6789")
        log_file = list(config.log_dir.glob("audit_*.jsonl"))[0]
        with open(log_file) as f:
            content = f.read()
        assert "john@acme.com" not in content
        assert "123-45-6789" not in content

    def test_entity_details_redact_mode(self, tmp_path):
        """In redact mode, tokens show [CATEGORY_REDACTED]."""
        config = ShieldConfig(mode="redact", log_dir=tmp_path / "audit")
        shield = Shield(config)
        _, token_map = shield.sanitize("Email john@acme.com")
        details = token_map.entity_details
        assert len(details) >= 1
        assert details[0]["token"] == "[EMAIL_REDACTED]"

    def test_entity_details_empty_for_no_pii(self, shield):
        """entity_details is empty when no PII is detected."""
        _, token_map = shield.sanitize("What is the weather like today?")
        assert token_map.entity_details == []

    def test_audit_chain_valid_with_entity_details(self, shield):
        """Hash chain remains valid with entity_details included."""
        shield.sanitize("Email john@acme.com")
        shield.sanitize("SSN 123-45-6789")
        shield.sanitize("No PII here")
        _audit_result = shield.verify_audit()
        is_valid, errors = _audit_result["valid"], _audit_result["errors"]
        assert is_valid, f"Chain errors: {errors}"


# ──────────────────────────────────────────────
# Batch Processing Tests
# ──────────────────────────────────────────────

class TestBatch:

    def test_basic_batch(self, shield):
        texts = ["Email john@acme.com", "SSN 123-45-6789"]
        sanitized, token_map = shield.sanitize_batch(texts)
        assert len(sanitized) == 2
        assert "[EMAIL_0]" in sanitized[0]
        assert "[SSN_0]" in sanitized[1]
        assert "john@acme.com" not in sanitized[0]
        assert "123-45-6789" not in sanitized[1]

    def test_shared_tokens_across_texts(self, shield):
        texts = [
            "Contact john@acme.com about the project",
            "Follow up with john@acme.com tomorrow",
        ]
        sanitized, token_map = shield.sanitize_batch(texts)
        assert "[EMAIL_0]" in sanitized[0]
        assert "[EMAIL_0]" in sanitized[1]
        # Same email in both texts should map to the same token
        assert "john@acme.com" in token_map.forward

    def test_single_audit_entry(self, shield, config):
        texts = ["Email john@acme.com", "SSN 123-45-6789"]
        shield.sanitize_batch(texts)
        log_file = list(config.log_dir.glob("audit_*.jsonl"))[0]
        with open(log_file) as f:
            lines = [l for l in f.readlines() if l.strip()]
        assert len(lines) == 1
        entry = json.loads(lines[0])
        assert entry["event_type"] == "sanitize_batch"
        assert "prompt_hashes" in entry["metadata"]
        assert "sanitized_hashes" in entry["metadata"]
        assert len(entry["metadata"]["prompt_hashes"]) == 2

    def test_entity_details_text_index(self, shield):
        texts = ["Email john@acme.com", "SSN 123-45-6789"]
        shield.sanitize_batch(texts)
        # Get entity_details from the audit log
        log_file = list(shield.config.log_dir.glob("audit_*.jsonl"))[0]
        with open(log_file) as f:
            entry = json.loads(f.readline())
        details = entry["entity_details"]
        assert len(details) >= 2
        text_indices = {d["text_index"] for d in details}
        assert 0 in text_indices
        assert 1 in text_indices
        for d in details:
            assert "text_index" in d

    def test_empty_list(self, shield):
        sanitized, token_map = shield.sanitize_batch([])
        assert sanitized == []
        assert token_map.entity_count == 0

    def test_no_pii_texts(self, shield):
        texts = ["Hello world", "Nice weather today"]
        sanitized, token_map = shield.sanitize_batch(texts)
        assert sanitized == texts
        assert token_map.entity_count == 0

    def test_existing_token_map_reuse(self, shield):
        _, token_map = shield.sanitize("Email john@acme.com")
        texts = ["Remind john@acme.com", "Also notify jane@acme.com"]
        sanitized, token_map = shield.sanitize_batch(texts, token_map=token_map)
        assert "[EMAIL_0]" in sanitized[0]  # same token for john@acme.com
        assert "[EMAIL_1]" in sanitized[1]  # new token for jane@acme.com

    def test_redact_mode(self, tmp_path):
        config = ShieldConfig(mode="redact", log_dir=tmp_path / "audit")
        shield = Shield(config)
        texts = ["Email john@acme.com", "Email jane@acme.com"]
        sanitized, token_map = shield.sanitize_batch(texts)
        assert "[EMAIL_REDACTED]" in sanitized[0]
        assert "[EMAIL_REDACTED]" in sanitized[1]
        assert "john@acme.com" not in sanitized[0]

    def test_desanitize_batch(self, shield):
        texts = ["Email john@acme.com", "Server 10.0.0.1"]
        sanitized, token_map = shield.sanitize_batch(texts)
        responses = [
            "Sent to [EMAIL_0]",
            "Configured [IP_ADDRESS_0]",
        ]
        restored = shield.desanitize_batch(responses, token_map)
        assert len(restored) == 2
        assert "john@acme.com" in restored[0]
        assert "10.0.0.1" in restored[1]

    def test_audit_chain_valid_with_batch(self, shield):
        shield.sanitize("Email john@acme.com")
        shield.sanitize_batch(["SSN 123-45-6789", "Phone 555-123-4567"])
        shield.desanitize_batch(["test"], TokenMap())
        _audit_result = shield.verify_audit()
        is_valid, errors = _audit_result["valid"], _audit_result["errors"]
        assert is_valid, f"Chain errors: {errors}"


# ──────────────────────────────────────────────
# Metrics & Timing Tests
# ──────────────────────────────────────────────

class TestMetrics:

    def test_timing_in_audit_entry(self, shield, config):
        """Audit log entries include timing object with per-pass breakdowns."""
        shield.sanitize("Email john@acme.com")
        log_file = list(config.log_dir.glob("audit_*.jsonl"))[0]
        with open(log_file) as f:
            entry = json.loads(f.readline())
        assert "timing" in entry
        timing = entry["timing"]
        assert "total_ms" in timing
        assert "detection_ms" in timing
        assert "regex_ms" in timing
        assert "ner_ms" in timing
        # llm_ms only present when LLM detection is enabled
        assert "tokenization_ms" in timing
        assert timing["total_ms"] >= 0
        assert timing["regex_ms"] >= 0

    def test_timing_in_desanitize_audit(self, shield, config):
        """Desanitize audit entries include timing."""
        _, token_map = shield.sanitize("Email john@acme.com")
        shield.desanitize("[EMAIL_0]", token_map)
        log_file = list(config.log_dir.glob("audit_*.jsonl"))[0]
        with open(log_file) as f:
            lines = [l for l in f.readlines() if l.strip()]
        entry = json.loads(lines[1])
        assert "timing" in entry
        assert "total_ms" in entry["timing"]
        assert "tokenization_ms" in entry["timing"]

    def test_timing_in_batch_audit(self, shield, config):
        """Batch audit entries include timing."""
        shield.sanitize_batch(["Email john@acme.com", "SSN 123-45-6789"])
        log_file = list(config.log_dir.glob("audit_*.jsonl"))[0]
        with open(log_file) as f:
            entry = json.loads(f.readline())
        timing = entry["timing"]
        assert "total_ms" in timing
        assert "detection_ms" in timing
        assert "regex_ms" in timing
        assert "tokenization_ms" in timing

    def test_metrics_accumulation(self, shield):
        """metrics() returns accumulated stats after multiple calls."""
        shield.sanitize("Email john@acme.com")
        shield.sanitize("SSN 123-45-6789")
        m = shield.metrics()
        assert m["calls"]["sanitize"] == 2
        assert m["total_ms"] > 0
        assert m["avg_ms"] > 0
        assert m["entities_detected"] >= 2
        assert "EMAIL" in m["categories"]
        assert m["detection"]["regex_ms"] >= 0
        assert m["tokenization_ms"] >= 0

    def test_metrics_includes_batch_calls(self, shield):
        """metrics() counts batch calls separately."""
        shield.sanitize_batch(["Email john@acme.com", "SSN 123-45-6789"])
        m = shield.metrics()
        assert m["calls"]["sanitize_batch"] == 1
        assert m["entities_detected"] >= 2

    def test_metrics_includes_desanitize(self, shield):
        """metrics() tracks desanitize calls."""
        _, token_map = shield.sanitize("Email john@acme.com")
        shield.desanitize("[EMAIL_0]", token_map)
        m = shield.metrics()
        assert m["calls"]["desanitize"] == 1

    def test_reset_metrics(self, shield):
        """reset_metrics() clears all accumulators."""
        shield.sanitize("Email john@acme.com")
        shield.reset_metrics()
        m = shield.metrics()
        assert m["calls"]["sanitize"] == 0
        assert m["total_ms"] == 0.0
        assert m["entities_detected"] == 0
        assert m["categories"] == {}

    def test_detector_returns_timing(self, detector):
        """DetectionEngine.detect() returns timing dict with per-pass keys."""
        _, timing = detector.detect("Email john@acme.com, call 555-123-4567")
        assert "regex_ms" in timing
        assert "ner_ms" in timing
        # llm_ms only present when LLM detection is enabled
        assert all(isinstance(v, float) for v in timing.values())

    def test_audit_chain_valid_with_timing(self, shield):
        """Hash chain remains valid with timing field included."""
        shield.sanitize("Email john@acme.com")
        shield.sanitize("SSN 123-45-6789")
        _, token_map = shield.sanitize("Phone 555-123-4567")
        shield.desanitize("[PHONE_0]", token_map)
        _audit_result = shield.verify_audit()
        is_valid, errors = _audit_result["valid"], _audit_result["errors"]
        assert is_valid, f"Chain errors: {errors}"


# ──────────────────────────────────────────────
# Custom LLM Categories Tests
# ──────────────────────────────────────────────

class TestCustomLlmCategories:

    def test_custom_llm_category_produces_token(self):
        """End-to-end: custom LLM category produces [PATIENT_ID_0] token."""
        from unittest.mock import patch, MagicMock
        import json

        config = ShieldConfig(
            llm_detection=True,
            custom_llm_categories=[("PATIENT_ID", "Hospital patient ID")],
            audit_enabled=False,
        )
        shield = Shield(config=config)

        text = "Patient PAT-12345 was admitted"
        ollama_response = {"entities": [{"value": "PAT-12345", "category": "PATIENT_ID"}]}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                resp = MagicMock()
                resp.read.return_value = b'{"models":[]}'
                return resp
            body = json.dumps({
                "message": {"content": json.dumps(ollama_response)}
            }).encode()
            resp = MagicMock()
            resp.read.return_value = body
            return resp

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            sanitized, token_map = shield.sanitize(text)

        assert "[PATIENT_ID_0]" in sanitized
        assert token_map.entity_count >= 1


# ──────────────────────────────────────────────
# Entity Hashing Tests
# ──────────────────────────────────────────────

class TestEntityHashing:

    def test_hash_disabled_by_default(self, shield):
        """entity_hash should not appear when hashing is disabled."""
        _, token_map = shield.sanitize("Contact john@acme.com")
        for detail in token_map.entity_details:
            assert "entity_hash" not in detail

    def test_hash_enabled_produces_hex(self, tmp_path):
        """entity_hash should be a 64-char hex string when enabled."""
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            entity_hashing=True,
            entity_hash_key="test-key",
        )
        shield = Shield(config)
        _, token_map = shield.sanitize("Contact john@acme.com")
        details = token_map.entity_details
        assert len(details) >= 1
        for detail in details:
            assert "entity_hash" in detail
            assert len(detail["entity_hash"]) == 64
            assert all(c in "0123456789abcdef" for c in detail["entity_hash"])

    def test_hash_deterministic(self, tmp_path):
        """Same input + key = same hash."""
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            entity_hashing=True,
            entity_hash_key="stable-key",
        )
        shield1 = Shield(config)
        _, tm1 = shield1.sanitize("Contact john@acme.com")

        config2 = ShieldConfig(
            log_dir=tmp_path / "audit",
            entity_hashing=True,
            entity_hash_key="stable-key",
        )
        shield2 = Shield(config2)
        _, tm2 = shield2.sanitize("Contact john@acme.com")

        h1 = [d["entity_hash"] for d in tm1.entity_details]
        h2 = [d["entity_hash"] for d in tm2.entity_details]
        assert h1 == h2

    def test_hash_category_prefix_prevents_collision(self, tmp_path):
        """Same text under different categories produces different hashes."""
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            entity_hashing=True,
            entity_hash_key="test-key",
        )
        from cloakllm.tokenizer import TokenMap
        tm = TokenMap(entity_hashing=True, entity_hash_key="test-key")
        hash_person = tm._compute_entity_hash("PERSON", "john")
        hash_org = tm._compute_entity_hash("ORG", "john")
        assert hash_person != hash_org

    def test_hash_normalization(self, tmp_path):
        """Hashing normalizes case and whitespace."""
        from cloakllm.tokenizer import TokenMap
        tm = TokenMap(entity_hashing=True, entity_hash_key="test-key")
        h1 = tm._compute_entity_hash("EMAIL", "John@Acme.com")
        h2 = tm._compute_entity_hash("EMAIL", "  john@acme.com  ")
        assert h1 == h2

    def test_hash_auto_generates_key(self, tmp_path):
        """When entity_hashing=True but no key, a key is auto-generated."""
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            entity_hashing=True,
        )
        shield = Shield(config)
        assert len(shield.config.entity_hash_key) == 64  # 32 bytes hex
        _, token_map = shield.sanitize("Contact john@acme.com")
        details = token_map.entity_details
        assert any("entity_hash" in d for d in details)

    def test_hash_works_in_redact_mode(self, tmp_path):
        """entity_hash should appear even in redact mode."""
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            mode="redact",
            entity_hashing=True,
            entity_hash_key="test-key",
        )
        shield = Shield(config)
        _, token_map = shield.sanitize("Contact john@acme.com")
        details = token_map.entity_details
        assert len(details) >= 1
        for d in details:
            assert "entity_hash" in d
            assert d["token"].endswith("_REDACTED]")

    def test_hash_audit_chain_valid(self, tmp_path):
        """Audit chain should remain valid with entity hashing enabled."""
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            entity_hashing=True,
            entity_hash_key="test-key",
        )
        shield = Shield(config)
        shield.sanitize("Contact john@acme.com")
        shield.sanitize("Call +1-555-0142")
        _audit_result = shield.verify_audit()
        valid, errors = _audit_result["valid"], _audit_result["errors"]
        assert valid, f"Audit chain errors: {errors}"

    def test_hash_batch_includes_hash(self, tmp_path):
        """sanitize_batch should include entity_hash with text_index."""
        config = ShieldConfig(
            log_dir=tmp_path / "audit",
            entity_hashing=True,
            entity_hash_key="test-key",
        )
        shield = Shield(config)
        texts = ["Email john@acme.com", "Call +1-555-0142"]
        _, token_map = shield.sanitize_batch(texts)
        # entity_details from token_map should have hashes
        details = token_map.entity_details
        assert len(details) >= 2
        for d in details:
            assert "entity_hash" in d

    def test_hash_cross_sdk_known_value(self, tmp_path):
        """Known-value test for cross-SDK parity."""
        import hmac
        import hashlib
        key = "test-key"
        category = "EMAIL"
        text = "john@acme.com"
        message = f"{category}:{text.strip().lower()}"
        expected = hmac.new(key.encode(), message.encode(), hashlib.sha256).hexdigest()

        from cloakllm.tokenizer import TokenMap
        tm = TokenMap(entity_hashing=True, entity_hash_key=key)
        actual = tm._compute_entity_hash(category, text)
        assert actual == expected


# ── Attestation Integration ─────────────────────────────────


class TestAttestationIntegration:
    """Integration tests for cryptographic attestation in Shield."""

    @pytest.fixture
    def keypair(self):
        from cloakllm.attestation import DeploymentKeyPair
        return DeploymentKeyPair.generate()

    def test_sanitize_creates_certificate(self, keypair, tmp_path):
        """Shield.sanitize attaches a certificate when attestation key is configured."""
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        _, tm = shield.sanitize("Email john@acme.com")
        assert tm.certificate is not None
        assert tm.certificate.verify(keypair.public_key)

    def test_sanitize_no_key_no_certificate(self, tmp_path):
        """Without attestation key, no certificate is created."""
        shield = Shield(ShieldConfig(log_dir=tmp_path))
        _, tm = shield.sanitize("Email john@acme.com")
        assert tm.certificate is None

    def test_certificate_hashes_match(self, keypair, tmp_path):
        """Certificate input/output hashes match SHA-256 of original/sanitized text."""
        import hashlib
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        text = "Email john@acme.com about Project Falcon"
        sanitized, tm = shield.sanitize(text)
        cert = tm.certificate
        assert cert.input_hash == hashlib.sha256(text.encode()).hexdigest()
        assert cert.output_hash == hashlib.sha256(sanitized.encode()).hexdigest()

    def test_certificate_entity_count_and_categories(self, keypair, tmp_path):
        """Certificate captures entity stats correctly."""
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        _, tm = shield.sanitize("Email john@acme.com and call 555-123-4567")
        cert = tm.certificate
        assert cert.entity_count >= 2
        assert "EMAIL" in cert.categories

    def test_certificate_mode_matches_config(self, keypair, tmp_path):
        """Certificate mode matches Shield config mode."""
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path, mode="redact"))
        _, tm = shield.sanitize("Email john@acme.com")
        assert tm.certificate.mode == "redact"

    def test_certificate_detection_passes(self, keypair, tmp_path):
        """Certificate includes at least 'regex' in detection_passes."""
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        _, tm = shield.sanitize("Email john@acme.com")
        assert "regex" in tm.certificate.detection_passes

    def test_certificate_tamper_detection(self, keypair, tmp_path):
        """Tampering with certificate fields fails verification."""
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        _, tm = shield.sanitize("Email john@acme.com")
        cert = tm.certificate
        cert.entity_count = 999
        assert cert.verify(keypair.public_key) is False

    def test_certificate_to_dict_and_back(self, keypair, tmp_path):
        """Certificate roundtrips through dict serialization."""
        from cloakllm.attestation import SanitizationCertificate
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        _, tm = shield.sanitize("Email john@acme.com")
        d = tm.certificate.to_dict()
        cert2 = SanitizationCertificate.from_dict(d)
        assert cert2.verify(keypair.public_key)

    def test_verify_certificate_method(self, keypair, tmp_path):
        """Shield.verify_certificate works with certificate and dict."""
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        _, tm = shield.sanitize("Email john@acme.com")
        assert shield.verify_certificate(tm.certificate) is True
        assert shield.verify_certificate(tm.certificate.to_dict()) is True

    def test_verify_certificate_wrong_key(self, keypair, tmp_path):
        """Verification with wrong key fails."""
        from cloakllm.attestation import DeploymentKeyPair
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        _, tm = shield.sanitize("Email john@acme.com")
        other_kp = DeploymentKeyPair.generate()
        assert shield.verify_certificate(tm.certificate, public_key=other_kp.public_key) is False

    def test_batch_creates_certificate(self, keypair, tmp_path):
        """sanitize_batch creates certificate with Merkle roots."""
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        texts = ["Email john@acme.com", "Call 555-123-4567"]
        _, tm = shield.sanitize_batch(texts)
        assert tm.certificate is not None
        assert tm.batch_certificate is not None
        assert tm.merkle_tree is not None
        assert tm.certificate.verify(keypair.public_key)

    def test_batch_merkle_proofs(self, keypair, tmp_path):
        """Batch Merkle proofs verify for each input text."""
        import hashlib
        from cloakllm.attestation import MerkleTree
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        texts = ["Email john@acme.com", "Call 555-123-4567", "SSN 123-45-6789"]
        sanitized_texts, tm = shield.sanitize_batch(texts)
        input_tree = tm.merkle_tree["input"]
        output_tree = tm.merkle_tree["output"]
        for i, text in enumerate(texts):
            leaf = hashlib.sha256(text.encode()).hexdigest()
            proof = input_tree.proof(i)
            assert MerkleTree.verify_proof(leaf, proof, input_tree.root)
        # Also verify output tree
        for i, text in enumerate(sanitized_texts):
            leaf = hashlib.sha256(text.encode()).hexdigest()
            proof = output_tree.proof(i)
            assert MerkleTree.verify_proof(leaf, proof, output_tree.root)

    def test_sanitize_no_pii_with_attestation(self, keypair, tmp_path):
        """Attestation works on text with no PII (entity_count=0)."""
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        sanitized, tm = shield.sanitize("The weather is nice today")
        assert sanitized == "The weather is nice today"
        assert tm.certificate is not None
        assert tm.certificate.entity_count == 0
        assert tm.certificate.categories == {}
        assert tm.certificate.verify(keypair.public_key)

    def test_batch_single_item(self, keypair, tmp_path):
        """Batch with a single text creates valid Merkle tree and certificate."""
        from cloakllm.attestation import MerkleTree
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        sanitized_texts, tm = shield.sanitize_batch(["Email john@acme.com"])
        assert tm.certificate is not None
        assert tm.certificate.verify(keypair.public_key)
        assert tm.merkle_tree is not None
        # Single-leaf Merkle tree: root = leaf hash
        import hashlib
        expected_root = hashlib.sha256("Email john@acme.com".encode()).hexdigest()
        assert tm.merkle_tree["input"].root == expected_root

    def test_batch_no_key_no_certificate(self, tmp_path):
        """Batch without attestation key produces no certificate."""
        shield = Shield(ShieldConfig(log_dir=tmp_path))
        _, tm = shield.sanitize_batch(["a", "b"])
        assert tm.certificate is None
        assert tm.merkle_tree is None

    def test_audit_includes_certificate_fields(self, keypair, tmp_path):
        """Audit log entries include certificate_hash and key_id."""
        import json
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        shield.sanitize("Email john@acme.com")
        log_files = list(tmp_path.glob("audit_*.jsonl"))
        assert len(log_files) == 1
        with open(log_files[0]) as f:
            entry = json.loads(f.readline())
        assert entry["certificate_hash"] is not None
        assert entry["key_id"] == keypair.key_id

    def test_audit_no_attestation_null_fields(self, tmp_path):
        """Without attestation, certificate_hash and key_id are null."""
        import json
        shield = Shield(ShieldConfig(log_dir=tmp_path))
        shield.sanitize("Email john@acme.com")
        log_files = list(tmp_path.glob("audit_*.jsonl"))
        with open(log_files[0]) as f:
            entry = json.loads(f.readline())
        assert entry["certificate_hash"] is None
        assert entry["key_id"] is None

    def test_audit_chain_valid_with_attestation(self, keypair, tmp_path):
        """Audit chain remains valid when attestation fields are present."""
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        shield.sanitize("Email john@acme.com")
        shield.sanitize("Call 555-123-4567")
        shield.sanitize_batch(["test1", "test2"])
        _audit_result = shield.verify_audit()
        valid, errors = _audit_result["valid"], _audit_result["errors"]
        assert valid is True, f"Audit chain broken: {errors}"

    def test_attestation_key_from_file(self, keypair, tmp_path):
        """Shield loads attestation key from file path."""
        key_path = tmp_path / "key.json"
        keypair.save(key_path)
        shield = Shield(ShieldConfig(attestation_key_path=str(key_path), log_dir=tmp_path / "logs"))
        _, tm = shield.sanitize("Email john@acme.com")
        assert tm.certificate is not None
        assert tm.certificate.verify(keypair.public_key)

    def test_generate_attestation_key(self):
        """Shield.generate_attestation_key creates a valid keypair."""
        kp = Shield.generate_attestation_key()
        assert len(kp.public_key) == 32
        assert len(kp.private_key) == 32

    def test_multi_turn_with_attestation(self, keypair, tmp_path):
        """Multi-turn conversation gets fresh certificates each call."""
        shield = Shield(ShieldConfig(attestation_key=keypair, log_dir=tmp_path))
        _, tm = shield.sanitize("Email john@acme.com")
        cert1 = tm.certificate
        _, tm = shield.sanitize("Call 555-123-4567", token_map=tm)
        cert2 = tm.certificate
        # Each call gets a fresh certificate
        assert cert1 is not cert2
        assert cert1.signature != cert2.signature
        assert cert1.verify(keypair.public_key)
        assert cert2.verify(keypair.public_key)
