"""
Tests for LLM-based PII detection (Pass 3).

All Ollama HTTP calls are mocked — no real Ollama instance needed.
"""

import json
import logging
from unittest.mock import MagicMock, patch

import pytest

from cloakllm.config import ShieldConfig
from cloakllm.llm_detector import LlmDetector


@pytest.fixture
def config():
    return ShieldConfig(
        llm_detection=True,
        llm_model="llama3.2",
        llm_ollama_url="http://localhost:11434",
        llm_timeout=10.0,
        llm_confidence=0.85,
    )


@pytest.fixture
def detector(config):
    return LlmDetector(config)


def _mock_urlopen_factory(response_content):
    """Create a mock urlopen that returns a given Ollama chat response."""
    def _mock_urlopen(req, timeout=None):
        body = json.dumps({
            "message": {
                "content": json.dumps(response_content)
            }
        }).encode()
        resp = MagicMock()
        resp.read.return_value = body
        return resp
    return _mock_urlopen


def _mock_tags_ok(req, timeout=None):
    """Mock a successful /api/tags response."""
    resp = MagicMock()
    resp.read.return_value = b'{"models":[]}'
    return resp


# ──────────────────────────────────────────────
# Availability Tests
# ──────────────────────────────────────────────

class TestAvailability:

    def test_unavailable_returns_empty(self, detector, caplog):
        """When Ollama is unreachable, detect() returns [] and logs warning."""
        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=OSError("Connection refused")):
            with caplog.at_level(logging.WARNING, logger="cloakllm.llm_detector"):
                result = detector.detect("My address is 123 Main St", [])
        assert result == []
        assert any("not available" in r.message for r in caplog.records)

    def test_available_flag_cached(self, detector):
        """After first check, availability is cached (no second HTTP call)."""
        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=OSError("down")):
            detector.detect("text", [])
        # Second call should NOT call urlopen again
        with patch("cloakllm.llm_detector.urllib.request.urlopen") as mock_open:
            detector.detect("text2", [])
            mock_open.assert_not_called()


# ──────────────────────────────────────────────
# Successful Detection Tests
# ──────────────────────────────────────────────

class TestSuccessfulDetection:

    def test_detects_address(self, detector):
        """LLM returns an ADDRESS entity — correct Detection object created."""
        text = "Ship to 742 Evergreen Terrace, Springfield"
        ollama_response = {"entities": [{"value": "742 Evergreen Terrace, Springfield", "category": "ADDRESS"}]}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, [])

        assert len(results) == 1
        assert results[0].text == "742 Evergreen Terrace, Springfield"
        assert results[0].category == "ADDRESS"
        assert results[0].source == "llm"
        assert results[0].confidence == 0.85
        assert results[0].start == 8
        assert results[0].end == 42

    def test_detects_medical(self, detector):
        """LLM returns a MEDICAL entity."""
        text = "Patient diagnosed with diabetes mellitus"
        ollama_response = {"entities": [{"value": "diabetes mellitus", "category": "MEDICAL"}]}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, [])

        assert len(results) == 1
        assert results[0].category == "MEDICAL"

    def test_detects_multiple_entities(self, detector):
        """LLM returns multiple entities of different categories."""
        text = "John born 1990-01-15 lives at 123 Oak Ave"
        ollama_response = {"entities": [
            {"value": "1990-01-15", "category": "DATE_OF_BIRTH"},
            {"value": "123 Oak Ave", "category": "ADDRESS"},
        ]}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, [])

        assert len(results) == 2
        categories = {r.category for r in results}
        assert "DATE_OF_BIRTH" in categories
        assert "ADDRESS" in categories


# ──────────────────────────────────────────────
# Filtering Tests
# ──────────────────────────────────────────────

class TestFiltering:

    def test_hallucinated_values_dropped(self, detector):
        """LLM returns a value not present in text — silently dropped."""
        text = "The patient is healthy"
        ollama_response = {"entities": [{"value": "hypertension", "category": "MEDICAL"}]}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, [])

        assert results == []

    def test_covered_spans_skipped(self, detector):
        """Entities overlapping with already-covered spans are skipped."""
        text = "Email john@acme.com about 123 Main St"
        ollama_response = {"entities": [{"value": "123 Main St", "category": "ADDRESS"}]}
        # Simulate that "john@acme.com" (chars 6-19) is already covered
        covered = [(6, 19)]

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, covered)

        # ADDRESS should still be detected (not overlapping)
        assert len(results) == 1
        assert results[0].category == "ADDRESS"

    def test_covered_span_overlap_skips_entity(self, detector):
        """Entity that overlaps with a covered span is skipped."""
        text = "Visit 123 Main St today"
        ollama_response = {"entities": [{"value": "123 Main St", "category": "ADDRESS"}]}
        # Covered span overlaps with "123 Main St" (chars 6-17)
        covered = [(6, 17)]

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, covered)

        assert results == []

    def test_short_values_skipped(self, detector):
        """Values shorter than 2 characters are skipped."""
        text = "Patient X has condition Y"
        ollama_response = {"entities": [{"value": "X", "category": "PERSON"}]}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, [])

        assert results == []

    def test_excluded_categories_skipped(self, detector):
        """LLM returning an excluded category (e.g., EMAIL) is ignored."""
        text = "Contact john@acme.com"
        ollama_response = {"entities": [{"value": "john@acme.com", "category": "EMAIL"}]}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, [])

        assert results == []

    def test_multiple_occurrences_all_detected(self, detector):
        """Value appearing multiple times — all non-covered occurrences detected."""
        text = "Visit 123 Main St or call about 123 Main St"
        ollama_response = {"entities": [{"value": "123 Main St", "category": "ADDRESS"}]}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, [])

        assert len(results) == 2
        assert results[0].start != results[1].start


# ──────────────────────────────────────────────
# Cache Tests
# ──────────────────────────────────────────────

class TestCache:

    def test_cache_hit_no_second_call(self, detector):
        """Second detect() with same text uses cache — no second Ollama call."""
        text = "Ship to 742 Evergreen Terrace"
        ollama_response = {"entities": [{"value": "742 Evergreen Terrace", "category": "ADDRESS"}]}

        call_count = 0

        def mock_urlopen(req, timeout=None):
            nonlocal call_count
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            call_count += 1
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            detector.detect(text, [])
            detector.detect(text, [])

        assert call_count == 1  # Only one /api/chat call


# ──────────────────────────────────────────────
# Error Handling Tests
# ──────────────────────────────────────────────

class TestErrorHandling:

    def test_malformed_json_returns_empty(self, detector, caplog):
        """Ollama returns invalid JSON — returns [] and logs warning."""
        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            resp = MagicMock()
            resp.read.return_value = b'{"message":{"content":"not valid json{{{"}}'
            return resp

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            with caplog.at_level(logging.WARNING, logger="cloakllm.llm_detector"):
                results = detector.detect("Some text with PII", [])

        assert results == []

    def test_timeout_returns_empty(self, detector, caplog):
        """Ollama times out — returns [] and logs warning."""
        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            raise TimeoutError("Request timed out")

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            with caplog.at_level(logging.WARNING, logger="cloakllm.llm_detector"):
                results = detector.detect("Some text", [])

        assert results == []

    def test_entities_not_list_returns_empty(self, detector):
        """Ollama returns entities as non-list — returns []."""
        ollama_response = {"entities": "not a list"}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect("Some text", [])

        assert results == []


# ──────────────────────────────────────────────
# Custom Categories Tests
# ──────────────────────────────────────────────

class TestCustomCategories:

    def test_custom_category_detected(self):
        """Custom category returned by LLM is accepted."""
        config = ShieldConfig(
            llm_detection=True,
            custom_llm_categories=[("PATIENT_ID", "Hospital patient ID, format PAT-XXXXX")],
        )
        detector = LlmDetector(config)
        text = "Patient PAT-12345 was admitted"
        ollama_response = {"entities": [{"value": "PAT-12345", "category": "PATIENT_ID"}]}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, [])

        assert len(results) == 1
        assert results[0].category == "PATIENT_ID"
        assert results[0].text == "PAT-12345"

    def test_prompt_includes_custom_category(self):
        """System prompt includes custom category name in category list."""
        config = ShieldConfig(
            llm_detection=True,
            custom_llm_categories=[("PATIENT_ID", "Hospital patient ID")],
        )
        detector = LlmDetector(config)
        prompt = detector._system_prompt()
        assert "PATIENT_ID" in prompt

    def test_category_without_description_no_hint(self):
        """Custom category with empty description appears in list but not in hints."""
        config = ShieldConfig(
            llm_detection=True,
            custom_llm_categories=[("CASE_NUMBER", "")],
        )
        detector = LlmDetector(config)
        prompt = detector._system_prompt()
        assert "CASE_NUMBER" in prompt
        assert "Category hints" not in prompt

    def test_excluded_category_rejected_with_warning(self, caplog):
        """Custom category colliding with EXCLUDED_CATEGORIES is skipped with warning."""
        config = ShieldConfig(
            llm_detection=True,
            custom_llm_categories=[("EMAIL", "Custom email detection")],
        )
        with caplog.at_level(logging.WARNING, logger="cloakllm.llm_detector"):
            detector = LlmDetector(config)
        assert "EMAIL" not in detector._custom_categories
        assert any("conflicts" in r.message for r in caplog.records)

    def test_custom_and_builtin_coexist(self):
        """LLM returns both a built-in and a custom category — both accepted."""
        config = ShieldConfig(
            llm_detection=True,
            custom_llm_categories=[("PATIENT_ID", "Hospital patient ID")],
        )
        detector = LlmDetector(config)
        text = "Patient PAT-12345 lives at 742 Evergreen Terrace"
        ollama_response = {"entities": [
            {"value": "PAT-12345", "category": "PATIENT_ID"},
            {"value": "742 Evergreen Terrace", "category": "ADDRESS"},
        ]}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, [])

        assert len(results) == 2
        categories = {r.category for r in results}
        assert "PATIENT_ID" in categories
        assert "ADDRESS" in categories

    def test_unknown_category_filtered_out(self):
        """LLM returns a category not in effective set — filtered out."""
        config = ShieldConfig(
            llm_detection=True,
            custom_llm_categories=[("PATIENT_ID", "Hospital patient ID")],
        )
        detector = LlmDetector(config)
        text = "Patient PAT-12345 born 1990-01-15"
        ollama_response = {"entities": [
            {"value": "PAT-12345", "category": "PATIENT_ID"},
            {"value": "1990-01-15", "category": "INVENTED_CATEGORY"},
        ]}

        def mock_urlopen(req, timeout=None):
            url = req.full_url if hasattr(req, 'full_url') else req.get_full_url()
            if "/api/tags" in url:
                return _mock_tags_ok(req, timeout)
            return _mock_urlopen_factory(ollama_response)(req, timeout)

        with patch("cloakllm.llm_detector.urllib.request.urlopen", side_effect=mock_urlopen):
            results = detector.detect(text, [])

        assert len(results) == 1
        assert results[0].category == "PATIENT_ID"
