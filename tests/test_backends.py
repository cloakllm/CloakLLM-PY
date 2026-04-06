"""Tests for pluggable detection backends."""

import pytest

from cloakllm.backends import DetectorBackend, RegexBackend, NerBackend, LlmBackend
from cloakllm.backends.base import DetectorBackend as BaseBackend
from cloakllm.config import ShieldConfig
from cloakllm.detector import Detection, DetectionEngine
from cloakllm.shield import Shield


# ---- DetectorBackend ABC ----

class TestDetectorBackend:
    def test_cannot_instantiate_abc(self):
        with pytest.raises(TypeError):
            DetectorBackend()

    def test_subclass_must_implement_name(self):
        class BadBackend(DetectorBackend):
            def detect(self, text, covered_spans):
                return []
        with pytest.raises(TypeError):
            BadBackend()

    def test_subclass_must_implement_detect(self):
        class BadBackend(DetectorBackend):
            @property
            def name(self):
                return "bad"
        with pytest.raises(TypeError):
            BadBackend()

    def test_valid_subclass(self):
        class GoodBackend(DetectorBackend):
            @property
            def name(self):
                return "good"
            def detect(self, text, covered_spans):
                return []
        b = GoodBackend()
        assert b.name == "good"
        assert b.detect("hello", []) == []


# ---- RegexBackend ----

class TestRegexBackend:
    def test_name(self):
        backend = RegexBackend(ShieldConfig())
        assert backend.name == "regex"

    def test_detects_email(self):
        backend = RegexBackend(ShieldConfig())
        spans = []
        results = backend.detect("Contact john@acme.com today", spans)
        assert len(results) == 1
        assert results[0].category == "EMAIL"
        assert results[0].text == "john@acme.com"
        assert results[0].source == "regex"
        assert len(spans) == 1

    def test_detects_ssn(self):
        backend = RegexBackend(ShieldConfig())
        results = backend.detect("SSN: 123-45-6789", [])
        assert any(d.category == "SSN" for d in results)

    def test_respects_config_flags(self):
        config = ShieldConfig(detect_emails=False)
        backend = RegexBackend(config)
        results = backend.detect("Contact john@acme.com", [])
        assert not any(d.category == "EMAIL" for d in results)

    def test_custom_patterns(self):
        config = ShieldConfig(custom_patterns=[("TICKET", r"TICK-\d+")])
        backend = RegexBackend(config)
        results = backend.detect("See TICK-1234", [])
        assert len(results) == 1
        assert results[0].category == "TICKET"

    def test_covered_spans_respected(self):
        backend = RegexBackend(ShieldConfig())
        # Pre-cover the span where the email is
        spans = [(8, 21)]
        results = backend.detect("Contact john@acme.com today", spans)
        assert not any(d.category == "EMAIL" for d in results)

    def test_covered_spans_mutated(self):
        backend = RegexBackend(ShieldConfig())
        spans = []
        backend.detect("Contact john@acme.com today", spans)
        assert len(spans) > 0


# ---- NerBackend ----

class TestNerBackend:
    def test_name(self):
        backend = NerBackend(ShieldConfig())
        assert backend.name == "ner"

    def test_detects_person(self):
        backend = NerBackend(ShieldConfig())
        # Force load spaCy
        _ = backend.nlp
        results = backend.detect("John Smith went to the store", [])
        # spaCy may or may not detect this depending on model — just check interface
        assert isinstance(results, list)
        for d in results:
            assert isinstance(d, Detection)

    def test_covered_spans_respected(self):
        backend = NerBackend(ShieldConfig())
        # Cover the whole text
        spans = [(0, 100)]
        results = backend.detect("John Smith works at Google", spans)
        assert len(results) == 0


# ---- Custom Backend ----

class TestCustomBackend:
    def test_custom_backend_in_pipeline(self):
        class UppercaseDetector(DetectorBackend):
            @property
            def name(self):
                return "uppercase"

            def detect(self, text, covered_spans):
                import re
                detections = []
                for m in re.finditer(r'\b[A-Z]{3,}\b', text):
                    start, end = m.start(), m.end()
                    if any(start < e and end > s for s, e in covered_spans):
                        continue
                    detections.append(Detection(
                        text=m.group(),
                        category="UPPERCASE_WORD",
                        start=start,
                        end=end,
                        confidence=0.9,
                        source="uppercase",
                    ))
                    covered_spans.append((start, end))
                return detections

        # Use custom backend alone
        config = ShieldConfig()
        engine = DetectionEngine(config, backends=[UppercaseDetector()])
        detections, timing = engine.detect("Check the NASA report")
        assert len(detections) == 1
        assert detections[0].category == "UPPERCASE_WORD"
        assert detections[0].text == "NASA"
        assert "uppercase_ms" in timing

    def test_custom_backend_with_shield(self):
        class AlwaysDetector(DetectorBackend):
            @property
            def name(self):
                return "always"

            def detect(self, text, covered_spans):
                covered_spans.append((0, 4))
                return [Detection(
                    text="test",
                    category="TEST",
                    start=0,
                    end=4,
                    confidence=1.0,
                    source="always",
                )]

        shield = Shield(backends=[AlwaysDetector()])
        sanitized, token_map = shield.sanitize("test input")
        assert "[TEST_0]" in sanitized


# ---- DetectionEngine with backends ----

class TestDetectionEnginePipeline:
    def test_default_pipeline_has_regex_and_ner(self):
        engine = DetectionEngine(ShieldConfig())
        names = [b.name for b in engine._backends]
        assert "regex" in names
        assert "ner" in names

    def test_default_pipeline_no_llm_by_default(self):
        engine = DetectionEngine(ShieldConfig())
        names = [b.name for b in engine._backends]
        assert "llm" not in names

    def test_custom_backends_replace_default(self):
        config = ShieldConfig()
        regex = RegexBackend(config)
        engine = DetectionEngine(config, backends=[regex])
        assert len(engine._backends) == 1
        assert engine._backends[0].name == "regex"

    def test_timing_keys_match_backend_names(self):
        config = ShieldConfig()
        engine = DetectionEngine(config)
        _, timing = engine.detect("john@acme.com")
        for backend in engine._backends:
            assert f"{backend.name}_ms" in timing

    def test_backward_compat_compiled_patterns(self):
        engine = DetectionEngine(ShieldConfig())
        assert len(engine._compiled_patterns) > 0

    def test_backward_compat_nlp(self):
        engine = DetectionEngine(ShieldConfig())
        # Should not raise
        nlp = engine._nlp
        assert nlp is not None


# ---- Shield with backends ----

class TestShieldBackends:
    def test_shield_default_pipeline(self):
        shield = Shield()
        names = [b.name for b in shield.detector._backends]
        assert "regex" in names
        assert "ner" in names

    def test_shield_custom_backends(self):
        config = ShieldConfig()
        regex = RegexBackend(config)
        shield = Shield(config, backends=[regex])
        assert len(shield.detector._backends) == 1

    def test_shield_metrics_dynamic_keys(self):
        shield = Shield()
        sanitized, _ = shield.sanitize("Email john@acme.com")
        m = shield.metrics()
        for backend in shield.detector._backends:
            assert f"{backend.name}_ms" in m["detection"]

    def test_shield_sanitize_batch_dynamic_timing(self):
        shield = Shield()
        texts = ["Email john@acme.com", "Call 555-123-4567"]
        sanitized_texts, _ = shield.sanitize_batch(texts)
        assert len(sanitized_texts) == 2
        m = shield.metrics()
        for backend in shield.detector._backends:
            assert f"{backend.name}_ms" in m["detection"]
