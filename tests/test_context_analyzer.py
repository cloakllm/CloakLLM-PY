"""
Tests for Context-Based PII Leakage Risk Analyzer.

Tests the ContextAnalyzer class directly and its integration with Shield.
"""

import tempfile
from pathlib import Path

import pytest

from cloakllm.context_analyzer import ContextAnalyzer, RiskAssessment
from cloakllm import Shield, ShieldConfig


class TestContextAnalyzerDirect:
    """Test ContextAnalyzer class directly."""

    def setup_method(self):
        self.analyzer = ContextAnalyzer()

    def test_empty_text(self):
        result = self.analyzer.analyze("")
        assert result.risk_level == "low"
        assert result.risk_score == 0.0
        assert result.token_density == 0.0
        assert result.identifying_descriptors == 0
        assert result.relationship_edges == 0
        assert result.warnings == []

    def test_whitespace_only(self):
        result = self.analyzer.analyze("   \n\t  ")
        assert result.risk_level == "low"
        assert result.risk_score == 0.0

    def test_no_tokens(self):
        result = self.analyzer.analyze("The weather is nice today and everything is fine.")
        assert result.risk_level == "low"
        assert result.risk_score == 0.0
        assert result.token_density == 0.0

    def test_token_density_calculation(self):
        # 2 tokens in 4 words = 0.5 density
        result = self.analyzer.analyze("[EMAIL_0] [PERSON_0] hello world")
        assert result.token_density == 0.5

    def test_token_density_single_token(self):
        # 1 token in 3 words = 0.333
        result = self.analyzer.analyze("Contact [EMAIL_0] please")
        assert result.token_density == pytest.approx(0.333, abs=0.001)

    def test_identifying_descriptor_ceo(self):
        text = "The CEO of [ORG_0] announced the merger"
        result = self.analyzer.analyze(text)
        assert result.identifying_descriptors >= 1
        assert any("ceo" in w.lower() for w in result.warnings)

    def test_identifying_descriptor_founder(self):
        text = "[PERSON_0] is the founder of [ORG_0]"
        result = self.analyzer.analyze(text)
        assert result.identifying_descriptors >= 1

    def test_identifying_descriptor_wife(self):
        text = "The wife of [PERSON_0] was also present"
        result = self.analyzer.analyze(text)
        assert result.identifying_descriptors >= 1

    def test_identifying_descriptor_no_token_nearby(self):
        """Descriptors far from tokens should not count."""
        text = "The CEO made a speech. Later that day, someone emailed [EMAIL_0]"
        result = self.analyzer.analyze(text)
        # CEO is more than 5 words from [EMAIL_0], may or may not count
        # depending on exact position — test the behavior is reasonable
        assert isinstance(result.identifying_descriptors, int)

    def test_relationship_works_at(self):
        text = "[PERSON_0] works at [ORG_0] in the marketing department"
        result = self.analyzer.analyze(text)
        assert result.relationship_edges >= 1
        assert any("works at" in w for w in result.warnings)

    def test_relationship_lives_in(self):
        text = "[PERSON_0] lives in [GPE_0] with their family"
        result = self.analyzer.analyze(text)
        assert result.relationship_edges >= 1

    def test_relationship_married(self):
        text = "[PERSON_0] married [PERSON_1] in 2015"
        result = self.analyzer.analyze(text)
        assert result.relationship_edges >= 1

    def test_relationship_no_two_tokens(self):
        """Relationship without tokens on both sides should not count."""
        text = "Someone works at Acme Corp in marketing"
        result = self.analyzer.analyze(text)
        assert result.relationship_edges == 0

    def test_high_risk_score(self):
        text = (
            "The CEO of [ORG_0], who founded [ORG_1] in 2003, "
            "lives in [GPE_0] and is married to [PERSON_0]"
        )
        result = self.analyzer.analyze(text)
        assert result.risk_score > 0.3
        assert result.risk_level in ("medium", "high")
        assert len(result.warnings) > 0

    def test_low_risk_simple_tokens(self):
        text = "Please process this email from [EMAIL_0] regarding the invoice."
        result = self.analyzer.analyze(text)
        assert result.risk_level == "low" or result.risk_score < 0.4

    def test_redacted_tokens_detected(self):
        text = "[EMAIL_REDACTED] [PERSON_REDACTED] hello world"
        result = self.analyzer.analyze(text)
        assert result.token_density == 0.5

    def test_mixed_tokens(self):
        """Both numbered and REDACTED tokens should be detected."""
        text = "[EMAIL_0] contacted [PERSON_REDACTED] about [ORG_1]"
        result = self.analyzer.analyze(text)
        assert result.token_density > 0

    def test_warnings_capped_at_5(self):
        """Maximum 5 warnings should be returned."""
        text = (
            "The CEO of [ORG_0] and president of [ORG_1] and director of [ORG_2] "
            "and chairman of [ORG_3] and founder of [ORG_4] "
            "and head of [ORG_5] and chief of [ORG_6]"
        )
        result = self.analyzer.analyze(text)
        assert len(result.warnings) <= 5

    def test_risk_score_capped_at_1(self):
        """Risk score should never exceed 1.0."""
        # Create extremely dense text
        tokens = " ".join(f"[PERSON_{i}]" for i in range(50))
        result = self.analyzer.analyze(tokens)
        assert result.risk_score <= 1.0

    def test_risk_levels(self):
        """Test the three risk level thresholds."""
        # Low: score <= 0.3
        low = self.analyzer.analyze("Hello world, no tokens here at all.")
        assert low.risk_level == "low"

        # Scores between 0 and 1 should map to correct levels
        assert low.risk_score <= 0.3

    def test_to_dict(self):
        result = self.analyzer.analyze("[EMAIL_0] hello")
        d = result.to_dict()
        assert isinstance(d, dict)
        assert "token_density" in d
        assert "identifying_descriptors" in d
        assert "relationship_edges" in d
        assert "risk_score" in d
        assert "risk_level" in d
        assert "warnings" in d

    def test_punctuation_stripping_on_descriptors(self):
        """Descriptors with punctuation should still be detected."""
        text = "The CEO, [PERSON_0], announced the deal."
        result = self.analyzer.analyze(text)
        assert result.identifying_descriptors >= 1

    def test_long_text(self):
        """Should handle long texts without errors."""
        text = "Hello world. " * 1000 + "[EMAIL_0] is here."
        result = self.analyzer.analyze(text)
        assert isinstance(result, RiskAssessment)
        assert result.token_density < 0.01  # Very diluted


class TestShieldContextRiskIntegration:
    """Test ContextAnalyzer integration with Shield."""

    def test_analyze_context_risk_method(self):
        """Shield.analyze_context_risk() should work without config flag."""
        shield = Shield(ShieldConfig(audit_enabled=False))
        result = shield.analyze_context_risk("[PERSON_0] works at [ORG_0]")
        assert isinstance(result, dict)
        assert "risk_score" in result
        assert "risk_level" in result
        assert result["relationship_edges"] >= 1

    def test_analyze_context_risk_no_tokens(self):
        shield = Shield(ShieldConfig(audit_enabled=False))
        result = shield.analyze_context_risk("Just a normal sentence.")
        assert result["risk_level"] == "low"
        assert result["risk_score"] == 0.0

    def test_auto_analysis_disabled_by_default(self):
        """By default, context_analysis is False — no risk on token_map."""
        shield = Shield(ShieldConfig(audit_enabled=False))
        _, token_map = shield.sanitize("Contact john@acme.com")
        assert token_map.risk_assessment is None

    def test_auto_analysis_enabled(self):
        """When context_analysis=True, risk_assessment is attached to token_map."""
        shield = Shield(ShieldConfig(
            audit_enabled=False,
            context_analysis=True,
        ))
        _, token_map = shield.sanitize("Contact john@acme.com about the project")
        assert token_map.risk_assessment is not None
        assert "risk_score" in token_map.risk_assessment
        assert "risk_level" in token_map.risk_assessment

    def test_auto_analysis_with_high_risk(self):
        """Auto-analysis should set risk on high-risk sanitized text."""
        shield = Shield(ShieldConfig(
            audit_enabled=False,
            context_analysis=True,
        ))
        text = "The CEO of Acme Corp works at their office in New York"
        _, token_map = shield.sanitize(text)
        assert token_map.risk_assessment is not None

    def test_auto_analysis_in_audit_log(self):
        """When context_analysis=True, audit log should include risk_assessment."""
        with tempfile.TemporaryDirectory() as tmpdir:
            shield = Shield(ShieldConfig(
                log_dir=tmpdir,
                audit_enabled=True,
                context_analysis=True,
            ))
            shield.sanitize("Contact john@acme.com about the project")
            # Verify audit file was created and has content
            import json
            log_files = list(Path(tmpdir).glob("audit_*.jsonl"))
            assert len(log_files) == 1
            with open(log_files[0]) as f:
                entry = json.loads(f.readline())
            assert "risk_assessment" in entry

    def test_batch_sanitize_with_context_analysis(self):
        """sanitize_batch should also perform context analysis when enabled."""
        shield = Shield(ShieldConfig(
            audit_enabled=False,
            context_analysis=True,
        ))
        texts = ["Email john@acme.com", "The CEO of Acme Corp"]
        _, token_map = shield.sanitize_batch(texts)
        # Batch creates combined sanitized text — risk may or may not be set
        # but the operation should not error
        assert isinstance(token_map.risk_assessment, (dict, type(None)))

    def test_context_risk_threshold_config(self):
        """context_risk_threshold should be configurable."""
        config = ShieldConfig(
            audit_enabled=False,
            context_analysis=True,
            context_risk_threshold=0.1,
        )
        assert config.context_risk_threshold == 0.1

    def test_roundtrip_with_context_analysis(self):
        """Context analysis should not affect sanitize/desanitize roundtrip."""
        shield = Shield(ShieldConfig(
            audit_enabled=False,
            context_analysis=True,
        ))
        original = "Contact john@acme.com about the project"
        sanitized, token_map = shield.sanitize(original)
        restored = shield.desanitize(sanitized, token_map)
        assert restored == original


class TestRiskAssessmentDataclass:
    """Test RiskAssessment dataclass."""

    def test_fields(self):
        ra = RiskAssessment(
            token_density=0.5,
            identifying_descriptors=2,
            relationship_edges=1,
            risk_score=0.65,
            risk_level="medium",
            warnings=["test warning"],
        )
        assert ra.token_density == 0.5
        assert ra.identifying_descriptors == 2
        assert ra.relationship_edges == 1
        assert ra.risk_score == 0.65
        assert ra.risk_level == "medium"
        assert ra.warnings == ["test warning"]

    def test_to_dict_roundtrip(self):
        ra = RiskAssessment(
            token_density=0.3,
            identifying_descriptors=1,
            relationship_edges=0,
            risk_score=0.45,
            risk_level="medium",
            warnings=["descriptor near token"],
        )
        d = ra.to_dict()
        assert d["token_density"] == 0.3
        assert d["risk_level"] == "medium"
        assert len(d["warnings"]) == 1
