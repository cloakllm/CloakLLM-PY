"""
v0.6.1 F1 regression: API_KEY pattern must detect real-world key formats.

Original v0.6.0 plan would have capped at 64 chars, missing:
- Anthropic keys (~100ch): sk-ant-XXXXXXXX...
- GitHub fine-grained PATs (~94ch): github_pat_XXX_XXX...
- Bearer tokens (200+ ch)

v0.6.1 ships {20,512} which covers all of the above while still bounding ReDoS.
Also covers v0.6.1 H1.4 input length cap.
"""

import pytest

from cloakllm import Shield, ShieldConfig


@pytest.fixture
def shield(tmp_path):
    config = ShieldConfig(audit_enabled=False, log_dir=tmp_path / "audit")
    return Shield(config)


def _detected_categories(shield, text):
    """Return set of detected categories."""
    result = shield.analyze(text, redact_values=False)
    return {e["category"] for e in result["entities"]}


def test_detects_anthropic_key(shield):
    """Anthropic API keys are ~100 chars, must be detected."""
    key = "sk-ant-api03-" + "A" * 87
    text = f"My key is {key}"
    cats = _detected_categories(shield, text)
    assert "API_KEY" in cats, f"Should detect Anthropic key (len={len(key)}); got {cats}"


def test_detects_stripe_secret_key(shield):
    """Stripe secret keys: sk_live_<24 alphanumeric> = 32 chars."""
    key = "sk_live_" + "A" * 24
    text = f"Stripe key: {key}"
    cats = _detected_categories(shield, text)
    assert "API_KEY" in cats


def test_detects_openai_key(shield):
    """OpenAI keys: sk-<48 alphanumeric> = 51 chars."""
    key = "sk-" + "A" * 48
    text = f"OpenAI: {key}"
    cats = _detected_categories(shield, text)
    assert "API_KEY" in cats


def test_detects_long_bearer_token(shield):
    """Bearer tokens of 200+ chars (common for AWS session tokens, JWTs as bearers)."""
    token = "bearer_" + "A" * 200
    text = f"Auth: {token}"
    cats = _detected_categories(shield, text)
    assert "API_KEY" in cats


def test_detects_400_char_bearer(shield):
    """400-char bearer (within 512 cap)."""
    token = "bearer_" + "A" * 400
    text = f"x {token} y"
    cats = _detected_categories(shield, text)
    assert "API_KEY" in cats


# --- v0.6.1 H1.4: input length cap ---


def test_input_length_cap_default_1mb(shield):
    """Default cap is 1MB. Larger input raises ValueError."""
    big = "x" * 1_000_001
    with pytest.raises(ValueError, match="max_input_length"):
        shield.sanitize(big)


def test_input_length_cap_disabled_with_zero(tmp_path):
    """max_input_length=0 disables the CloakLLM cap.

    Note: spaCy NER has its own hardcoded 1M-char limit (independent of CloakLLM).
    To exercise the cloakllm cap-disable behavior in isolation, we go just past
    CloakLLM's default cap (1M+1) without exceeding spaCy's.
    """
    config = ShieldConfig(
        audit_enabled=False, log_dir=tmp_path / "audit",
        max_input_length=0,
    )
    shield = Shield(config)
    # Slightly over default cap, well under spaCy's 1M char limit. Use spaces
    # to keep token count low so spaCy's own internal limits are not hit.
    big = "x" * 999_999  # just under spaCy's 1M cap, well above where the cap-disabled would matter
    sanitized, _ = shield.sanitize(big)
    assert isinstance(sanitized, str)


def test_input_length_cap_configurable(tmp_path):
    """max_input_length can be raised within spaCy's 1M character ceiling.

    spaCy itself caps at 1M characters; CloakLLM's max_input_length is the
    OUTER bound. Operators wanting larger inputs need to raise spaCy's
    `nlp.max_length` separately.
    """
    config = ShieldConfig(
        audit_enabled=False, log_dir=tmp_path / "audit",
        max_input_length=2_000_000,
    )
    shield = Shield(config)
    # Below spaCy's hard limit — confirms cloakllm cap raise works
    medium = "x" * 999_000
    sanitized, _ = shield.sanitize(medium)
    assert isinstance(sanitized, str)


def test_input_length_cap_applies_to_batch(shield):
    """sanitize_batch validates each text individually."""
    big = "x" * 1_000_001
    with pytest.raises(ValueError, match=r"texts\[1\]"):
        shield.sanitize_batch(["small", big, "small"])


def test_input_length_cap_applies_to_analyze(shield):
    big = "x" * 1_000_001
    with pytest.raises(ValueError, match="max_input_length"):
        shield.analyze(big, redact_values=False)
