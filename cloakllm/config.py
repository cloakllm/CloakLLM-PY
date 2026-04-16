"""
CloakLLM configuration.

All settings have sensible defaults. Override via:
    config = ShieldConfig(log_dir="./my-audit-logs", spacy_model="en_core_web_lg")
    shield = Shield(config=config)

Or via environment variables:
    CLOAKLLM_LOG_DIR=./my-audit-logs
    CLOAKLLM_SPACY_MODEL=en_core_web_lg
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


_LOCALE_MODELS = {
    "en": "en_core_web_sm",
    "de": "de_core_news_sm",
    "fr": "fr_core_news_sm",
    "es": "es_core_news_sm",
    "nl": "nl_core_news_sm",       # OntoNotes labels (PERSON, ORG, GPE, etc.)
    "zh": "zh_core_web_sm",        # OntoNotes labels
    "ja": "ja_core_news_sm",       # OntoNotes labels + Japanese-specific
    "ru": "ru_core_news_sm",       # WikiNER labels (PER, LOC, ORG — no MISC)
    "ko": "ko_core_news_sm",       # KLUE labels (PS, LC, OG, DT, QT, TI)
    "it": "it_core_news_sm",       # WikiNER labels (PER, LOC, ORG, MISC)
    "pl": "pl_core_news_sm",       # NKJP labels (persName, placeName, orgName, geogName)
    "pt": "pt_core_news_sm",       # WikiNER labels (PER, LOC, ORG, MISC)
    # "he" — no official spaCy model; uses regex + Ollama LLM only
    # "hi" — no official spaCy model; uses regex + Ollama LLM only
    "multi": "xx_ent_wiki_sm",     # WikiNER labels (PER, LOC, ORG, MISC)
}


@dataclass
class ShieldConfig:
    """Configuration for CloakLLM."""

    # --- Locale ---
    locale: str = field(
        default_factory=lambda: os.getenv("CLOAKLLM_LOCALE", "en")
    )  # Language/locale code: en, de, fr, es, nl, he, zh, ja, ru, ko, it, pl, pt, hi, multi

    # --- Detection ---
    spacy_model: str = field(
        default_factory=lambda: os.getenv("CLOAKLLM_SPACY_MODEL", "en_core_web_sm")
    )
    # Entity types to detect via spaCy NER
    ner_entity_types: set[str] = field(
        default_factory=lambda: {
            # OntoNotes (en, nl, zh, ja)
            "PERSON", "ORG", "GPE", "LOC", "FAC", "NORP",
            # WikiNER (de, fr, es, it, pt, ru)
            "PER", "MISC",
            # KLUE (ko)
            "PS", "LC", "OG",
            # NKJP (pl)
            "persName", "placeName", "orgName", "geogName",
            # Regex-covered (pass-through)
            "EMAIL", "PHONE",
        }
    )
    # Enable/disable regex-based detection
    detect_emails: bool = True
    detect_phones: bool = True
    detect_ssns: bool = True
    detect_credit_cards: bool = True
    detect_api_keys: bool = True
    detect_ip_addresses: bool = True
    detect_iban: bool = True
    # Custom patterns: list of (name, regex_pattern) tuples
    custom_patterns: list[tuple[str, str]] = field(default_factory=list)
    # Custom LLM categories: list of (name, description) tuples for semantic detection
    custom_llm_categories: list[tuple[str, str]] = field(default_factory=list)

    # --- LLM Detection (Pass 3: local LLM via Ollama) ---
    llm_detection: bool = field(
        default_factory=lambda: os.getenv("CLOAKLLM_LLM_DETECTION", "false").lower() == "true"
    )
    llm_model: str = field(
        default_factory=lambda: os.getenv("CLOAKLLM_LLM_MODEL", "llama3.2")
    )
    llm_ollama_url: str = field(
        default_factory=lambda: os.getenv("CLOAKLLM_OLLAMA_URL", "http://localhost:11434")
    )
    llm_timeout: float = 10.0
    llm_confidence: float = 0.85
    llm_allow_remote: bool = field(
        default_factory=lambda: os.getenv("CLOAKLLM_LLM_ALLOW_REMOTE", "false").lower() == "true"
    )

    # --- Context Analysis ---
    context_analysis: bool = field(
        default_factory=lambda: os.getenv("CLOAKLLM_CONTEXT_ANALYSIS", "false").lower() == "true"
    )
    context_risk_threshold: float = 0.7

    # --- Tokenization ---
    # Mode: "tokenize" (reversible tokens) or "redact" (irreversible [CATEGORY_REDACTED])
    mode: str = "tokenize"
    # Use descriptive tokens like [PERSON_0] vs opaque tokens like [TKN_A3F2]
    descriptive_tokens: bool = True

    # --- Entity Hashing ---
    # Enable per-entity HMAC-SHA256 hashing in entity_details (for cross-document linkage)
    entity_hashing: bool = field(
        default_factory=lambda: os.getenv("CLOAKLLM_ENTITY_HASHING", "false").lower() == "true"
    )
    # HMAC key — if empty and entity_hashing is True, a random key is auto-generated per session
    entity_hash_key: str = field(
        default_factory=lambda: os.getenv("CLOAKLLM_ENTITY_HASH_KEY", "")
    )

    # --- Audit Logging ---
    audit_enabled: bool = True
    log_dir: Path = field(
        default_factory=lambda: Path(os.getenv("CLOAKLLM_LOG_DIR", "./cloakllm_audit"))
    )
    # --- OpenTelemetry ---
    otel_enabled: bool = field(
        default_factory=lambda: os.getenv("CLOAKLLM_OTEL_ENABLED", "false").lower() == "true"
    )
    otel_service_name: str = field(
        default_factory=lambda: os.getenv("OTEL_SERVICE_NAME", "cloakllm")
    )

    # --- Attestation (Ed25519 signing) ---
    # Pre-loaded DeploymentKeyPair object (from cloakllm.attestation)
    attestation_key: Optional[Any] = None
    # Path to keypair JSON file (loaded on Shield init)
    attestation_key_path: Optional[str] = field(
        default_factory=lambda: os.getenv("CLOAKLLM_SIGNING_KEY_PATH", None)
    )

    # --- Compliance Mode (v0.6.0) ---
    # When set, enforces an Article 12-compliant audit log structure and
    # adds compliance metadata fields to every log entry.
    # Accepted values: "eu_ai_act_article12" | None
    compliance_mode: Optional[str] = field(
        default_factory=lambda: os.getenv("CLOAKLLM_COMPLIANCE_MODE", None)
    )
    # Retention hint included in compliance-mode audit entries.
    # 180 = EU AI Act Article 12 minimum (6 months for deployers).
    retention_hint_days: int = 180

    # --- Enterprise Key Management (v0.6.0, Python only) ---
    # Provider for attestation signing keys.
    # Accepted values: "aws_kms" | "gcp_kms" | "azure_keyvault" | "hashicorp_vault" | None
    attestation_key_provider: Optional[str] = field(
        default_factory=lambda: os.getenv("CLOAKLLM_KEY_PROVIDER", None)
    )
    # Provider-specific key ID/ARN/name
    attestation_key_id: Optional[str] = field(
        default_factory=lambda: os.getenv("CLOAKLLM_KEY_ID", None)
    )
    # If True, checks key version on session init and logs a key_rotation_event
    key_rotation_enabled: bool = field(
        default_factory=lambda: os.getenv("CLOAKLLM_KEY_ROTATION", "false").lower() == "true"
    )

    # --- LiteLLM Integration ---
    # Auto-sanitize on request, auto-desanitize on response
    auto_mode: bool = True
    # Skip sanitization for these model prefixes (e.g., local models)
    skip_models: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.log_dir = Path(self.log_dir)
        if self.mode not in ("tokenize", "redact"):
            raise ValueError(f"Invalid mode '{self.mode}'. Must be 'tokenize' or 'redact'.")
        # Compliance mode validation
        _VALID_COMPLIANCE_MODES = (None, "eu_ai_act_article12")
        if self.compliance_mode not in _VALID_COMPLIANCE_MODES:
            raise ValueError(
                f"Invalid compliance_mode '{self.compliance_mode}'. "
                f"Must be one of {[m for m in _VALID_COMPLIANCE_MODES if m]} or None."
            )
        if self.retention_hint_days < 1:
            raise ValueError(
                f"retention_hint_days must be >= 1 (got {self.retention_hint_days})."
            )
        # Key provider validation
        _VALID_KEY_PROVIDERS = (None, "aws_kms", "gcp_kms", "azure_keyvault", "hashicorp_vault")
        if self.attestation_key_provider not in _VALID_KEY_PROVIDERS:
            raise ValueError(
                f"Invalid attestation_key_provider '{self.attestation_key_provider}'. "
                f"Must be one of {[p for p in _VALID_KEY_PROVIDERS if p]} or None."
            )
        if self.attestation_key_provider and not self.attestation_key_id:
            raise ValueError(
                f"attestation_key_id is required when attestation_key_provider='{self.attestation_key_provider}'."
            )
        from cloakllm.token_spec import validate_category_name, RESERVED_CATEGORIES
        for name, _desc in self.custom_llm_categories:
            if not validate_category_name(name):
                raise ValueError(
                    f"Invalid custom LLM category name '{name}'. "
                    "Must match ^[A-Z][A-Z0-9_]*$"
                )
            if name in RESERVED_CATEGORIES:
                raise ValueError(
                    f"Custom LLM category '{name}' conflicts with built-in category."
                )

        # Auto-select spaCy model if locale != en and user didn't explicitly override.
        # Note: This checks if spacy_model still equals the default "en_core_web_sm".
        # If a user explicitly passes spacy_model="en_core_web_sm" AND locale="de",
        # the German model will be auto-selected (because we can't distinguish
        # "user passed the default" from "user didn't pass anything"). This is the
        # desired behavior — the locale should drive model selection unless a
        # non-English model is explicitly specified.
        if self.locale != "en" and self.spacy_model == "en_core_web_sm":
            model = _LOCALE_MODELS.get(self.locale)
            if model:
                self.spacy_model = model

        # Path validation
        import warnings as _warnings
        _resolved_log = self.log_dir.resolve()
        _cwd = Path.cwd().resolve()
        try:
            _resolved_log.relative_to(_cwd)
        except ValueError:
            _warnings.warn(
                f"CloakLLM: log_dir '{_resolved_log}' is outside the current working directory.",
                RuntimeWarning, stacklevel=2,
            )
        if self.attestation_key_path:
            _resolved_key = Path(self.attestation_key_path).resolve()
            try:
                _resolved_key.relative_to(_cwd)
            except ValueError:
                _warnings.warn(
                    f"CloakLLM: attestation_key_path '{_resolved_key}' is outside the current working directory.",
                    RuntimeWarning, stacklevel=2,
                )
