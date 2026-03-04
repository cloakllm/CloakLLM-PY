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


@dataclass
class ShieldConfig:
    """Configuration for CloakLLM."""

    # --- Detection ---
    spacy_model: str = field(
        default_factory=lambda: os.getenv("CLOAKLLM_SPACY_MODEL", "en_core_web_sm")
    )
    # Entity types to detect via spaCy NER
    ner_entity_types: set[str] = field(
        default_factory=lambda: {"PERSON", "ORG", "GPE", "LOC", "FAC", "NORP", "EMAIL", "PHONE"}
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

    # --- Tokenization ---
    # Use descriptive tokens like [PERSON_0] vs opaque tokens like [TKN_A3F2]
    descriptive_tokens: bool = True

    # --- Audit Logging ---
    audit_enabled: bool = True
    log_dir: Path = field(
        default_factory=lambda: Path(os.getenv("CLOAKLLM_LOG_DIR", "./cloakllm_audit"))
    )
    # Log original values (set False for maximum privacy - only hashes logged)
    log_original_values: bool = False

    # --- OpenTelemetry ---
    otel_enabled: bool = field(
        default_factory=lambda: os.getenv("CLOAKLLM_OTEL_ENABLED", "false").lower() == "true"
    )
    otel_service_name: str = field(
        default_factory=lambda: os.getenv("OTEL_SERVICE_NAME", "cloakllm")
    )

    # --- LiteLLM Integration ---
    # Auto-sanitize on request, auto-desanitize on response
    auto_mode: bool = True
    # Skip sanitization for these model prefixes (e.g., local models)
    skip_models: list[str] = field(default_factory=list)

    def __post_init__(self):
        self.log_dir = Path(self.log_dir)
