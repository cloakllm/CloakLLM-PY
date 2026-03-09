"""
LLM-based PII Detection (Pass 3).

Uses a local Ollama instance to detect semantic/contextual PII that regex
and spaCy NER miss (addresses, medical info, financial data, etc.).

Opt-in via config: ShieldConfig(llm_detection=True)
Data never leaves the user's machine.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from cloakllm.config import ShieldConfig

logger = logging.getLogger("cloakllm.llm_detector")

# Categories the LLM should detect (excludes regex + NER covered ones)
LLM_CATEGORIES = frozenset({
    "ADDRESS", "DATE_OF_BIRTH", "MEDICAL", "FINANCIAL",
    "NATIONAL_ID", "BIOMETRIC", "USERNAME", "PASSWORD", "VEHICLE",
})

# Categories already covered by regex or spaCy — LLM should NOT detect these
EXCLUDED_CATEGORIES = frozenset({
    "EMAIL", "PHONE", "SSN", "CREDIT_CARD", "IP_ADDRESS",
    "API_KEY", "IBAN", "JWT", "ORG", "GPE", "PERSON",
})


@dataclass(frozen=True)
class _CachedResult:
    entities: list[dict]


class LlmDetector:
    """Detects semantic PII via a local Ollama LLM."""

    def __init__(self, config: ShieldConfig):
        self._model = config.llm_model
        self._base_url = config.llm_ollama_url.rstrip("/")
        self._timeout = config.llm_timeout
        self._confidence = config.llm_confidence
        self._available: bool | None = None  # None = not checked yet
        self._cache: dict[str, _CachedResult] = {}
        # Custom LLM categories
        self._custom_categories: dict[str, str] = {}
        for name, desc in getattr(config, 'custom_llm_categories', []):
            if name in EXCLUDED_CATEGORIES:
                logger.warning("Custom LLM category '%s' conflicts with excluded category — skipped", name)
                continue
            self._custom_categories[name] = desc

    @property
    def _effective_categories(self) -> frozenset[str]:
        return LLM_CATEGORIES | frozenset(self._custom_categories)

    def _check_available(self) -> bool:
        """Ping Ollama. Cache result so we only check once."""
        if self._available is not None:
            return self._available
        try:
            req = urllib.request.Request(f"{self._base_url}/api/tags", method="GET")
            urllib.request.urlopen(req, timeout=3)
            self._available = True
        except Exception:
            logger.warning("Ollama not available at %s — LLM detection disabled", self._base_url)
            self._available = False
        return self._available

    def _system_prompt(self) -> str:
        cats = ", ".join(sorted(self._effective_categories))
        excluded = ", ".join(sorted(EXCLUDED_CATEGORIES))
        prompt = (
            "You are a PII detection engine. Given text, extract sensitive entities.\n"
            f"Return ONLY entities in these categories: {cats}\n"
            f"Do NOT detect: {excluded} (already handled by other systems).\n"
            "Return valid JSON: {\"entities\": [{\"value\": \"exact text from input\", \"category\": \"CATEGORY\"}]}\n"
            "Rules:\n"
            "- \"value\" must be an EXACT substring of the input text\n"
            "- Do not paraphrase or modify values\n"
            "- If no entities found, return {\"entities\": []}\n"
            "- Only return high-confidence detections"
        )
        # Add category hints for custom categories with descriptions
        hints = [(name, desc) for name, desc in self._custom_categories.items() if desc]
        if hints:
            prompt += "\nCategory hints:"
            for name, desc in sorted(hints):
                prompt += f"\n- {name}: {desc}"
        return prompt

    def _build_prompt(self, text: str) -> str:
        return f"Extract PII entities from this text:\n\n{text}"

    def _query_ollama(self, text: str) -> list[dict]:
        """Send text to Ollama and parse JSON response."""
        payload = json.dumps({
            "model": self._model,
            "messages": [
                {"role": "system", "content": self._system_prompt()},
                {"role": "user", "content": self._build_prompt(text)},
            ],
            "format": "json",
            "stream": False,
            "options": {"temperature": 0.0},
        }).encode()

        req = urllib.request.Request(
            f"{self._base_url}/api/chat",
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )

        try:
            resp = urllib.request.urlopen(req, timeout=self._timeout)
            body = json.loads(resp.read())
            content = body.get("message", {}).get("content", "{}")
            parsed = json.loads(content)
            entities = parsed.get("entities", [])
            if not isinstance(entities, list):
                return []
            return entities
        except (urllib.error.URLError, json.JSONDecodeError, KeyError, TimeoutError, OSError) as exc:
            logger.warning("Ollama query failed: %s", exc)
            return []

    def detect(self, text: str, covered_spans: list[tuple[int, int]]) -> list:
        """
        Detect semantic PII via LLM.

        Args:
            text: The original text to scan.
            covered_spans: Spans already detected by regex/NER (to skip).

        Returns:
            list of Detection objects for newly found entities.
        """
        from cloakllm.detector import Detection

        if not self._check_available():
            return []

        # Check cache
        if text in self._cache:
            entities = self._cache[text].entities
        else:
            entities = self._query_ollama(text)
            self._cache[text] = _CachedResult(entities=entities)

        # Sort by value length desc (longer matches first)
        entities.sort(key=lambda e: len(e.get("value", "")), reverse=True)

        detections: list[Detection] = []
        for ent in entities:
            value = ent.get("value", "")
            category = ent.get("category", "").upper()

            # Skip invalid
            if len(value) < 2:
                continue
            if category not in self._effective_categories:
                continue

            # Find all occurrences in text
            for match in re.finditer(re.escape(value), text):
                start, end = match.start(), match.end()
                # Skip if overlapping with already-covered spans
                if any(start < ce and end > cs for cs, ce in covered_spans):
                    continue
                detections.append(Detection(
                    text=value,
                    category=category,
                    start=start,
                    end=end,
                    confidence=self._confidence,
                    source="llm",
                ))
                covered_spans.append((start, end))

        return detections
