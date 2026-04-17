"""
LLM-based PII Detection (Pass 3).

Uses a local Ollama instance to detect semantic/contextual PII that regex
and spaCy NER miss (addresses, medical info, financial data, etc.).

Opt-in via config: ShieldConfig(llm_detection=True)
Data never leaves the user's machine.

SECURITY NOTE: LLM-based detection is advisory and non-deterministic.
It must never be the sole detection mechanism. The LLM may miss entities
or hallucinate false detections. Always use in combination with regex
and NER detection (Pass 1 and Pass 2). The LLM prompt is not hardened
against prompt injection — adversarial input text could manipulate results.
"""

from __future__ import annotations

import json
import logging
import re
import urllib.error
import urllib.request
from collections import OrderedDict
import hashlib
import ipaddress
import socket
import threading
import urllib.parse
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


class _BoundedCache:
    """LRU cache with a maximum size."""

    def __init__(self, maxsize: int = 1024):
        self._cache: OrderedDict[str, _CachedResult] = OrderedDict()
        self._maxsize = maxsize
        self._lock = threading.Lock()

    def get(self, key: str) -> _CachedResult | None:
        with self._lock:
            if key in self._cache:
                self._cache.move_to_end(key)
                return self._cache[key]
            return None

    def set(self, key: str, value: _CachedResult) -> None:
        with self._lock:
            self._cache[key] = value
            if len(self._cache) > self._maxsize:
                self._cache.popitem(last=False)

    def clear(self) -> None:
        with self._lock:
            self._cache.clear()


# Private IP ranges for URL validation
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),
]


def _validate_ollama_url(url: str, allow_remote: bool) -> str:
    """Validate that the Ollama URL points to a local/private address."""
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""

    # Fast path for common localhost names
    if hostname in ("localhost", "127.0.0.1", "::1"):
        return url

    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
        for _family, _type, _proto, _canonname, sockaddr in infos:
            ip = ipaddress.ip_address(sockaddr[0])
            if any(ip in net for net in _PRIVATE_NETWORKS):
                return url
    except (socket.gaierror, ValueError, OSError):
        pass

    if allow_remote:
        logger.warning(
            "CloakLLM: Ollama URL '%s' points to a non-local address. "
            "PII data will be sent to this remote server.", url
        )
        return url

    raise ValueError(
        f"CloakLLM: Ollama URL '{url}' points to a non-local address. "
        f"Set llm_allow_remote=True to allow remote Ollama instances. "
        f"WARNING: PII data will be sent to the remote server."
    )


_LOCALE_HINTS = {
    "de": "The input text is in German. Look for German PII formats (Steuer-ID, IBAN DE, German phone numbers, addresses).",
    "fr": "The input text is in French. Look for French PII formats (NIR/Sécu, IBAN FR, French phone numbers, addresses).",
    "es": "The input text is in Spanish. Look for Spanish PII formats (DNI, NIE, IBAN ES, Spanish phone numbers, addresses).",
    "nl": "The input text is in Dutch. Look for Dutch PII formats (BSN, IBAN NL, Dutch phone numbers, addresses).",
    "he": "The input text is in Hebrew. Look for Israeli PII formats (Teudat Zehut, Israeli phone numbers, addresses).",
    "zh": "The input text is in Chinese. Look for Chinese PII formats (身份证号, Chinese phone numbers, addresses).",
    "ja": "The input text is in Japanese. Look for Japanese PII formats (マイナンバー, Japanese phone numbers, addresses).",
    "ru": "The input text is in Russian. Look for Russian PII formats (ИНН, СНИЛС, Russian passport, phone numbers, addresses).",
    "ko": "The input text is in Korean. Look for Korean PII formats (주민등록번호/RRN, Korean phone numbers, addresses).",
    "it": "The input text is in Italian. Look for Italian PII formats (Codice Fiscale, IBAN IT, Italian phone numbers, addresses).",
    "pl": "The input text is in Polish. Look for Polish PII formats (PESEL, NIP, IBAN PL, Polish phone numbers, addresses).",
    "pt": "The input text is in Portuguese. Look for Portuguese/Brazilian PII formats (CPF, NIF, IBAN PT, phone numbers, addresses).",
    "hi": "The input text is in Hindi. Look for Indian PII formats (Aadhaar, PAN card, Indian phone numbers, addresses).",
}


class LlmDetector:
    """Detects semantic PII via a local Ollama LLM."""

    def __init__(self, config: ShieldConfig):
        self._model = config.llm_model
        # F2.1 (v0.6.1): SSRF hardening lands in v0.6.2. Until then, warn loudly
        # whenever llm_allow_remote=True is set — the validator currently has
        # known bypass paths (DNS rebinding, integer/octal IPv4, IPv4-mapped
        # IPv6 metadata IPs).
        _allow_remote = getattr(config, 'llm_allow_remote', False)
        if _allow_remote:
            import warnings as _w
            _w.warn(
                "llm_allow_remote=True has known SSRF bypass paths in v0.6.x "
                "(DNS rebinding, integer/octal IPv4, IPv4-mapped IPv6 metadata "
                "addresses). Do NOT use in production until the v0.6.2 SSRF "
                "hardening lands. Tracking: "
                "https://github.com/cloakllm/CloakLLM-PY/issues/ssrf-hardening",
                RuntimeWarning,
                stacklevel=2,
            )
        self._base_url = _validate_ollama_url(
            config.llm_ollama_url.rstrip("/"),
            _allow_remote,
        )
        self._timeout = config.llm_timeout
        self._confidence = config.llm_confidence
        self._locale = getattr(config, 'locale', 'en')
        self._available: bool | None = None  # None = not checked yet
        self._cache = _BoundedCache(maxsize=getattr(config, 'llm_cache_maxsize', 1024))
        # Custom LLM categories
        self._custom_categories: dict[str, str] = {}
        for name, desc in getattr(config, 'custom_llm_categories', []):
            if name in EXCLUDED_CATEGORIES:
                logger.warning("Custom LLM category '%s' conflicts with excluded category — skipped", name)
                continue
            self._custom_categories[name] = desc

    @staticmethod
    def _cache_key(text: str) -> str:
        """Hash text for cache key to avoid storing raw PII."""
        return hashlib.sha256(text.encode("utf-8")).hexdigest()

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
        # Append locale hint if available
        locale_hint = _LOCALE_HINTS.get(self._locale)
        if locale_hint:
            prompt += f"\n{locale_hint}"
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
        cached = self._cache.get(self._cache_key(text))
        if cached is not None:
            entities = cached.entities
        else:
            entities = self._query_ollama(text)
            self._cache.set(self._cache_key(text), _CachedResult(entities=entities))

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
