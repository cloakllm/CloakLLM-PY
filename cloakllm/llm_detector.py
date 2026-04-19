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


# v0.6.3 H2: SSRF hardening.
# Private IP ranges that ARE permitted for Ollama (when allow_remote=False, only
# these are accepted; when allow_remote=True, these are accepted automatically
# without the warning).
_PRIVATE_NETWORKS = [
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fc00::/7"),
    ipaddress.ip_network("fe80::/10"),  # IPv6 link-local (legitimate same-link Ollama)
]

# v0.6.3 H2: Networks that MUST be denied even when allow_remote=True.
# These cover cloud metadata services and other addresses that are never
# legitimate Ollama hosts and would constitute SSRF if reached.
_ALWAYS_DENY_NETWORKS = [
    ipaddress.ip_network("169.254.0.0/16"),    # IPv4 link-local + AWS/GCP/Azure IMDS
    ipaddress.ip_network("100.64.0.0/10"),     # Carrier-grade NAT (covers Alibaba 100.100.100.200)
    ipaddress.ip_network("192.0.0.0/24"),      # IETF protocol assignments — covers Oracle Cloud IMDS at 192.0.0.192
    ipaddress.ip_network("0.0.0.0/8"),         # "this network" — 0.0.0.0 aliases to localhost on Linux
    ipaddress.ip_network("224.0.0.0/4"),       # IPv4 multicast
    ipaddress.ip_network("240.0.0.0/4"),       # IPv4 reserved (future use)
    ipaddress.ip_network("::/128"),            # IPv6 unspecified
    ipaddress.ip_network("ff00::/8"),          # IPv6 multicast
    # AWS uses fd00:ec2::254 for IPv6 IMDS, which lives inside fc00::/7 ULA
    # (which IS in PRIVATE_NETWORKS for legitimate same-network Ollama). Add
    # the AWS IPv6 IMDS subnet to deny so the deny check (which runs first)
    # blocks it before the private-allow check passes it through.
    ipaddress.ip_network("fd00:ec2::/64"),     # AWS IPv6 IMDS
    # Note: fe80::/10 (IPv6 link-local) is NOT in deny because legitimate
    # same-link Ollama uses it; GCP uses it only for neighbour-discovery,
    # Azure uses it for the VM's own NIC, no IMDS lives there.
]


# v0.6.3 SEC-1: HTTP redirect SSRF bypass.
#
# urllib.request.urlopen() installs an HTTPRedirectHandler by default — a
# malicious Ollama server at a permitted IP can respond with
#     HTTP/1.1 301 Moved Permanently
#     Location: http://169.254.169.254/latest/meta-data/iam/...
# and urllib will follow the redirect WITHOUT passing the new URL through
# our `_validate_ollama_url` / `_revalidate_url` chain. The H2 IP blocklist
# (cloud metadata, multicast, etc.) is silently bypassed for any Ollama
# server that returns a redirect.
#
# Defense: build an opener with a custom HTTPRedirectHandler that REFUSES
# all redirects. The Ollama API never legitimately returns 3xx for /api/tags
# or /api/chat — any redirect is either misconfiguration or an attack.
class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """v0.6.3 SEC-1: refuse all 3xx redirects to prevent SSRF bypass.

    A malicious Ollama at a permitted IP could redirect us to cloud
    metadata or any internal service. Turning redirects off forces the
    request to terminate at the validated IP/host.
    """

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise urllib.error.URLError(
            f"CloakLLM: Ollama server returned a {code} redirect to "
            f"{newurl!r}. Refusing for SSRF protection — the H2 IP blocklist "
            f"is bypassable if redirects are followed. If your Ollama "
            f"deployment legitimately needs redirects, configure it to serve "
            f"the final URL directly."
        )


# Module-level opener: built once, reused for all Ollama HTTP calls in this
# process. Including the standard handlers ensures cookies/auth/etc still
# work normally — only redirects are refused.
_NO_REDIRECT_OPENER = urllib.request.build_opener(_NoRedirectHandler())


def _normalize_ip(ip: ipaddress._BaseAddress) -> ipaddress._BaseAddress:
    """v0.6.3 H2: Unwrap IPv4-mapped IPv6 (`::ffff:x.y.z.w`) to its IPv4 form
    so range checks against IPv4 deny lists still apply.

    Without this, an attacker could bypass an IPv4 deny by writing the same
    address as `::ffff:169.254.169.254`.
    """
    if isinstance(ip, ipaddress.IPv6Address):
        v4 = ip.ipv4_mapped
        if v4 is not None:
            return v4
    return ip


def _check_ip_allowed(ip_str: str, allow_remote: bool) -> bool:
    """v0.6.3 H2: Single source of truth for whether a resolved IP is reachable.

    Order of checks matters:
    1. ALWAYS_DENY wins regardless of allow_remote (cloud metadata, multicast,
       unspecified). This is the protection that survives `allow_remote=True`.
    2. PRIVATE networks are always allowed (loopback, RFC1918, IPv6 ULA/link-local).
    3. Anything else requires `allow_remote=True`.
    """
    try:
        ip = ipaddress.ip_address(ip_str)
    except ValueError:
        return False
    ip = _normalize_ip(ip)
    if any(ip in net for net in _ALWAYS_DENY_NETWORKS):
        return False
    if any(ip in net for net in _PRIVATE_NETWORKS):
        return True
    return bool(allow_remote)


def _validate_ollama_url(url: str, allow_remote: bool) -> str:
    """v0.6.3 H2: Validate that the Ollama URL is safe to contact.

    No fast-path string bypass: we always resolve the hostname so that
    `localhost` (which an /etc/hosts override could redirect) and
    integer/octal IPv4 forms (`http://2130706433/`) go through the same
    `_check_ip_allowed` filter as any other input.

    All resolved addresses must pass — if a hostname returns both an
    allowed and a denied IP, the request is rejected (the underlying
    HTTP client may pick either, so we fail closed).
    """
    parsed = urllib.parse.urlparse(url)
    hostname = parsed.hostname or ""
    if not hostname:
        raise ValueError(
            f"CloakLLM: Ollama URL '{url}' has no hostname."
        )

    try:
        infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except (socket.gaierror, OSError) as exc:
        if not allow_remote:
            raise ValueError(
                f"CloakLLM: Cannot resolve Ollama hostname '{hostname}' ({exc}). "
                f"Set llm_allow_remote=True only if you accept that re-resolution "
                f"happens at fetch time."
            ) from exc
        # allow_remote=True: defer to fetch-time re-validation. The actual
        # connect will succeed or fail; either way, the deny list is checked
        # again before the request is issued.
        logger.warning(
            "CloakLLM: Cannot resolve Ollama hostname '%s' at validation time "
            "(%s). Will re-check at fetch time.", hostname, exc
        )
        return url

    if not infos:
        raise ValueError(
            f"CloakLLM: Hostname '{hostname}' returned no addresses."
        )

    for _family, _type, _proto, _canonname, sockaddr in infos:
        ip_str = sockaddr[0]
        if not _check_ip_allowed(ip_str, allow_remote):
            raise ValueError(
                f"CloakLLM: Ollama URL '{url}' resolves to '{ip_str}', which "
                f"is denied (cloud metadata service, multicast, or non-private "
                f"address without llm_allow_remote=True). This protects against "
                f"SSRF to cloud metadata endpoints (169.254.169.254 etc.) even "
                f"when remote Ollama is enabled."
            )

    if allow_remote:
        # All resolved IPs are non-deny but at least one is non-private.
        # Warn so operators know PII goes off-host.
        for _f, _t, _p, _c, sockaddr in infos:
            ip = _normalize_ip(ipaddress.ip_address(sockaddr[0]))
            if not any(ip in net for net in _PRIVATE_NETWORKS):
                logger.warning(
                    "CloakLLM: Ollama URL '%s' points to a non-local address "
                    "(%s). PII data will be sent to this remote server.",
                    url, sockaddr[0],
                )
                break

    return url


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
        # v0.6.3 H2: SSRF hardening landed. The bypass paths from v0.6.x
        # (DNS rebinding, integer/octal IPv4, IPv4-mapped IPv6 metadata IPs)
        # are now closed by `_validate_ollama_url` (init-time deny+unwrap),
        # `_revalidate_url` (fetch-time re-resolve), and the always-deny
        # network list (cloud metadata blocked even when allow_remote=True).
        # We still warn on allow_remote=True so the operational risk of
        # sending PII off-host is visible.
        self._allow_remote = bool(getattr(config, 'llm_allow_remote', False))
        if self._allow_remote:
            import warnings as _w
            _w.warn(
                "llm_allow_remote=True: PII data will be transmitted to a "
                "non-local Ollama instance. Cloud metadata addresses "
                "(169.254.169.254 etc.) and other always-deny ranges are still "
                "blocked, but you must trust the remote endpoint with your input "
                "text. Prefer running Ollama locally.",
                RuntimeWarning,
                stacklevel=2,
            )
        self._base_url = _validate_ollama_url(
            config.llm_ollama_url.rstrip("/"),
            self._allow_remote,
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

    def _http_open(self, req, *, timeout):
        """v0.6.3 SEC-1: single seam for all HTTP calls so tests can patch
        one method, and SEC-1's no-redirect handler is enforced
        consistently. Production code MUST call this — never
        urllib.request.urlopen directly — so a malicious Ollama can't
        301-redirect us to cloud metadata."""
        return _NO_REDIRECT_OPENER.open(req, timeout=timeout)

    def _revalidate_url(self) -> None:
        """v0.6.3 H2: Re-resolve the base URL's hostname and apply the same
        deny/private-IP checks as init-time validation.

        Closes the DNS rebinding window: an attacker who pointed
        `ollama.example.com` at a private/allowed IP at init time can't flip
        their authoritative DNS to `169.254.169.254` before the actual fetch.

        On failure, raises `ValueError` — callers (`_check_available`,
        `_query_ollama`) catch and treat as "Ollama unavailable" to keep the
        detector fail-soft (consistent with regex/NER passes still running).
        """
        _validate_ollama_url(self._base_url, self._allow_remote)

    def _check_available(self) -> bool:
        """Ping Ollama. Cache result so we only check once."""
        if self._available is not None:
            return self._available
        try:
            self._revalidate_url()  # v0.6.3 H2: DNS rebinding mitigation
            req = urllib.request.Request(f"{self._base_url}/api/tags", method="GET")
            # v0.6.3 SEC-1: route through _http_open so the no-redirect opener
            # is always used and tests have a single patchable seam.
            self._http_open(req, timeout=3)
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
            self._revalidate_url()  # v0.6.3 H2: DNS rebinding mitigation
            # v0.6.3 SEC-1: route through _http_open (same seam as
            # _check_available — tests patch one method, redirects refused).
            resp = self._http_open(req, timeout=self._timeout)
            body = json.loads(resp.read())
            content = body.get("message", {}).get("content", "{}")
            parsed = json.loads(content)
            entities = parsed.get("entities", [])
            if not isinstance(entities, list):
                return []
            return entities
        except (urllib.error.URLError, json.JSONDecodeError, KeyError, TimeoutError, OSError, ValueError) as exc:
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
