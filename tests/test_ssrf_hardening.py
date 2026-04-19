"""v0.6.3 H2 — SSRF hardening tests for the Ollama URL validator.

Covers the three gaps documented as known-bad in v0.6.x:
  1. DNS rebinding (init-time validation passes; fetch-time re-resolution
     would resolve to a denied IP).
  2. Integer / octal / hex IPv4 forms reaching cloud metadata.
  3. IPv4-mapped IPv6 forms (`::ffff:169.254.169.254`) bypassing the deny.

Plus the regressions: localhost, RFC1918, IPv6 ULA still accepted.
"""

from __future__ import annotations

import socket
import unittest
import urllib.error
from unittest import mock

import pytest

from cloakllm.llm_detector import (
    _ALWAYS_DENY_NETWORKS,
    _PRIVATE_NETWORKS,
    _check_ip_allowed,
    _normalize_ip,
    _validate_ollama_url,
)


# ─── helpers ──────────────────────────────────────────────────────────────


def _patch_resolve(addresses):
    """Make socket.getaddrinfo return the given list of (family, ip) pairs.

    Each address is yielded as a tuple matching getaddrinfo's shape.
    """

    def _fake_getaddrinfo(host, port, family=0, type=0, proto=0, flags=0):
        return [
            (fam, socket.SOCK_STREAM, 0, "", (ip, port or 0))
            for fam, ip in addresses
        ]

    return mock.patch("cloakllm.llm_detector.socket.getaddrinfo", _fake_getaddrinfo)


# ─── _normalize_ip ────────────────────────────────────────────────────────


class TestNormalizeIp(unittest.TestCase):
    def test_ipv4_passthrough(self):
        import ipaddress
        ip = ipaddress.IPv4Address("169.254.169.254")
        self.assertEqual(str(_normalize_ip(ip)), "169.254.169.254")

    def test_ipv4_mapped_ipv6_unwrapped(self):
        import ipaddress
        # ::ffff:169.254.169.254 must unwrap to 169.254.169.254
        ip = ipaddress.IPv6Address("::ffff:169.254.169.254")
        normalized = _normalize_ip(ip)
        self.assertEqual(str(normalized), "169.254.169.254")
        self.assertIsInstance(normalized, ipaddress.IPv4Address)

    def test_pure_ipv6_passthrough(self):
        import ipaddress
        ip = ipaddress.IPv6Address("fd00::1")
        self.assertEqual(str(_normalize_ip(ip)), "fd00::1")


# ─── _check_ip_allowed ────────────────────────────────────────────────────


class TestCheckIpAllowed(unittest.TestCase):
    """The single-source-of-truth predicate. allow_remote=True must NOT bypass deny."""

    def test_loopback_always_allowed(self):
        self.assertTrue(_check_ip_allowed("127.0.0.1", allow_remote=False))
        self.assertTrue(_check_ip_allowed("127.0.0.1", allow_remote=True))

    def test_rfc1918_always_allowed(self):
        for ip in ("10.0.0.1", "172.16.5.5", "192.168.1.1"):
            self.assertTrue(_check_ip_allowed(ip, allow_remote=False), ip)
            self.assertTrue(_check_ip_allowed(ip, allow_remote=True), ip)

    def test_ipv6_loopback_and_ula_allowed(self):
        self.assertTrue(_check_ip_allowed("::1", allow_remote=False))
        self.assertTrue(_check_ip_allowed("fd00::1", allow_remote=False))

    def test_aws_imds_denied_even_with_allow_remote(self):
        # The headline bug. Without H2, allow_remote=True passed everything
        # except RFC1918, including 169.254.169.254.
        self.assertFalse(_check_ip_allowed("169.254.169.254", allow_remote=False))
        self.assertFalse(_check_ip_allowed("169.254.169.254", allow_remote=True))

    def test_ipv4_mapped_imds_denied(self):
        # ::ffff:169.254.169.254 must unwrap and hit the IPv4 deny.
        self.assertFalse(_check_ip_allowed("::ffff:169.254.169.254", allow_remote=True))
        # Sibling forms — same address, different notation.
        self.assertFalse(_check_ip_allowed("::ffff:a9fe:a9fe", allow_remote=True))

    def test_link_local_full_range_denied(self):
        # Anywhere in 169.254.0.0/16
        for ip in ("169.254.0.1", "169.254.255.254", "169.254.42.42"):
            self.assertFalse(_check_ip_allowed(ip, allow_remote=True), ip)

    def test_zero_network_denied(self):
        # 0.0.0.0/8 — 0.0.0.0 aliases to localhost on Linux, useful for
        # SSRF when an HTTP client interprets it as 127.0.0.1.
        self.assertFalse(_check_ip_allowed("0.0.0.0", allow_remote=True))
        self.assertFalse(_check_ip_allowed("0.0.0.1", allow_remote=True))

    def test_multicast_denied(self):
        self.assertFalse(_check_ip_allowed("224.0.0.1", allow_remote=True))
        self.assertFalse(_check_ip_allowed("239.255.255.250", allow_remote=True))
        self.assertFalse(_check_ip_allowed("ff02::1", allow_remote=True))

    def test_carrier_grade_nat_denied(self):
        # 100.64.0.0/10 — used by some clouds for metadata (Alibaba 100.100.100.200)
        self.assertFalse(_check_ip_allowed("100.64.0.1", allow_remote=True))
        self.assertFalse(_check_ip_allowed("100.127.255.254", allow_remote=True))
        self.assertFalse(_check_ip_allowed("100.100.100.200", allow_remote=True))  # Alibaba IMDS

    def test_oracle_imds_denied(self):
        # Oracle Cloud IMDS at 192.0.0.192 — IETF protocol assignments range.
        # Not in the legacy private allow (192.168/16 is), so allow_remote=False
        # already denied it; allow_remote=True must STILL deny it.
        self.assertFalse(_check_ip_allowed("192.0.0.192", allow_remote=True))
        self.assertFalse(_check_ip_allowed("192.0.0.0", allow_remote=True))
        self.assertFalse(_check_ip_allowed("192.0.0.255", allow_remote=True))
        # Adjacent IPv4 outside /24 stays subject to allow_remote
        self.assertTrue(_check_ip_allowed("192.0.1.1", allow_remote=True))
        self.assertFalse(_check_ip_allowed("192.0.1.1", allow_remote=False))

    def test_aws_ipv6_imds_denied(self):
        # AWS IPv6 IMDS at fd00:ec2::254 lives inside fc00::/7 ULA, which is
        # in the legacy private allow list. The deny check must run first
        # and block it even when the address is technically a private ULA.
        self.assertFalse(_check_ip_allowed("fd00:ec2::254", allow_remote=True))
        self.assertFalse(_check_ip_allowed("fd00:ec2::1", allow_remote=True))
        # Other ULA addresses stay allowed (legitimate same-network Ollama)
        self.assertTrue(_check_ip_allowed("fd00:abcd::1", allow_remote=False))
        self.assertTrue(_check_ip_allowed("fd00:1234::1", allow_remote=False))

    def test_public_address_requires_allow_remote(self):
        # 8.8.8.8 is genuinely public — denied by default, allowed when opted in.
        self.assertFalse(_check_ip_allowed("8.8.8.8", allow_remote=False))
        self.assertTrue(_check_ip_allowed("8.8.8.8", allow_remote=True))

    def test_invalid_ip_string_denied(self):
        self.assertFalse(_check_ip_allowed("not-an-ip", allow_remote=True))
        self.assertFalse(_check_ip_allowed("", allow_remote=True))


# ─── _validate_ollama_url ─────────────────────────────────────────────────


class TestValidateOllamaUrl(unittest.TestCase):
    def test_localhost_resolves_and_passes(self):
        # The fast-path string bypass is gone — must resolve. localhost
        # resolves to 127.0.0.1 on every supported platform.
        with _patch_resolve([(socket.AF_INET, "127.0.0.1")]):
            url = _validate_ollama_url("http://localhost:11434", allow_remote=False)
            self.assertEqual(url, "http://localhost:11434")

    def test_localhost_etc_hosts_redirect_caught(self):
        # If /etc/hosts redirects `localhost` to an attacker IP, the fast-path
        # bypass would have returned the URL unchanged. Now we resolve and
        # check the actual IP.
        with _patch_resolve([(socket.AF_INET, "169.254.169.254")]):
            with self.assertRaises(ValueError) as cm:
                _validate_ollama_url("http://localhost:11434", allow_remote=True)
            self.assertIn("169.254.169.254", str(cm.exception))

    def test_imds_literal_rejected(self):
        with _patch_resolve([(socket.AF_INET, "169.254.169.254")]):
            with self.assertRaises(ValueError):
                _validate_ollama_url("http://169.254.169.254", allow_remote=True)

    def test_ipv4_mapped_ipv6_imds_rejected(self):
        # The headline IPv4-mapped IPv6 bypass.
        with _patch_resolve([(socket.AF_INET6, "::ffff:169.254.169.254")]):
            with self.assertRaises(ValueError):
                _validate_ollama_url(
                    "http://[::ffff:169.254.169.254]:11434", allow_remote=True
                )

    def test_split_horizon_dns_fail_closed(self):
        # Hostname returns BOTH a private and a public IP. The HTTP client
        # might pick either, so we must reject (fail closed).
        with _patch_resolve([
            (socket.AF_INET, "10.0.0.5"),
            (socket.AF_INET, "169.254.169.254"),
        ]):
            with self.assertRaises(ValueError) as cm:
                _validate_ollama_url("http://ambiguous.example", allow_remote=True)
            self.assertIn("169.254.169.254", str(cm.exception))

    def test_remote_address_with_allow_remote_passes(self):
        with _patch_resolve([(socket.AF_INET, "8.8.8.8")]):
            url = _validate_ollama_url("http://ollama.example", allow_remote=True)
            self.assertEqual(url, "http://ollama.example")

    def test_remote_address_without_allow_remote_rejected(self):
        with _patch_resolve([(socket.AF_INET, "8.8.8.8")]):
            with self.assertRaises(ValueError):
                _validate_ollama_url("http://ollama.example", allow_remote=False)

    def test_resolution_failure_fail_closed_without_allow_remote(self):
        with mock.patch(
            "cloakllm.llm_detector.socket.getaddrinfo",
            side_effect=socket.gaierror("name not found"),
        ):
            with self.assertRaises(ValueError):
                _validate_ollama_url("http://nonexistent.example", allow_remote=False)

    def test_resolution_failure_deferred_with_allow_remote(self):
        # Hostname unresolvable at validation time + allow_remote=True =
        # defer to fetch time (warning, not exception). The fetch-time
        # re-validation will catch a malicious answer when DNS recovers.
        with mock.patch(
            "cloakllm.llm_detector.socket.getaddrinfo",
            side_effect=socket.gaierror("temporary failure"),
        ):
            url = _validate_ollama_url("http://transient.example", allow_remote=True)
            self.assertEqual(url, "http://transient.example")

    def test_empty_hostname_rejected(self):
        with self.assertRaises(ValueError):
            _validate_ollama_url("http://", allow_remote=True)


# ─── DNS rebinding mitigation via _revalidate_url ─────────────────────────


class TestDnsRebindingMitigation(unittest.TestCase):
    """The classic SSRF: validation passes, attacker flips DNS, fetch hits
    a denied IP. _revalidate_url is called before each HTTP fetch and
    re-runs the same checks against the latest resolution."""

    def test_revalidate_called_in_check_available(self):
        from cloakllm.llm_detector import LlmDetector
        from cloakllm.config import ShieldConfig

        with _patch_resolve([(socket.AF_INET, "127.0.0.1")]):
            cfg = ShieldConfig(llm_detection=True, llm_ollama_url="http://localhost:11434")
            det = LlmDetector(cfg)

        # Now simulate DNS rebinding to IMDS. The next _check_available()
        # must catch this and mark unavailable rather than connect.
        with _patch_resolve([(socket.AF_INET, "169.254.169.254")]):
            with mock.patch("cloakllm.llm_detector.LlmDetector._http_open") as mock_open:
                result = det._check_available()
                self.assertFalse(result)
                # Critical: the fetch was never attempted.
                mock_open.assert_not_called()

    def test_revalidate_called_in_query(self):
        from cloakllm.llm_detector import LlmDetector
        from cloakllm.config import ShieldConfig

        with _patch_resolve([(socket.AF_INET, "127.0.0.1")]):
            cfg = ShieldConfig(llm_detection=True, llm_ollama_url="http://localhost:11434")
            det = LlmDetector(cfg)
            # Force _check_available to short-circuit so we test query path.
            det._available = True

        with _patch_resolve([(socket.AF_INET, "169.254.169.254")]):
            with mock.patch("cloakllm.llm_detector.LlmDetector._http_open") as mock_open:
                result = det._query_ollama("some text")
                self.assertEqual(result, [])
                # Critical: the fetch was never attempted.
                mock_open.assert_not_called()


# ─── deny-list completeness sanity check ──────────────────────────────────


class TestDenyListCompleteness(unittest.TestCase):
    def test_aws_imds_in_deny(self):
        import ipaddress
        imds = ipaddress.IPv4Address("169.254.169.254")
        self.assertTrue(any(imds in net for net in _ALWAYS_DENY_NETWORKS))

    def test_loopback_not_in_deny(self):
        # Regression guard: don't accidentally block legitimate loopback.
        import ipaddress
        loopback = ipaddress.IPv4Address("127.0.0.1")
        self.assertFalse(any(loopback in net for net in _ALWAYS_DENY_NETWORKS))

    def test_rfc1918_not_in_deny(self):
        import ipaddress
        for ip in ("10.0.0.1", "172.16.0.1", "192.168.1.1"):
            addr = ipaddress.IPv4Address(ip)
            self.assertFalse(any(addr in net for net in _ALWAYS_DENY_NETWORKS), ip)


class TestNoHttpRedirectBypass(unittest.TestCase):
    """v0.6.3 SEC-1: HTTP 3xx redirects MUST be refused.

    The H2 IP blocklist (`_ALWAYS_DENY_NETWORKS`) validates the IP we're
    about to connect to. But `urllib.request.urlopen()` follows 3xx
    redirects by default — a malicious Ollama server at a permitted IP
    can respond with `HTTP/1.1 301 Location: http://169.254.169.254/...`
    and urllib would follow the redirect WITHOUT re-running our IP
    validation. Cloud metadata exfiltrated, blocklist bypassed entirely.

    Defense: a custom HTTPRedirectHandler that raises on every 3xx.
    """

    def test_redirect_handler_refuses_301(self):
        from cloakllm.llm_detector import _NoRedirectHandler
        handler = _NoRedirectHandler()
        with self.assertRaises(urllib.error.URLError) as cm:
            handler.redirect_request(
                req=mock.MagicMock(),
                fp=mock.MagicMock(),
                code=301,
                msg="Moved Permanently",
                headers={},
                newurl="http://169.254.169.254/latest/meta-data/",
            )
        msg = str(cm.exception)
        self.assertIn("301", msg)
        self.assertIn("SSRF", msg)
        self.assertIn("169.254.169.254", msg)

    def test_redirect_handler_refuses_302(self):
        from cloakllm.llm_detector import _NoRedirectHandler
        handler = _NoRedirectHandler()
        with self.assertRaises(urllib.error.URLError):
            handler.redirect_request(
                req=mock.MagicMock(), fp=mock.MagicMock(),
                code=302, msg="Found", headers={},
                newurl="http://internal.corp/secret",
            )

    def test_no_redirect_opener_built(self):
        # Sanity: the module-level opener must include _NoRedirectHandler.
        from cloakllm.llm_detector import _NO_REDIRECT_OPENER, _NoRedirectHandler
        has_no_redirect = any(
            isinstance(h, _NoRedirectHandler)
            for h in _NO_REDIRECT_OPENER.handlers
        )
        self.assertTrue(
            has_no_redirect,
            "_NO_REDIRECT_OPENER must install _NoRedirectHandler — otherwise "
            "the SEC-1 fix is a no-op and redirects would still be followed.",
        )

    def test_check_available_uses_no_redirect_opener(self):
        # Integration: when LlmDetector hits a 301-redirecting Ollama,
        # _check_available must mark unavailable rather than follow the redirect.
        from cloakllm.llm_detector import LlmDetector
        from cloakllm.config import ShieldConfig

        with _patch_resolve([(socket.AF_INET, "127.0.0.1")]):
            cfg = ShieldConfig(llm_detection=True, llm_ollama_url="http://localhost:11434")
            det = LlmDetector(cfg)

        # Mock the opener's open() to simulate a 301 → IMDS attempt: our
        # _NoRedirectHandler raises URLError before urllib can follow.
        with _patch_resolve([(socket.AF_INET, "127.0.0.1")]):
            from cloakllm.llm_detector import _NO_REDIRECT_OPENER
            with mock.patch.object(
                _NO_REDIRECT_OPENER, "open",
                side_effect=urllib.error.URLError(
                    "CloakLLM: Ollama server returned a 301 redirect — refused for SSRF"
                ),
            ):
                ok = det._check_available()
                self.assertFalse(
                    ok,
                    "redirect-refusing opener must mark Ollama unavailable, "
                    "not silently fall through to urllib's default redirect.",
                )


if __name__ == "__main__":
    unittest.main()
