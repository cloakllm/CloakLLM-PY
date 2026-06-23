"""RFC 3161 trusted timestamping (v0.11.0 TS-2 / TS-4).

Checkpoint-level trusted timestamps over the audit chain's latest entry_hash.
An RFC 3161 Time-Stamp Authority (TSA) binds a hash to a UTC time under its
own certificate, proving "this hash existed no later than T" -- the one
defense KeyManifest cannot provide (an attacker holding both the signing key
AND the root key can otherwise fabricate a backdated history). See
SPIKE_timestamping.md and COMPLIANCE.md.

INVARIANT: the TSA only ever receives a HASH (the chain entry_hash, itself a
hash of a no-PII entry). No content, no PII ever leaves to the TSA. The stored
checkpoint carries a hash, a URL, and an opaque signed token only.

Optional dependency group:  pip install cloakllm[timestamping]
  (asn1crypto for ASN.1 build/parse, cryptography for signature verification)

Verification is fully OFFLINE: a token + the TSA cert chain verify forever
without network access (the air-gapped-auditor guarantee, parity with
KeyManifest / RevocationList).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from dataclasses import dataclass
from typing import Optional

# ASCII-only error strings (the v0.7.0 Windows-console lesson).
_TS_BACKEND_MISSING_MSG = (
    "RFC 3161 timestamping requires the optional backend: "
    "pip install cloakllm[timestamping] (asn1crypto + cryptography)."
)

_SUPPORTED_HASHES = {"sha256", "sha512"}


def _backend():
    """Lazy-import the ASN.1 + crypto backend, raising an actionable error."""
    try:
        from asn1crypto import tsp, cms, algos, core, x509 as _x509  # noqa: F401
        from cryptography.x509 import load_pem_x509_certificate  # noqa: F401
        return True
    except ImportError as e:
        raise ImportError(_TS_BACKEND_MISSING_MSG) from e


def _ts_backend_available() -> bool:
    try:
        import asn1crypto  # noqa: F401
        import cryptography  # noqa: F401
        return True
    except ImportError:
        return False


# --- TS-2: request build / response parse / network ------------------

def build_timestamp_request(
    digest: bytes, hash_algorithm: str = "sha256", nonce: Optional[int] = None
) -> bytes:
    """DER-encode an RFC 3161 TimeStampReq for `digest`. certReq=True so the
    TSA returns its signing certificate inside the token (needed for offline
    verification)."""
    _backend()
    from asn1crypto import tsp, algos
    if hash_algorithm not in _SUPPORTED_HASHES:
        raise ValueError(f"hash_algorithm must be one of {sorted(_SUPPORTED_HASHES)}")
    if nonce is None:
        nonce = secrets.randbits(64)
    req = tsp.TimeStampReq({
        "version": "v1",
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": hash_algorithm}),
            "hashed_message": digest,
        }),
        "nonce": nonce,
        "cert_req": True,
    })
    return req.dump()


def parse_timestamp_response(der: bytes) -> bytes:
    """Parse a TimeStampResp; raise unless status is granted/grantedWithMods.
    Returns the TimeStampToken (a CMS ContentInfo) DER bytes."""
    _backend()
    from asn1crypto import tsp
    resp = tsp.TimeStampResp.load(der)
    status = resp["status"]["status"].native
    if status not in ("granted", "granted_with_mods"):
        raise ValueError(f"TSA did not grant the timestamp (status={status!r}).")
    token = resp["time_stamp_token"]
    if token is None or token.native is None:
        raise ValueError("TSA response granted but carried no time_stamp_token.")
    return token.dump()


def request_timestamp(
    tsa_url: str,
    digest: bytes,
    hash_algorithm: str = "sha256",
    timeout: float = 10.0,
) -> str:
    """POST a TimeStampReq to `tsa_url` and return the TimeStampToken as base64.

    SSRF-hardened (reuses the llm_detector defenses): https-only, cloud-metadata
    / private-range denial at resolve time, no redirects. The TSA URL is
    deployer-configured (lower risk than user input) but still validated.
    """
    _backend()
    import urllib.request
    from cloakllm.llm_detector import (
        _check_ip_allowed, _normalize_ip, _NoRedirectHandler,
    )
    import ipaddress
    import socket
    from urllib.parse import urlparse

    if not isinstance(tsa_url, str) or not tsa_url.startswith("https://"):
        raise ValueError("tsa_url must be an https:// URL.")
    parsed = urlparse(tsa_url)
    host = parsed.hostname
    if not host:
        raise ValueError("tsa_url has no host.")
    # Resolve + SSRF-check every address. allow_remote=True (TSAs are remote):
    # the ALWAYS_DENY networks (cloud metadata, loopback, multicast, etc.) are
    # blocked, which closes the metadata-exfil SSRF. Private ranges (10/8,
    # 192.168/16) and loopback are NOT blocked -- a deployer may legitimately
    # run an internal TSA (same posture as the Ollama detector). Pin the first
    # validated address would add rebind resistance; we validate all resolved
    # addresses here.
    addrs = socket.getaddrinfo(host, parsed.port or 443, proto=socket.IPPROTO_TCP)
    for fam, _, _, _, sockaddr in addrs:
        ip = sockaddr[0]
        if not _check_ip_allowed(ip, allow_remote=True):
            raise ValueError(
                f"tsa_url host {host} resolves to a disallowed address ({ip})."
            )

    req_der = build_timestamp_request(digest, hash_algorithm)
    http_req = urllib.request.Request(
        tsa_url, data=req_der,
        headers={"Content-Type": "application/timestamp-query"},
        method="POST",
    )
    opener = urllib.request.build_opener(_NoRedirectHandler())
    with opener.open(http_req, timeout=timeout) as resp:
        body = resp.read()
    token_der = parse_timestamp_response(body)
    return base64.b64encode(token_der).decode("ascii")


# --- TS-4: offline verification --------------------------------------

@dataclass
class TimestampVerifyResult:
    valid: bool                       # all required checks passed
    gen_time: Optional[str]           # ISO 8601 UTC, the TSA's asserted time
    message_imprint_matches: bool     # token hash == expected entry_hash
    signature_valid: bool             # CMS signature over the token verifies
    chain_valid: Optional[bool]       # signer cert chains to a trusted anchor
                                      #   (None when no trust anchors supplied)
    reason: str                       # human-readable summary (ASCII)


def verify_timestamp_token(
    tst_token_b64: str,
    expected_digest: bytes,
    trusted_certs_pem: Optional[list[str]] = None,
) -> TimestampVerifyResult:
    """Verify an RFC 3161 TimeStampToken offline.

    Checks (in order): parse; messageImprint == expected_digest; the
    messageDigest signed-attribute == hash(TSTInfo); the CMS signature over the
    signed attributes verifies under the signer certificate's public key; and
    (when `trusted_certs_pem` is supplied) the signer cert chains to one of
    those trust anchors. genTime is extracted regardless.

    `valid` is True iff messageImprint + signature pass AND, when anchors are
    supplied, the chain verifies. Supplying no anchors yields chain_valid=None
    and `valid` reflects only messageImprint + signature (the deployer chose
    not to pin a TSA root).
    """
    _backend()
    from asn1crypto import cms as _cms, tsp as _tsp
    from cryptography import x509 as cx509
    from cryptography.hazmat.primitives import hashes as _hashes
    from cryptography.hazmat.primitives.asymmetric import padding as _padding, ec as _ec
    from cryptography.x509 import load_pem_x509_certificate

    def _fail(reason: str, gen_time=None, mi=False, sig=False, chain=None):
        return TimestampVerifyResult(False, gen_time, mi, sig, chain, reason)

    try:
        token_der = base64.b64decode(tst_token_b64, validate=True)
    except Exception:
        return _fail("token is not valid base64")

    try:
        ci = _cms.ContentInfo.load(token_der)
        if ci["content_type"].native != "signed_data":
            return _fail("token is not a CMS SignedData")
        sd = ci["content"]
        eci = sd["encap_content_info"]
        # eContent is a ParsableOctetString wrapping the TSTInfo DER. The raw
        # octet bytes (TSTInfo DER) are what the signature's messageDigest
        # attribute covers -- NOT the octet-string tag/length.
        _content = eci["content"]
        try:
            tst_info = _content.parsed
            tst_info_bytes = tst_info.dump()
        except Exception:
            _raw = _content.native
            tst_info = _tsp.TSTInfo.load(_raw)
            tst_info_bytes = _raw
    except Exception as e:
        return _fail(f"malformed token: {type(e).__name__}")

    # genTime
    gen_dt = None
    try:
        gt = tst_info["gen_time"].native
        gen_time = None
        if gt is not None:
            from datetime import timezone as _tz
            gen_dt = gt.astimezone(_tz.utc)
            gen_time = gen_dt.isoformat()
    except Exception:
        gen_time = None

    # messageImprint == expected digest
    try:
        token_digest = tst_info["message_imprint"]["hashed_message"].native
    except Exception:
        return _fail("token has no message imprint", gen_time)
    import hmac as _hmac
    mi_ok = _hmac.compare_digest(token_digest, expected_digest)
    if not mi_ok:
        return _fail("message imprint does not match the stamped entry hash", gen_time)

    # --- CMS signature over the signed attributes ---
    try:
        signer_info = sd["signer_infos"][0]
        digest_algo = signer_info["digest_algorithm"]["algorithm"].native
        signed_attrs = signer_info["signed_attrs"]
        if signed_attrs is None or len(signed_attrs) == 0:
            return _fail("token has no signed attributes", gen_time, mi=True)

        # messageDigest attr must equal hash(eContent) under digest_algo.
        algo_map = {"sha256": hashlib.sha256, "sha512": hashlib.sha512,
                    "sha1": hashlib.sha1}
        hfn = algo_map.get(digest_algo)
        if hfn is None:
            return _fail(f"unsupported digest algorithm {digest_algo}", gen_time, mi=True)
        econtent_hash = hfn(tst_info_bytes).digest()
        md_attr = None
        for attr in signed_attrs:
            if attr["type"].native == "message_digest":
                md_attr = attr["values"][0].native
                break
        if md_attr is None or not _hmac.compare_digest(md_attr, econtent_hash):
            return _fail("messageDigest attribute does not match eContent", gen_time, mi=True)

        # Locate the signer certificate.
        signer_cert_der = None
        sid = signer_info["sid"]
        certs = sd["certificates"]
        for c in certs:
            cert = c.chosen  # x509.Certificate
            if sid.name == "issuer_and_serial_number":
                if (cert.issuer == sid.chosen["issuer"] and
                        cert.serial_number == sid.chosen["serial_number"].native):
                    signer_cert_der = cert.dump()
                    break
            else:  # subject_key_identifier
                try:
                    if cert.key_identifier == sid.chosen.native:
                        signer_cert_der = cert.dump()
                        break
                except Exception:
                    continue
        if signer_cert_der is None:
            return _fail("signer certificate not found in token", gen_time, mi=True)

        signer_cert = cx509.load_der_x509_certificate(signer_cert_der)
        pub = signer_cert.public_key()

        # The signature is over the DER of the signed attributes re-encoded
        # with the universal SET tag (RFC 5652 5.4).
        signed_attrs_der = signed_attrs.untag().dump()
        signature = signer_info["signature"].native

        hash_cls = {"sha256": _hashes.SHA256, "sha512": _hashes.SHA512,
                    "sha1": _hashes.SHA1}[digest_algo]
        try:
            if isinstance(pub, _ec.EllipticCurvePublicKey):
                pub.verify(signature, signed_attrs_der, _ec.ECDSA(hash_cls()))
            else:  # RSA
                pub.verify(signature, signed_attrs_der, _padding.PKCS1v15(), hash_cls())
            sig_ok = True
        except Exception:
            sig_ok = False
        if not sig_ok:
            return _fail("CMS signature verification failed", gen_time, mi=True)

        # --- v0.11.1: ESS signing-certificate attribute (RFC 3161 sec 2.4.1 /
        # RFC 5035 / RFC 5816). A conforming TSA MUST bind its signing cert into
        # signerInfo via SigningCertificateV2 (legacy: SigningCertificate); it
        # closes a cert-substitution surface and OpenSSL enforces it. Require +
        # verify so we accept exactly what a conforming verifier accepts.
        # asn1crypto ships no ESS specs, so define minimal ones + match by OID. ---
        from asn1crypto import core as _core, algos as _algos
        _ESS_V2_OID = "1.2.840.113549.1.9.16.2.47"   # id-aa-signingCertificateV2
        _ESS_V1_OID = "1.2.840.113549.1.9.16.2.12"   # id-aa-signingCertificate

        class _ESSCertIDv2(_core.Sequence):
            _fields = [
                ("hash_algorithm", _algos.DigestAlgorithm, {"optional": True}),
                ("cert_hash", _core.OctetString),
                ("issuer_serial", _core.Any, {"optional": True}),
            ]

        class _ESSCertIDv2s(_core.SequenceOf):
            _child_spec = _ESSCertIDv2

        class _SigningCertificateV2(_core.Sequence):
            _fields = [("certs", _ESSCertIDv2s),
                       ("policies", _core.Any, {"optional": True})]

        class _ESSCertID(_core.Sequence):
            _fields = [("cert_hash", _core.OctetString),
                       ("issuer_serial", _core.Any, {"optional": True})]

        class _ESSCertIDs(_core.SequenceOf):
            _child_spec = _ESSCertID

        class _SigningCertificate(_core.Sequence):
            _fields = [("certs", _ESSCertIDs),
                       ("policies", _core.Any, {"optional": True})]

        ess_raw = None
        ess_v2 = False
        for attr in signed_attrs:
            dotted = attr["type"].dotted
            if dotted == _ESS_V2_OID:
                ess_raw, ess_v2 = attr["values"][0], True
                break
            if dotted == _ESS_V1_OID:
                ess_raw, ess_v2 = attr["values"][0], False
                break
        if ess_raw is None:
            return _fail("token lacks the ESS signing-certificate attribute "
                         "(RFC 3161 sec 2.4.1)", gen_time, mi=True, sig=True)
        try:
            spec = _SigningCertificateV2 if ess_v2 else _SigningCertificate
            sc = spec.load(ess_raw.dump())
            cert_id = sc["certs"][0]
            ess_hash = cert_id["cert_hash"].native
            if ess_v2:
                ha = cert_id["hash_algorithm"]
                algo_name = ("sha256" if isinstance(ha, _core.Void)
                             else ha["algorithm"].native)
                efn = algo_map.get(algo_name)
            else:
                efn = hashlib.sha1  # ESSCertID (v1) is always SHA-1
            if efn is None:
                return _fail("ESS uses an unsupported hash algorithm",
                             gen_time, mi=True, sig=True)
            if not _hmac.compare_digest(efn(signer_cert_der).digest(), ess_hash):
                return _fail("ESS signing-certificate hash does not match the "
                             "signer cert", gen_time, mi=True, sig=True)
        except (KeyError, IndexError, TypeError, ValueError):
            return _fail("malformed ESS signing-certificate attribute",
                         gen_time, mi=True, sig=True)
    except Exception as e:
        return _fail(f"signature check error: {type(e).__name__}", gen_time, mi=True)

    # --- v0.11.0 MEDIUM-2: intrinsic signer-cert checks (independent of any
    # anchor): the cert must be VALID at genTime and carry the id-kp-
    # timeStamping EKU (RFC 3161 sec 2.3). Without these an expired cert, or a
    # TLS cert from the same CA, would otherwise pass as a TSA. ---
    def _cert_valid_at(cert, when) -> bool:
        if when is None:
            return True  # no genTime to compare against; don't over-reject
        nb = getattr(cert, "not_valid_before_utc", None) or cert.not_valid_before
        na = getattr(cert, "not_valid_after_utc", None) or cert.not_valid_after
        # make naive datetimes tz-aware (UTC) for comparison
        from datetime import timezone as _tz
        if nb.tzinfo is None:
            nb = nb.replace(tzinfo=_tz.utc)
        if na.tzinfo is None:
            na = na.replace(tzinfo=_tz.utc)
        return nb <= when <= na

    try:
        eku = signer_cert.extensions.get_extension_for_class(cx509.ExtendedKeyUsage).value
        if cx509.oid.ExtendedKeyUsageOID.TIME_STAMPING not in eku:
            return _fail("signer cert lacks the id-kp-timeStamping EKU", gen_time, mi=True, sig=True)
    except cx509.ExtensionNotFound:
        return _fail("signer cert has no ExtendedKeyUsage (id-kp-timeStamping required)",
                     gen_time, mi=True, sig=True)
    if not _cert_valid_at(signer_cert, gen_dt):
        return _fail("signer cert is not valid at genTime", gen_time, mi=True, sig=True)

    # --- chain to a trusted anchor (MEDIUM-3: allow ONE intermediate from the
    # token's own certificates, so signer <- intermediate <- anchor works). ---
    chain_valid: Optional[bool] = None
    if trusted_certs_pem:
        # collect candidate issuers: the supplied anchors + the token's certs
        # (the latter as possible intermediates).
        anchors = []
        for pem in trusted_certs_pem:
            try:
                anchors.append(load_pem_x509_certificate(
                    pem.encode() if isinstance(pem, str) else pem))
            except Exception:
                continue
        token_certs = []
        for c in certs:
            try:
                token_certs.append(cx509.load_der_x509_certificate(c.chosen.dump()))
            except Exception:
                continue

        def _signed_by(child, issuer) -> bool:
            try:
                ipub = issuer.public_key()
                hc = child.signature_hash_algorithm
                if isinstance(ipub, _ec.EllipticCurvePublicKey):
                    ipub.verify(child.signature, child.tbs_certificate_bytes, _ec.ECDSA(hc))
                else:
                    ipub.verify(child.signature, child.tbs_certificate_bytes,
                                _padding.PKCS1v15(), hc)
                return True
            except Exception:
                return False

        chain_valid = False
        # direct: signer <- anchor
        if any(_signed_by(signer_cert, a) for a in anchors):
            chain_valid = True
        else:
            # one intermediate (valid at genTime) from the token: signer <- int <- anchor
            for inter in token_certs:
                if inter.fingerprint(__import__("cryptography.hazmat.primitives.hashes",
                                                fromlist=["SHA256"]).SHA256()) == \
                   signer_cert.fingerprint(__import__("cryptography.hazmat.primitives.hashes",
                                                      fromlist=["SHA256"]).SHA256()):
                    continue
                if (_signed_by(signer_cert, inter) and _cert_valid_at(inter, gen_dt)
                        and any(_signed_by(inter, a) for a in anchors)):
                    chain_valid = True
                    break
        if not chain_valid:
            return _fail("signer cert does not chain to a trusted anchor",
                         gen_time, mi=True, sig=True, chain=False)

    return TimestampVerifyResult(
        valid=True, gen_time=gen_time, message_imprint_matches=True,
        signature_valid=True, chain_valid=chain_valid,
        reason="ok",
    )
