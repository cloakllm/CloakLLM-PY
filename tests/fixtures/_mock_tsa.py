"""Mock RFC 3161 TSA + committed-fixture generator.

Mints real, valid TimeStampTokens for offline tests, AND regenerates the
committed corpus `tests/fixtures/timestamp_token.json` (copied to the JS side)
used by the verifier tests and the OpenSSL-differential suite.

Run `python tests/fixtures/_mock_tsa.py generate` from the cloakllm-py root to
rewrite both fixture copies. The corpus deliberately covers one defect per
token so a differential against `openssl ts -verify` pins each rejection
reason. A real freetsa.org token is minted too (needs network at generate
time only; tests read the committed bytes offline).

v0.11.1: every mock token now carries the ESS SigningCertificateV2 attribute
(RFC 3161 sec 2.4.1 / RFC 5035) that a conforming TSA MUST include, plus
explicit no-ESS / wrong-ESS negatives.
"""
import base64
import datetime as _dt
import hashlib
import json
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

from asn1crypto import algos, cms, core, tsp, x509 as a_x509
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.x509.oid import NameOID

GEN_TIME = datetime(2026, 7, 1, 10, 0, 0, tzinfo=timezone.utc)
_ESS_V2_OID = "1.2.840.113549.1.9.16.2.47"


def _mkcert(subject_cn, issuer_cn, issuer_key, subject_key, ca=False, eku_tsa=False,
            not_before=_dt.datetime(2020, 1, 1), not_after=_dt.datetime(2035, 1, 1)):
    b = cx509.CertificateBuilder()
    b = b.subject_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
    b = b.issuer_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
    b = b.public_key(subject_key.public_key())
    b = b.serial_number(cx509.random_serial_number())
    b = b.not_valid_before(not_before).not_valid_after(not_after)
    if ca:
        b = b.add_extension(cx509.BasicConstraints(ca=True, path_length=None), critical=True)
    if eku_tsa:
        b = b.add_extension(
            cx509.ExtendedKeyUsage([cx509.ObjectIdentifier("1.3.6.1.5.5.7.3.8")]),
            critical=True)
    return b.sign(issuer_key, hashes.SHA256())


def make_tsa():
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = _mkcert("Test TSA Root CA", "Test TSA Root CA", ca_key, ca_key, ca=True)
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tsa_cert = _mkcert("Test TSA", "Test TSA Root CA", ca_key, tsa_key, eku_tsa=True)
    return ca_key, ca_cert, tsa_key, tsa_cert


# --- ESS SigningCertificateV2 (asn1crypto ships no ESS spec) ---
class _ESSCertIDv2(core.Sequence):
    _fields = [("hashAlgorithm", algos.DigestAlgorithm, {"optional": True}),
               ("certHash", core.OctetString),
               ("issuerSerial", core.Any, {"optional": True})]


class _ESSCertIDv2s(core.SequenceOf):
    _child_spec = _ESSCertIDv2


class _SigningCertificateV2(core.Sequence):
    _fields = [("certs", _ESSCertIDv2s), ("policies", core.Any, {"optional": True})]


class _SetOfSigningCertificateV2(core.SetOf):
    _child_spec = _SigningCertificateV2


# Register the ESS attribute with asn1crypto so CMSAttribute encodes it cleanly
# (asn1crypto ships no ESS spec). Test-process-only; the verifier matches by OID.
cms.CMSAttributeType._map[_ESS_V2_OID] = "signing_certificate_v2"
cms.CMSAttribute._oid_specs["signing_certificate_v2"] = _SetOfSigningCertificateV2


def _ess_attr_value(cert_der, algo="sha256", wrong=False):
    hfn = {"sha256": hashlib.sha256, "sha512": hashlib.sha512}[algo]
    h = hfn(cert_der).digest()
    if wrong:
        h = bytes(x ^ 0xFF for x in h)  # bind a deliberately wrong cert hash
    cid = _ESSCertIDv2({"hashAlgorithm": algos.DigestAlgorithm({"algorithm": algo}),
                        "certHash": h})
    return _SigningCertificateV2({"certs": _ESSCertIDv2s([cid])})


def sign_token(digest, tsa_key, tsa_cert, hash_algorithm="sha256", gen_time=None,
               ess=True, ess_cert=None, ess_wrong=False, ess_algo="sha256"):
    """Mint a TimeStampToken. `ess`/`ess_cert`/`ess_wrong` control the ESS
    SigningCertificateV2 binding for the differential negatives."""
    gen_time = gen_time or GEN_TIME
    tst_info = tsp.TSTInfo({
        "version": "v1",
        "policy": "1.2.3.4.1",
        "message_imprint": tsp.MessageImprint({
            "hash_algorithm": algos.DigestAlgorithm({"algorithm": hash_algorithm}),
            "hashed_message": digest,
        }),
        "serial_number": 42,
        "gen_time": gen_time,
    })
    tst_info_der = tst_info.dump()
    econtent_hash = hashlib.sha256(tst_info_der).digest()
    tsa_cert_a = a_x509.Certificate.load(tsa_cert.public_bytes(serialization.Encoding.DER))
    attrs = [
        cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [econtent_hash]}),
    ]
    if ess:
        bind = ess_cert if ess_cert is not None else tsa_cert
        bind_der = bind.public_bytes(serialization.Encoding.DER)
        attrs.append(cms.CMSAttribute({
            "type": "signing_certificate_v2",
            "values": [_ess_attr_value(bind_der, ess_algo, ess_wrong)],
        }))
    signed_attrs = cms.CMSAttributes(attrs)
    to_sign = signed_attrs.dump()  # universal SET encoding
    signature = tsa_key.sign(to_sign, padding.PKCS1v15(), hashes.SHA256())
    sid = cms.SignerIdentifier({"issuer_and_serial_number": cms.IssuerAndSerialNumber({
        "issuer": tsa_cert_a.issuer, "serial_number": tsa_cert_a.serial_number,
    })})
    signer_info = cms.SignerInfo({
        "version": "v1", "sid": sid,
        "digest_algorithm": algos.DigestAlgorithm({"algorithm": "sha256"}),
        "signed_attrs": signed_attrs,
        "signature_algorithm": algos.SignedDigestAlgorithm({"algorithm": "rsassa_pkcs1v15"}),
        "signature": signature,
    })
    signed_data = cms.SignedData({
        "version": "v3",
        "digest_algorithms": [algos.DigestAlgorithm({"algorithm": "sha256"})],
        "encap_content_info": cms.EncapsulatedContentInfo({
            "content_type": "tst_info",
            "content": tst_info,
        }),
        "certificates": [tsa_cert_a],
        "signer_infos": [signer_info],
    })
    ci = cms.ContentInfo({"content_type": "signed_data", "content": signed_data})
    return base64.b64encode(ci.dump()).decode("ascii")


def build_corpus():
    """Build the full committed fixture dict (deterministic except the real
    freetsa token + serial numbers, which don't affect verifier verdicts)."""
    ca_key, ca_cert, tsa_key, tsa_cert = make_tsa()
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    digest = bytes.fromhex("ab" * 32)

    # expired signer cert (validity window ends before genTime)
    exp_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    exp_cert = _mkcert("Test TSA Expired", "Test TSA Root CA", ca_key, exp_key, eku_tsa=True,
                       not_before=_dt.datetime(2019, 1, 1), not_after=_dt.datetime(2021, 1, 1))
    # signer cert without the timestamping EKU
    noeku_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    noeku_cert = _mkcert("Test TSA NoEKU", "Test TSA Root CA", ca_key, noeku_key, eku_tsa=False)
    # an unrelated cert used to forge a wrong ESS binding
    other_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    other_cert = _mkcert("Other Cert", "Test TSA Root CA", ca_key, other_key, eku_tsa=True)

    data = {
        "description": "RFC 3161 TimeStampToken corpus for verifier + OpenSSL-differential "
                       "tests. Each token has exactly one defect (or none). Regenerate "
                       "with: python tests/fixtures/_mock_tsa.py generate",
        "stamped_entry_hash": "ab" * 32,
        "hash_algorithm": "sha256",
        "expected_gen_time": "2026-07-01T10:00:00+00:00",
        "tsa_ca_cert_pem": ca_pem,
        # positive: valid token WITH the ESS SigningCertificateV2 attribute
        "tst_token_b64": sign_token(digest, tsa_key, tsa_cert),
        # negative: identical but MISSING the ESS attribute (v0.11.1 reject)
        "no_ess_token_b64": sign_token(digest, tsa_key, tsa_cert, ess=False),
        # negative: ESS binds a DIFFERENT cert than the signer (cert substitution)
        "wrong_ess_token_b64": sign_token(digest, tsa_key, tsa_cert, ess_cert=other_cert),
        # negative: signer cert expired at genTime (still carries ESS)
        "expired_token_b64": sign_token(digest, exp_key, exp_cert),
        # negative: signer cert lacks the timestamping EKU (still carries ESS)
        "no_eku_token_b64": sign_token(digest, noeku_key, noeku_cert),
    }

    # Real freetsa.org token for an independent, RFC-compliant positive in the
    # differential (network at generate time only; committed bytes verify offline).
    try:
        import sys
        sys.path.insert(0, ".")
        from cloakllm.timestamping import request_timestamp
        fdig = hashlib.sha256(b"cloakllm-differential-fixture-v0111").digest()
        ftok = request_timestamp("https://freetsa.org/tsr", fdig, hash_algorithm="sha256")
        fca = urllib.request.urlopen(
            "https://freetsa.org/files/cacert.pem", timeout=20).read().decode()
        data["freetsa_token_b64"] = ftok
        data["freetsa_digest_hex"] = fdig.hex()
        data["freetsa_ca_pem"] = fca
    except Exception as e:  # noqa: BLE001
        print("WARN: real freetsa token not minted (%s: %s) -- kept prior value if any"
              % (type(e).__name__, e))
    return data


def generate():
    data = build_corpus()
    here = Path(__file__).resolve().parent
    py_path = here / "timestamp_token.json"
    js_path = here.parents[2] / "cloakllm-js" / "test" / "fixtures" / "timestamp_token.json"

    # preserve a prior real-freetsa token if this run could not reach the network
    if "freetsa_token_b64" not in data and py_path.exists():
        prior = json.loads(py_path.read_text(encoding="utf-8"))
        for k in ("freetsa_token_b64", "freetsa_digest_hex", "freetsa_ca_pem"):
            if k in prior:
                data[k] = prior[k]

    out = json.dumps(data, indent=2) + "\n"
    py_path.write_text(out, encoding="utf-8")
    print("wrote", py_path)
    if js_path.parent.exists():
        js_path.write_text(out, encoding="utf-8")
        print("wrote", js_path)
    else:
        print("WARN: JS fixtures dir not found at", js_path)


if __name__ == "__main__":
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == "generate":
        generate()
    else:
        print("usage: python tests/fixtures/_mock_tsa.py generate")
