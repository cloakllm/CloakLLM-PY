"""Mock RFC 3161 TSA: mints real, valid TimeStampTokens for testing."""
import hashlib, base64
from datetime import datetime, timezone
from asn1crypto import tsp, cms, algos, core, x509 as a_x509
from cryptography import x509 as cx509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
import datetime as _dt

def _mkcert(subject_cn, issuer_cn, issuer_key, subject_key, ca=False, eku_tsa=False, self_signed=False):
    sk = subject_key
    builder = cx509.CertificateBuilder()
    builder = builder.subject_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, subject_cn)]))
    builder = builder.issuer_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, issuer_cn)]))
    builder = builder.public_key(sk.public_key())
    builder = builder.serial_number(cx509.random_serial_number())
    builder = builder.not_valid_before(_dt.datetime(2020,1,1))
    builder = builder.not_valid_after(_dt.datetime(2035,1,1))
    if ca:
        builder = builder.add_extension(cx509.BasicConstraints(ca=True, path_length=None), critical=True)
    if eku_tsa:
        builder = builder.add_extension(cx509.ExtendedKeyUsage([cx509.ObjectIdentifier("1.3.6.1.5.5.7.3.8")]), critical=True)
    return builder.sign(issuer_key, hashes.SHA256())

def make_tsa():
    ca_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    ca_cert = _mkcert("Test TSA Root CA", "Test TSA Root CA", ca_key, ca_key, ca=True)
    tsa_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    tsa_cert = _mkcert("Test TSA", "Test TSA Root CA", ca_key, tsa_key, eku_tsa=True)
    return ca_key, ca_cert, tsa_key, tsa_cert

def sign_token(digest, tsa_key, tsa_cert, hash_algorithm="sha256", gen_time=None):
    gen_time = gen_time or datetime(2026,7,1,10,0,0,tzinfo=timezone.utc)
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
    signed_attrs = cms.CMSAttributes([
        cms.CMSAttribute({"type": "content_type", "values": ["tst_info"]}),
        cms.CMSAttribute({"type": "message_digest", "values": [econtent_hash]}),
    ])
    to_sign = signed_attrs.dump()  # universal SET encoding
    signature = tsa_key.sign(to_sign, __import__("cryptography.hazmat.primitives.asymmetric.padding", fromlist=["PKCS1v15"]).PKCS1v15(), hashes.SHA256())
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

if __name__ == "__main__":
    import sys
    sys.path.insert(0, ".")
    from cloakllm.timestamping import verify_timestamp_token, build_timestamp_request, parse_timestamp_response
    ca_key, ca_cert, tsa_key, tsa_cert = make_tsa()
    entry_hash_hex = "ab"*32
    digest = bytes.fromhex(entry_hash_hex)
    token_b64 = sign_token(digest, tsa_key, tsa_cert)
    ca_pem = ca_cert.public_bytes(serialization.Encoding.PEM).decode()
    # 1. valid, no anchor
    r = verify_timestamp_token(token_b64, digest)
    print("no-anchor:", r.valid, "mi", r.message_imprint_matches, "sig", r.signature_valid, "chain", r.chain_valid, "genT", r.gen_time, "|", r.reason)
    # 2. valid, with correct anchor
    r2 = verify_timestamp_token(token_b64, digest, trusted_certs_pem=[ca_pem])
    print("good-anchor:", r2.valid, "chain", r2.chain_valid)
    # 3. wrong digest -> reject
    r3 = verify_timestamp_token(token_b64, bytes.fromhex("cd"*32))
    print("wrong-digest:", r3.valid, "|", r3.reason)
    # 4. tampered token -> reject
    bad = bytearray(base64.b64decode(token_b64)); bad[-5] ^= 0xFF
    r4 = verify_timestamp_token(base64.b64encode(bytes(bad)).decode(), digest)
    print("tampered:", r4.valid, "|", r4.reason)
    # 5. wrong anchor -> chain fail
    other_key, other_cert, _, _ = make_tsa()
    r5 = verify_timestamp_token(token_b64, digest, trusted_certs_pem=[other_cert.public_bytes(serialization.Encoding.PEM).decode()])
    print("wrong-anchor:", r5.valid, "chain", r5.chain_valid, "|", r5.reason)
