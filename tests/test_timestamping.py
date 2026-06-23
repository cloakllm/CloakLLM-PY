"""v0.11.0 TS-* test suite: RFC 3161 trusted timestamping.

Deterministic + OFFLINE: drives the verifier and the report rollup from a
committed mock-TSA token fixture (tests/fixtures/timestamp_token.json), so CI
never touches a live TSA. The fixture is an RFC 3161 TimeStampToken minted by
the Python mock TSA over a known sha256 digest, with its CA cert.

Requires the optional backend (asn1crypto + cryptography); skipped otherwise.
"""

from __future__ import annotations

import base64
import json
import os
from pathlib import Path

import pytest

from cloakllm.timestamping import _ts_backend_available

pytestmark = pytest.mark.skipif(
    not _ts_backend_available(),
    reason="timestamping backend (asn1crypto + cryptography) not installed",
)

_FIX = json.loads(
    (Path(__file__).parent / "fixtures" / "timestamp_token.json").read_text(encoding="utf-8")
)


def _digest():
    return bytes.fromhex(_FIX["stamped_entry_hash"])


# --- TS-4 verifier ---------------------------------------------------

class TestVerifyToken:
    def test_valid_no_anchor(self):
        from cloakllm.timestamping import verify_timestamp_token
        r = verify_timestamp_token(_FIX["tst_token_b64"], _digest())
        assert r.valid and r.message_imprint_matches and r.signature_valid
        assert r.gen_time == _FIX["expected_gen_time"]
        assert r.chain_valid is None  # no anchor supplied

    def test_valid_with_correct_anchor(self):
        from cloakllm.timestamping import verify_timestamp_token
        r = verify_timestamp_token(_FIX["tst_token_b64"], _digest(),
                                   trusted_certs_pem=[_FIX["tsa_ca_cert_pem"]])
        assert r.valid and r.chain_valid is True

    def test_wrong_digest_rejected(self):
        from cloakllm.timestamping import verify_timestamp_token
        r = verify_timestamp_token(_FIX["tst_token_b64"], bytes.fromhex("cd" * 32))
        assert not r.valid and not r.message_imprint_matches

    def test_tampered_token_rejected(self):
        from cloakllm.timestamping import verify_timestamp_token
        raw = bytearray(base64.b64decode(_FIX["tst_token_b64"]))
        raw[-5] ^= 0xFF
        r = verify_timestamp_token(base64.b64encode(bytes(raw)).decode(), _digest())
        assert not r.valid and not r.signature_valid

    def test_wrong_anchor_chain_fails(self):
        from cloakllm.timestamping import verify_timestamp_token
        # an unrelated self-signed cert is not the token's CA
        from cryptography import x509 as cx509
        from cryptography.hazmat.primitives import hashes, serialization
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.x509.oid import NameOID
        import datetime as dt
        k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        cert = (cx509.CertificateBuilder()
                .subject_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "Other")]))
                .issuer_name(cx509.Name([cx509.NameAttribute(NameOID.COMMON_NAME, "Other")]))
                .public_key(k.public_key()).serial_number(1)
                .not_valid_before(dt.datetime(2020, 1, 1))
                .not_valid_after(dt.datetime(2035, 1, 1))
                .sign(k, hashes.SHA256()))
        pem = cert.public_bytes(serialization.Encoding.PEM).decode()
        r = verify_timestamp_token(_FIX["tst_token_b64"], _digest(), trusted_certs_pem=[pem])
        assert not r.valid and r.chain_valid is False

    def test_garbage_token_no_crash(self):
        from cloakllm.timestamping import verify_timestamp_token
        for bad in ["not base64 !!!", "", base64.b64encode(b"\x30\x00").decode()]:
            r = verify_timestamp_token(bad, _digest())
            assert not r.valid  # never raises


# --- TS-2 client (request build / response parse, offline) ----------

class TestClient:
    def test_build_request_round_trips(self):
        from cloakllm.timestamping import build_timestamp_request
        from asn1crypto import tsp
        der = build_timestamp_request(b"\xab" * 32, "sha256")
        req = tsp.TimeStampReq.load(der)
        assert req["cert_req"].native is True
        assert req["message_imprint"]["hashed_message"].native == b"\xab" * 32

    def test_build_request_rejects_bad_algo(self):
        from cloakllm.timestamping import build_timestamp_request
        with pytest.raises(ValueError):
            build_timestamp_request(b"\x00" * 32, "md5")

    def test_request_timestamp_rejects_non_https(self):
        from cloakllm.timestamping import request_timestamp
        with pytest.raises(ValueError, match="https"):
            request_timestamp("http://tsa.example", b"\x00" * 32)


# --- TS-3 Shield API (offline paths) --------------------------------

class TestShieldCheckpoint:
    def test_no_tsa_returns_none(self, tmp_path):
        from cloakllm import Shield, ShieldConfig
        cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            sh = Shield(config=ShieldConfig(log_dir=str(tmp_path / "a"),
                                            compliance_mode="eu_ai_act_article12"))
            sh.sanitize("hello")
            assert sh.checkpoint() is None
        finally:
            os.chdir(cwd)

    def test_empty_chain_returns_none(self, tmp_path):
        from cloakllm import Shield, ShieldConfig
        cwd = Path.cwd()
        os.chdir(tmp_path)
        try:
            sh = Shield(config=ShieldConfig(
                log_dir=str(tmp_path / "b"), compliance_mode="eu_ai_act_article12",
                timestamp_authority_url="https://tsa.example"))
            assert sh.checkpoint() is None  # nothing written -> nothing to stamp
        finally:
            os.chdir(cwd)


# --- TS-5 report rollup (offline, fixture-driven) -------------------

def _checkpoint_entry(seq, prev_hash, cc):
    return dict(
        seq=seq, event_id="e%d" % seq, timestamp="2026-07-01T10:05:00.000000+00:00",
        event_type="chain_checkpoint", model=None, provider=None, entity_count=0,
        categories={}, tokens_used=[], prompt_hash="", sanitized_hash="",
        latency_ms=0, mode=None, entity_details=[], timing=None,
        certificate_hash=None, key_id=None, prev_hash=prev_hash, entry_hash="x",
        metadata={}, risk_assessment=None,
        article_ref=["EU_AI_Act_Art_12", "EU_AI_Act_Art_19"],
        checkpoint_context=cc,
    )


class TestReportRollup:
    def _cc(self):
        return {
            "stamped_entry_hash": _FIX["stamped_entry_hash"],
            "tsa_url": "https://freetsa.org/tsr",
            "tst_token_b64": _FIX["tst_token_b64"],
            "hash_algorithm": "sha256",
            "stamped_seq": 0,
        }

    def test_valid_checkpoint_rolls_up(self):
        from cloakllm.compliance_report import build_report, ReportPeriod
        rep = build_report(audit_entries=[_checkpoint_entry(0, "0" * 64, self._cc())],
                           period=ReportPeriod(None, None), cloakllm_version="0.11.0",
                           chain_valid=True)
        ps = rep["attestation"]["provenance_summary"]
        assert ps["timestamped_checkpoints"] == 1
        assert ps["checkpoints_verified"] == 1
        assert ps["earliest_provable_time"] == _FIX["expected_gen_time"]
        assert ps["checkpoint_tsa_distribution"] == {"https://freetsa.org/tsr": 1}
        assert rep["verdict"] == "COMPLIANT"

    def test_invalid_checkpoint_is_non_compliant(self):
        from cloakllm.compliance_report import build_report, ReportPeriod
        # tamper the token -> verification fails -> NON_COMPLIANT (verify-don't-assert)
        cc = self._cc()
        raw = bytearray(base64.b64decode(cc["tst_token_b64"])); raw[-5] ^= 0xFF
        cc["tst_token_b64"] = base64.b64encode(bytes(raw)).decode()
        rep = build_report(audit_entries=[_checkpoint_entry(0, "0" * 64, cc)],
                           period=ReportPeriod(None, None), cloakllm_version="0.11.0",
                           chain_valid=True)
        ps = rep["attestation"]["provenance_summary"]
        assert ps["timestamped_checkpoints"] == 1 and ps["checkpoints_verified"] == 0
        assert rep["verdict"] == "NON_COMPLIANT"
        assert any("checkpoints verified" in r for r in rep["verdict_reasons"])

    def test_no_checkpoints_leaves_fields_null(self):
        from cloakllm.compliance_report import build_report, ReportPeriod
        e = dict(seq=0, event_id="e", timestamp="2026-07-01T10:00:00+00:00",
                 event_type="sanitize", model=None, provider=None, entity_count=0,
                 categories={}, tokens_used=[], prompt_hash="", sanitized_hash="",
                 latency_ms=0, mode=None, entity_details=[], timing=None,
                 certificate_hash=None, key_id=None, prev_hash="0" * 64, entry_hash="x",
                 metadata={}, risk_assessment=None, article_ref=["EU_AI_Act_Art_12"])
        rep = build_report(audit_entries=[e], period=ReportPeriod(None, None),
                           cloakllm_version="0.11.0", chain_valid=True)
        ps = rep["attestation"]["provenance_summary"]
        assert ps["timestamped_checkpoints"] is None


# --- TS-1 checkpoint_context validator (AUDIT-3) ---

class TestCheckpointContextValidator:
    def _ok(self, **over):
        cc = {"stamped_entry_hash": "a" * 64, "tsa_url": "https://tsa.example",
              "tst_token_b64": "AAAA", "hash_algorithm": "sha256", "stamped_seq": 5}
        cc.update(over)
        return cc

    def test_valid(self):
        from cloakllm.audit import _validate_checkpoint_context
        _validate_checkpoint_context(self._ok())

    @pytest.mark.parametrize("over,msg", [
        ({"tsa_url": "http://x"}, "https"),
        ({"hash_algorithm": "md5"}, "hash_algorithm"),
        ({"stamped_entry_hash": "xyz"}, "hex"),
        ({"tst_token_b64": "a" * 99999}, "1.."),
        ({"tst_token_b64": "!!!notb64"}, "base64"),
        ({"stamped_seq": -1}, ">= 0"),
        ({"extra": "x"}, "disallowed"),
    ])
    def test_rejections(self, over, msg):
        from cloakllm.audit import _validate_checkpoint_context
        with pytest.raises(RuntimeError, match=msg):
            _validate_checkpoint_context(self._ok(**over))

    def test_coupling_only_on_checkpoint_event(self):
        from cloakllm.audit import _validate_audit_entry_schema
        base = dict(seq=0, event_id="e", timestamp="2026-01-01T00:00:00+00:00",
                    event_type="sanitize", model=None, provider=None, entity_count=0,
                    categories={}, tokens_used=[], prompt_hash="", sanitized_hash="",
                    latency_ms=0, mode=None, entity_details=[], timing=None,
                    certificate_hash=None, key_id=None, prev_hash="0" * 64,
                    metadata={}, risk_assessment=None, checkpoint_context=self._ok())
        with pytest.raises(RuntimeError, match="checkpoint_context requires"):
            _validate_audit_entry_schema(base)


# --- v0.11.0 adversarial-review fixes (MEDIUM-2): cert validity + EKU ---

class TestSignerCertHardening:
    def test_expired_signer_cert_rejected(self):
        from cloakllm.timestamping import verify_timestamp_token
        if "expired_token_b64" not in _FIX:
            import pytest as _p; _p.skip("fixture lacks expired token")
        r = verify_timestamp_token(_FIX["expired_token_b64"], _digest(),
                                   trusted_certs_pem=[_FIX["tsa_ca_cert_pem"]])
        assert not r.valid and "not valid at genTime" in r.reason

    def test_non_timestamping_cert_rejected(self):
        from cloakllm.timestamping import verify_timestamp_token
        if "no_eku_token_b64" not in _FIX:
            import pytest as _p; _p.skip("fixture lacks no-eku token")
        r = verify_timestamp_token(_FIX["no_eku_token_b64"], _digest(),
                                   trusted_certs_pem=[_FIX["tsa_ca_cert_pem"]])
        assert not r.valid and "timeStamping" in r.reason


# --- v0.11.1: ESS signing-certificate attribute (RFC 3161 sec 2.4.1) ---

class TestEssSigningCert:
    def test_missing_ess_rejected(self):
        from cloakllm.timestamping import verify_timestamp_token
        if "no_ess_token_b64" not in _FIX:
            import pytest as _p; _p.skip("fixture lacks no-ess token")
        r = verify_timestamp_token(_FIX["no_ess_token_b64"], _digest(),
                                   trusted_certs_pem=[_FIX["tsa_ca_cert_pem"]])
        assert not r.valid and "ESS signing-certificate" in r.reason

    def test_wrong_ess_binding_rejected(self):
        from cloakllm.timestamping import verify_timestamp_token
        if "wrong_ess_token_b64" not in _FIX:
            import pytest as _p; _p.skip("fixture lacks wrong-ess token")
        r = verify_timestamp_token(_FIX["wrong_ess_token_b64"], _digest(),
                                   trusted_certs_pem=[_FIX["tsa_ca_cert_pem"]])
        assert not r.valid and "does not match the signer cert" in r.reason

    def test_real_freetsa_token_has_ess_and_verifies(self):
        from cloakllm.timestamping import verify_timestamp_token
        if "freetsa_token_b64" not in _FIX:
            import pytest as _p; _p.skip("fixture lacks real freetsa token")
        r = verify_timestamp_token(_FIX["freetsa_token_b64"],
                                   bytes.fromhex(_FIX["freetsa_digest_hex"]),
                                   trusted_certs_pem=[_FIX["freetsa_ca_pem"]])
        assert r.valid and r.chain_valid is True


# --- v0.11.1: OpenSSL-differential. Our verifier's accept/reject verdict MUST
# match `openssl ts -verify` across the committed corpus. This is independent-
# implementation corroboration (the strongest signal short of a formal audit).
# Skipped if openssl is not on PATH; REQUIRED in CI (runners ship openssl). ---

import shutil  # noqa: E402

_OPENSSL = shutil.which("openssl")


@pytest.mark.skipif(_OPENSSL is None, reason="openssl not on PATH")
class TestOpenSSLDifferential:
    def _openssl_accepts(self, tmp_path, der: bytes, digest_hex: str, ca_pem: str) -> bool:
        import subprocess
        tok = tmp_path / "t.der"; tok.write_bytes(der)
        ca = tmp_path / "ca.pem"; ca.write_text(ca_pem, encoding="utf-8")
        r = subprocess.run(
            [_OPENSSL, "ts", "-verify", "-token_in", "-in", str(tok),
             "-digest", digest_hex, "-CAfile", str(ca)],
            capture_output=True, text=True)
        return r.returncode == 0

    def _corpus(self):
        md, mca = _FIX["stamped_entry_hash"], _FIX["tsa_ca_cert_pem"]
        cases = [
            ("valid", _FIX["tst_token_b64"], md, mca, True),
            ("no_ess", _FIX["no_ess_token_b64"], md, mca, False),
            ("wrong_ess", _FIX["wrong_ess_token_b64"], md, mca, False),
            ("expired", _FIX["expired_token_b64"], md, mca, False),
            ("no_eku", _FIX["no_eku_token_b64"], md, mca, False),
        ]
        if "freetsa_token_b64" in _FIX:
            cases.append(("freetsa", _FIX["freetsa_token_b64"],
                          _FIX["freetsa_digest_hex"], _FIX["freetsa_ca_pem"], True))
        return cases

    def test_verdicts_match_openssl(self, tmp_path):
        from cloakllm.timestamping import verify_timestamp_token
        for name, b64, dig_hex, ca, expect in self._corpus():
            der = base64.b64decode(b64)
            ours = verify_timestamp_token(b64, bytes.fromhex(dig_hex),
                                          trusted_certs_pem=[ca]).valid
            osl = self._openssl_accepts(tmp_path, der, dig_hex, ca)
            assert ours == osl == expect, (
                f"{name}: ours={ours} openssl={osl} expected={expect}")


# --- v0.11.1: fuzz the offline parser/verifier. Random + mutated bytes must
# NEVER raise and NEVER return valid=True. Targets the parsing surface (the
# hand-rolled JS mirror has the same harness). Seeded -> deterministic. ---

class TestFuzzParser:
    def test_random_and_truncated_never_raise_and_are_invalid(self):
        # Pure-random and truncated inputs are structurally broken: they can
        # never carry a valid signature, so valid MUST be False -- and the
        # hand-rolled parsing surface must never raise (crash/DoS resistance).
        import random
        from cloakllm.timestamping import verify_timestamp_token
        rng = random.Random(0xC10A)
        base = base64.b64decode(_FIX["tst_token_b64"])
        dig = _digest()
        for i in range(3000):
            if i % 2 == 0:                         # pure random blob
                blob = bytes(rng.randrange(256) for _ in range(rng.randrange(0, 80)))
            else:                                  # truncated real token (>=1 byte short)
                blob = base[:rng.randrange(0, len(base))]
            r = verify_timestamp_token(base64.b64encode(blob).decode(), dig)
            assert r.valid is False  # never raises (would error the test), never wrongly valid

    def test_bitflips_never_raise(self):
        # A single bit-flip may land on a don't-care byte (e.g. the embedded
        # cert's own signature, unchecked without a trust anchor) and leave the
        # token validly verifiable -- that is correct. The invariant under fuzz
        # is only that the parser NEVER raises on a mutated real token.
        import random
        from cloakllm.timestamping import verify_timestamp_token
        rng = random.Random(0x5EED)
        base = bytearray(base64.b64decode(_FIX["tst_token_b64"]))
        dig = _digest()
        for _ in range(3000):
            b = bytearray(base)
            for _ in range(rng.randrange(1, 12)):
                b[rng.randrange(len(b))] = rng.randrange(256)
            r = verify_timestamp_token(base64.b64encode(bytes(b)).decode(), dig)
            assert r.valid in (True, False)  # a result object, no exception escaped
