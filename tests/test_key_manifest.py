"""v0.8.1 KM-* test suite: externally-verifiable key provenance.

Covers KM-1 (KeyManifest + derive_key_manifest), KM-2 (verify_key_provenance
+ ProvenanceReport), KM-3 (key_registered audit event + B3 extension),
KM-4 (root_signature offline-root signing -- folded into KM-1/2),
KM-7 (backward compatibility), and AUDIT-3 hardening (adversarial inputs).
KM-9 (compliance_report aggregator) is covered in test_compliance_report.py.
"""

from __future__ import annotations

import base64
import json
import tempfile
from pathlib import Path

import pytest

from cloakllm import (
    DeploymentKeyPair, KeyManifest, derive_key_manifest,
    ProvenanceReport, verify_key_provenance,
    SanitizationCertificate, Shield, ShieldConfig,
)
from cloakllm.attestation import (
    _compute_manifest_hash, KEY_MANIFEST_SCHEMA_VERSION,
    ROOT_SIG_VALID, ROOT_SIG_INVALID,
    ROOT_SIG_NOT_REQUESTED, ROOT_SIG_UNVERIFIED_NO_KEY,
    PROVENANCE_VERIFIED, PROVENANCE_FAILED, PROVENANCE_UNVERIFIED,
)
from cloakllm.audit import (
    _validate_audit_entry_schema, _validate_key_manifest,
)


# ===================================================================
# KM-1: KeyManifest + derive_key_manifest()
# ===================================================================

class TestDeriveKeyManifest:
    def _kp(self):
        return DeploymentKeyPair.generate()

    def test_happy_path(self):
        kp = self._kp()
        m = derive_key_manifest(kp, deployer_id="acme")
        assert m.key_id == kp.key_id
        assert m.public_key == kp.public_key_b64
        assert m.deployer_id == "acme"
        assert m.purpose == "cloakllm-audit-attestation"
        assert m.manifest_version == KEY_MANIFEST_SCHEMA_VERSION
        assert m.manifest_hash
        assert m.root_signature is None
        assert m.root_key_id is None

    def test_determinism(self):
        kp = self._kp()
        m1 = derive_key_manifest(kp,
            deployer_id="x", valid_from="2026-01-01T00:00:00+00:00")
        m2 = derive_key_manifest(kp,
            deployer_id="x", valid_from="2026-01-01T00:00:00+00:00")
        assert m1.manifest_hash == m2.manifest_hash

    def test_json_round_trip(self):
        kp = self._kp()
        m = derive_key_manifest(kp, deployer_id="acme")
        d = m.to_dict()
        m2 = KeyManifest.from_dict(d)
        assert m2 == m

    def test_root_signing_callback(self):
        kp = self._kp()
        root_kp = self._kp()
        m = derive_key_manifest(kp,
            deployer_id="acme",
            valid_from="2026-01-01T00:00:00+00:00",
            root_signing_callback=root_kp.sign,
            root_key_id="root-2026",
        )
        assert m.root_signature is not None
        assert m.root_key_id == "root-2026"
        # Verify the root signature
        assert DeploymentKeyPair.verify(
            root_kp.public_key,
            m.manifest_hash.encode("ascii"),
            base64.b64decode(m.root_signature),
        )

    def test_rejects_empty_deployer_id(self):
        kp = self._kp()
        with pytest.raises(ValueError, match="deployer_id"):
            derive_key_manifest(kp, deployer_id="")

    def test_rejects_oversized_deployer_id(self):
        kp = self._kp()
        with pytest.raises(ValueError, match="256 chars"):
            derive_key_manifest(kp, deployer_id="x" * 257)

    def test_rejects_nul_byte_deployer_id(self):
        kp = self._kp()
        with pytest.raises(ValueError, match="NUL"):
            derive_key_manifest(kp, deployer_id="bad\x00name")

    def test_rejects_unknown_purpose(self):
        kp = self._kp()
        with pytest.raises(ValueError, match="purpose"):
            derive_key_manifest(kp, deployer_id="x", purpose="evil-malware")

    def test_rejects_naive_timestamp(self):
        kp = self._kp()
        with pytest.raises(ValueError, match="UTC"):
            derive_key_manifest(kp, deployer_id="x",
                valid_from="2026-01-01T00:00:00")  # no tz

    def test_rejects_valid_until_before_valid_from(self):
        kp = self._kp()
        with pytest.raises(ValueError, match="valid_until"):
            derive_key_manifest(kp, deployer_id="x",
                valid_from="2027-01-01T00:00:00+00:00",
                valid_until="2026-01-01T00:00:00+00:00")

    def test_rejects_root_callback_without_root_key_id(self):
        kp = self._kp()
        with pytest.raises(ValueError, match="root_key_id"):
            derive_key_manifest(kp, deployer_id="x",
                root_signing_callback=kp.sign)

    def test_rejects_bad_callback_signature_length(self):
        kp = self._kp()
        with pytest.raises(ValueError, match="64 bytes"):
            derive_key_manifest(kp, deployer_id="x",
                root_signing_callback=lambda data: b"too-short",
                root_key_id="r")


# ===================================================================
# KM-2: verify_key_provenance + ProvenanceReport
# ===================================================================

@pytest.fixture
def setup():
    kp = DeploymentKeyPair.generate()
    manifest = derive_key_manifest(kp,
        deployer_id="acme",
        valid_from="2026-01-01T00:00:00+00:00",
        valid_until="2027-01-01T00:00:00+00:00",
    )
    cert = SanitizationCertificate.create(
        original_text="x", sanitized_text="y",
        entity_count=0, categories={}, detection_passes=["regex"],
        mode="tokenize", keypair=kp,
    )
    return kp, manifest, cert


class TestVerifyKeyProvenance:
    def test_happy_path(self, setup):
        _, manifest, cert = setup
        r = verify_key_provenance(cert, manifest)
        assert r.overall_valid is True
        assert r.provenance_status == PROVENANCE_VERIFIED
        assert r.signature_valid is True
        assert r.key_id_matches is True
        assert r.within_validity_window is True
        assert r.root_signature_status == ROOT_SIG_NOT_REQUESTED
        assert r.manifest_hash_consistent is True

    def test_manifest_none_back_compat(self, setup):
        _, _, cert = setup
        r = verify_key_provenance(cert, None)
        assert r.provenance_status == PROVENANCE_UNVERIFIED
        assert r.signature_valid is True
        assert r.overall_valid is True  # signature-only mode
        assert r.key_id_matches is None
        assert r.within_validity_window is None
        assert r.manifest_hash_consistent is None

    def test_tampered_manifest_key_id(self, setup):
        _, manifest, cert = setup
        import dataclasses
        tampered = dataclasses.replace(manifest, key_id="bogus")
        r = verify_key_provenance(cert, tampered)
        assert r.overall_valid is False
        assert r.provenance_status == PROVENANCE_FAILED
        assert r.key_id_matches is False
        assert r.manifest_hash_consistent is False

    def test_expired_key(self, setup):
        kp, _, cert = setup
        expired = derive_key_manifest(kp,
            deployer_id="acme",
            valid_from="2025-01-01T00:00:00+00:00",
            valid_until="2025-12-31T00:00:00+00:00",
        )
        r = verify_key_provenance(cert, expired)
        assert r.within_validity_window is False
        assert any("expired" in n for n in r.notes)

    def test_cert_before_key_validity(self, setup):
        kp, _, cert = setup
        future = derive_key_manifest(kp,
            deployer_id="acme",
            valid_from="2030-01-01T00:00:00+00:00",
        )
        r = verify_key_provenance(cert, future)
        assert r.within_validity_window is False

    def test_root_signed_correct_root_pk(self, setup):
        kp, _, cert = setup
        root_kp = DeploymentKeyPair.generate()
        m = derive_key_manifest(kp,
            deployer_id="acme",
            valid_from="2026-01-01T00:00:00+00:00",
            valid_until="2027-01-01T00:00:00+00:00",
            root_signing_callback=root_kp.sign, root_key_id="r",
        )
        r = verify_key_provenance(cert, m, root_public_key=root_kp.public_key)
        assert r.root_signature_status == ROOT_SIG_VALID
        assert r.overall_valid is True

    def test_root_signed_wrong_root_pk(self, setup):
        kp, _, cert = setup
        root_kp = DeploymentKeyPair.generate()
        wrong_root = DeploymentKeyPair.generate()
        m = derive_key_manifest(kp,
            deployer_id="acme",
            valid_from="2026-01-01T00:00:00+00:00",
            valid_until="2027-01-01T00:00:00+00:00",
            root_signing_callback=root_kp.sign, root_key_id="r",
        )
        r = verify_key_provenance(cert, m, root_public_key=wrong_root.public_key)
        assert r.root_signature_status == ROOT_SIG_INVALID
        assert r.overall_valid is False

    def test_root_signed_no_root_pk_supplied(self, setup):
        kp, _, cert = setup
        root_kp = DeploymentKeyPair.generate()
        m = derive_key_manifest(kp,
            deployer_id="acme",
            valid_from="2026-01-01T00:00:00+00:00",
            valid_until="2027-01-01T00:00:00+00:00",
            root_signing_callback=root_kp.sign, root_key_id="r",
        )
        r = verify_key_provenance(cert, m)  # no root_public_key
        assert r.root_signature_status == ROOT_SIG_UNVERIFIED_NO_KEY
        # overall_valid stays True -- caller didn't request the root check
        assert r.overall_valid is True

    def test_clock_skew_tolerance(self, setup):
        kp, _, cert = setup
        # Window 1 minute in the past -- normally cert.timestamp is after.
        # With +90s skew the upper bound widens enough to admit it.
        import datetime as _dt
        now = _dt.datetime.now(_dt.timezone.utc)
        past_end = (now - _dt.timedelta(seconds=60)).isoformat()
        past_start = (now - _dt.timedelta(seconds=3600)).isoformat()
        m = derive_key_manifest(kp,
            deployer_id="acme",
            valid_from=past_start, valid_until=past_end,
        )
        # Strict (default): outside the window
        r_strict = verify_key_provenance(cert, m)
        assert r_strict.within_validity_window is False
        # With 90s tolerance: cert is within
        r_skew = verify_key_provenance(cert, m, clock_skew_seconds=90)
        assert r_skew.within_validity_window is True


# ===================================================================
# KM-3: key_registered audit event + B3 extension
# ===================================================================

class TestKeyRegisteredEvent:
    def test_shield_emits_on_init(self, tmp_path):
        kp = DeploymentKeyPair.generate()
        cfg = ShieldConfig(
            audit_enabled=True, log_dir=str(tmp_path),
            attestation_key=kp,
            deployer_id="acme",
            compliance_mode="eu_ai_act_article12",
        )
        Shield(config=cfg)
        # Find the key_registered event
        entries = []
        for f in sorted(tmp_path.glob("audit_*.jsonl")):
            for line in f.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    entries.append(json.loads(line))
        kr = [e for e in entries if e["event_type"] == "key_registered"]
        assert len(kr) == 1
        assert kr[0]["key_manifest"]["deployer_id"] == "acme"

    def test_no_emit_without_deployer_id(self, tmp_path):
        kp = DeploymentKeyPair.generate()
        cfg = ShieldConfig(
            audit_enabled=True, log_dir=str(tmp_path),
            attestation_key=kp,  # no deployer_id
        )
        Shield(config=cfg)
        entries = []
        for f in sorted(tmp_path.glob("audit_*.jsonl")):
            for line in f.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    entries.append(json.loads(line))
        kr = [e for e in entries if e["event_type"] == "key_registered"]
        assert len(kr) == 0

    def test_allow_duplicate_emission_policy(self, tmp_path):
        """Decision 3 in PLAN_v081.md: concurrent Shield inits with the
        same key both emit; verifier dedups by manifest_hash."""
        kp = DeploymentKeyPair.generate()
        cfg_factory = lambda: ShieldConfig(
            audit_enabled=True, log_dir=str(tmp_path),
            attestation_key=kp, deployer_id="acme",
            key_valid_from="2026-01-01T00:00:00+00:00",
        )
        Shield(config=cfg_factory())
        Shield(config=cfg_factory())
        entries = []
        for f in sorted(tmp_path.glob("audit_*.jsonl")):
            for line in f.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    entries.append(json.loads(line))
        kr = [e for e in entries if e["event_type"] == "key_registered"]
        # Two emissions
        assert len(kr) == 2
        # One unique manifest_hash (verifier dedups)
        assert len({e["key_manifest"]["manifest_hash"] for e in kr}) == 1

    def test_chain_still_verifies(self, tmp_path):
        kp = DeploymentKeyPair.generate()
        cfg = ShieldConfig(
            audit_enabled=True, log_dir=str(tmp_path),
            attestation_key=kp, deployer_id="acme",
            compliance_mode="eu_ai_act_article12",
        )
        sh = Shield(config=cfg)
        sh.sanitize("a@b.com")
        sh.sanitize("c@d.com")
        # Verify
        verifier_cfg = ShieldConfig(audit_enabled=False, log_dir=str(tmp_path))
        result = Shield(config=verifier_cfg).verify_audit()
        assert result["valid"] is True
        assert len(result.get("errors", [])) == 0

    def test_b3_validator_accepts_well_formed_key_manifest(self):
        entry = {
            "seq": 0, "event_id": "x", "timestamp": "2026-05-31T00:00:00+00:00",
            "event_type": "key_registered",
            "model": None, "provider": None, "entity_count": 0,
            "categories": {}, "tokens_used": [], "prompt_hash": "",
            "sanitized_hash": "", "latency_ms": 0.0, "mode": None,
            "entity_details": [], "timing": None, "certificate_hash": None,
            "key_id": "abc123", "prev_hash": "", "metadata": {},
            "risk_assessment": None,
            "key_manifest": {
                "key_id": "abc123",
                "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "deployer_id": "acme",
                "valid_from": "2026-01-01T00:00:00+00:00",
                "valid_until": "2027-01-01T00:00:00+00:00",
                "purpose": "cloakllm-audit-attestation",
                "manifest_version": "1.0",
                "manifest_hash": "cafef00d",
                "root_signature": None,
                "root_key_id": None,
            },
        }
        # Should not raise
        _validate_audit_entry_schema(entry)

    def test_b3_rejects_key_manifest_on_non_key_registered_event(self):
        entry = {
            "seq": 0, "event_id": "x", "timestamp": "2026-05-31T00:00:00+00:00",
            "event_type": "sanitize",  # << wrong type
            "model": None, "provider": None, "entity_count": 0,
            "categories": {}, "tokens_used": [], "prompt_hash": "",
            "sanitized_hash": "", "latency_ms": 0.0, "mode": None,
            "entity_details": [], "timing": None, "certificate_hash": None,
            "key_id": "abc", "prev_hash": "", "metadata": {},
            "risk_assessment": None,
            "key_manifest": {
                "key_id": "abc",
                "public_key": "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=",
                "deployer_id": "acme",
                "valid_from": "2026-01-01T00:00:00+00:00",
                "purpose": "cloakllm-audit-attestation",
                "manifest_version": "1.0",
                "manifest_hash": "cafef00d",
            },
        }
        with pytest.raises(RuntimeError, match="key_manifest requires"):
            _validate_audit_entry_schema(entry)


# ===================================================================
# AUDIT-3 hardening: adversarial inputs (applied from day 1)
# ===================================================================

class TestKeyManifestAdversarialInputs:
    def test_validate_rejects_non_dict(self):
        with pytest.raises(RuntimeError, match="must be a dict"):
            _validate_key_manifest("not-a-dict")  # type: ignore

    def test_validate_rejects_missing_required_field(self):
        with pytest.raises(RuntimeError, match="missing required field"):
            _validate_key_manifest({
                "key_id": "abc",
                # missing public_key, deployer_id, etc.
            })

    def test_validate_rejects_disallowed_key(self):
        km = {
            "key_id": "abc", "public_key": "x", "deployer_id": "y",
            "valid_from": "2026-01-01T00:00:00+00:00",
            "purpose": "cloakllm-audit-attestation",
            "manifest_version": "1.0", "manifest_hash": "cafe",
            "evil_extra_field": "data",
        }
        with pytest.raises(RuntimeError, match="disallowed"):
            _validate_key_manifest(km)

    def test_validate_rejects_required_field_null(self):
        km = {
            "key_id": None,  # << must not be null
            "public_key": "x", "deployer_id": "y",
            "valid_from": "2026-01-01T00:00:00+00:00",
            "purpose": "cloakllm-audit-attestation",
            "manifest_version": "1.0", "manifest_hash": "cafe",
        }
        with pytest.raises(RuntimeError, match="must not be null"):
            _validate_key_manifest(km)

    def test_validate_rejects_oversized_field(self):
        km = {
            "key_id": "abc", "public_key": "x",
            "deployer_id": "y" * 257,  # oversized
            "valid_from": "2026-01-01T00:00:00+00:00",
            "purpose": "cloakllm-audit-attestation",
            "manifest_version": "1.0", "manifest_hash": "cafe",
        }
        with pytest.raises(RuntimeError, match="exceeds"):
            _validate_key_manifest(km)

    def test_validate_rejects_nul_byte(self):
        km = {
            "key_id": "abc", "public_key": "x",
            "deployer_id": "bad\x00name",
            "valid_from": "2026-01-01T00:00:00+00:00",
            "purpose": "cloakllm-audit-attestation",
            "manifest_version": "1.0", "manifest_hash": "cafe",
        }
        with pytest.raises(RuntimeError, match="NUL byte"):
            _validate_key_manifest(km)

    def test_verify_key_provenance_handles_malformed_timestamps(self, setup):
        kp, _, cert = setup
        # Construct a manifest manually with malformed timestamps -- pre-AUDIT-3
        # this would crash. After hardening: returns within_validity_window=False
        # with a clear note.
        bad_manifest = KeyManifest(
            key_id=kp.key_id, public_key=kp.public_key_b64,
            deployer_id="x", valid_from="not-a-timestamp",
            valid_until=None, purpose="cloakllm-audit-attestation",
            manifest_version="1.0",
            manifest_hash=_compute_manifest_hash(
                key_id=kp.key_id, public_key=kp.public_key_b64,
                deployer_id="x", valid_from="not-a-timestamp",
                valid_until=None, purpose="cloakllm-audit-attestation",
                manifest_version="1.0", root_key_id=None,
            ),
        )
        # Should NOT raise; should return within_validity_window=False
        r = verify_key_provenance(cert, bad_manifest)
        assert r.within_validity_window is False
        assert any("cannot compare timestamps" in n for n in r.notes)


# ===================================================================
# KM-7: Backward compatibility
# ===================================================================

class TestBackwardCompatibility:
    def test_pre_v081_chain_still_verifies(self, tmp_path):
        """A v0.8.0 audit chain (no key_registered events) verifies under
        v0.8.1 unchanged. Pure additive change."""
        kp = DeploymentKeyPair.generate()
        cfg = ShieldConfig(
            audit_enabled=True, log_dir=str(tmp_path),
            attestation_key=kp,  # no deployer_id -> v0.8.0-style chain
            compliance_mode="eu_ai_act_article12",
        )
        sh = Shield(config=cfg)
        sh.sanitize("a@b.com")
        result = Shield(config=ShieldConfig(
            audit_enabled=False, log_dir=str(tmp_path))).verify_audit()
        assert result["valid"] is True

    def test_pre_v081_cert_verify_unchanged(self):
        """The v0.6.x cert.verify(pk) API is unchanged. KeyManifest is opt-in."""
        kp = DeploymentKeyPair.generate()
        cert = SanitizationCertificate.create(
            original_text="x", sanitized_text="y",
            entity_count=0, categories={}, detection_passes=["regex"],
            mode="tokenize", keypair=kp,
        )
        # The old API still works
        assert cert.verify(kp.public_key) is True
