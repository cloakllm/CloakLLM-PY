"""v0.9.0 RV-* test suite: root-signed key revocation.

Covers RV-1 (RevocationList + derive_revocation_list), RV-2
(verify_key_provenance check #6), RV-3 (key_revoked advisory event +
Shield own-key fail-hard), RV-4 (provenance_summary revocation fields),
and AUDIT-3 adversarial hardening. The out-of-band Design Decision 1
properties are asserted explicitly.
"""

from __future__ import annotations

import dataclasses
import json
import tempfile
from pathlib import Path

import pytest

from cloakllm import (
    DeploymentKeyPair, SanitizationCertificate,
    KeyManifest, derive_key_manifest,
    RevocationEntry, RevocationList, derive_revocation_list,
    verify_key_provenance,
    Shield, ShieldConfig,
)
from cloakllm.attestation import (
    REVOCATION_NOT_REVOKED, REVOCATION_REVOKED,
    REVOCATION_REVOKED_BUT_CERT_PREDATES,
    REVOCATION_NOT_CHECKED, REVOCATION_LIST_INVALID,
    REVOCATION_LIST_SCHEMA_VERSION,
)


@pytest.fixture
def kit():
    kp = DeploymentKeyPair.generate()
    root_kp = DeploymentKeyPair.generate()
    manifest = derive_key_manifest(
        kp, deployer_id="acme",
        valid_from="2026-01-01T00:00:00+00:00",
        valid_until="2027-01-01T00:00:00+00:00",
    )
    cert = SanitizationCertificate.create(
        original_text="x", sanitized_text="y",
        entity_count=0, categories={}, detection_passes=["regex"],
        mode="tokenize", keypair=kp,
    )
    return kp, root_kp, manifest, cert


# ===================================================================
# RV-1: RevocationList + derive_revocation_list
# ===================================================================

class TestDeriveRevocationList:
    def test_empty_list_is_valid_and_signable(self, kit):
        _, root_kp, _, _ = kit
        rl = derive_revocation_list(
            deployer_id="acme", entries=[],
            issued_at="2026-06-01T00:00:00+00:00",
            root_signing_callback=root_kp.sign, root_key_id="root-1",
        )
        assert rl.entries == ()
        assert rl.list_hash
        assert rl.root_signature is not None
        assert rl.list_version == REVOCATION_LIST_SCHEMA_VERSION

    def test_hash_deterministic(self):
        kwargs = dict(
            deployer_id="acme",
            entries=[{"key_id": "k1",
                      "revoked_at": "2026-01-01T00:00:00+00:00",
                      "reason": "compromised"}],
            issued_at="2026-06-01T00:00:00+00:00",
        )
        assert (derive_revocation_list(**kwargs).list_hash
                == derive_revocation_list(**kwargs).list_hash)

    def test_entry_order_is_part_of_hash(self):
        e1 = {"key_id": "k1", "revoked_at": "2026-01-01T00:00:00+00:00", "reason": "compromised"}
        e2 = {"key_id": "k2", "revoked_at": "2026-02-01T00:00:00+00:00", "reason": "superseded"}
        a = derive_revocation_list(deployer_id="x", entries=[e1, e2],
                                   issued_at="2026-06-01T00:00:00+00:00")
        b = derive_revocation_list(deployer_id="x", entries=[e2, e1],
                                   issued_at="2026-06-01T00:00:00+00:00")
        assert a.list_hash != b.list_hash  # reordering is tampering

    def test_json_round_trip(self, kit):
        _, root_kp, _, _ = kit
        rl = derive_revocation_list(
            deployer_id="acme",
            entries=[{"key_id": "k1",
                      "revoked_at": "2026-01-01T00:00:00+00:00",
                      "reason": "ceased_operation"}],
            issued_at="2026-06-01T00:00:00+00:00",
            root_signing_callback=root_kp.sign, root_key_id="r",
        )
        rt = RevocationList.from_dict(rl.to_dict())
        assert rt.list_hash == rl.list_hash
        assert len(rt.entries) == 1
        assert rt.entries[0].reason == "ceased_operation"

    def test_rejects_duplicate_key_id(self):
        with pytest.raises(ValueError, match="duplicated"):
            derive_revocation_list(deployer_id="x", entries=[
                {"key_id": "k1", "revoked_at": "2026-01-01T00:00:00+00:00", "reason": "compromised"},
                {"key_id": "k1", "revoked_at": "2026-02-01T00:00:00+00:00", "reason": "superseded"},
            ], issued_at="2026-06-01T00:00:00+00:00")

    def test_rejects_unknown_reason(self):
        with pytest.raises(ValueError, match="reason"):
            derive_revocation_list(deployer_id="x", entries=[
                {"key_id": "k1", "revoked_at": "2026-01-01T00:00:00+00:00", "reason": "oops"},
            ], issued_at="2026-06-01T00:00:00+00:00")

    def test_rejects_naive_timestamps(self):
        with pytest.raises(ValueError, match="UTC"):
            derive_revocation_list(deployer_id="x", entries=[
                {"key_id": "k1", "revoked_at": "2026-01-01T00:00:00", "reason": "compromised"},
            ], issued_at="2026-06-01T00:00:00+00:00")

    def test_rejects_oversized_entry_count(self):
        entries = [
            {"key_id": f"k{i}", "revoked_at": "2026-01-01T00:00:00+00:00", "reason": "superseded"}
            for i in range(4097)
        ]
        with pytest.raises(ValueError, match="4096"):
            derive_revocation_list(deployer_id="x", entries=entries,
                                   issued_at="2026-06-01T00:00:00+00:00")

    def test_find_entry_earliest_wins(self):
        # from_dict tolerates duplicates (defensive); earliest revoked_at wins.
        rl = RevocationList.from_dict({
            "deployer_id": "x",
            "entries": [
                {"key_id": "k1", "revoked_at": "2026-03-01T00:00:00+00:00", "reason": "superseded"},
                {"key_id": "k1", "revoked_at": "2026-01-01T00:00:00+00:00", "reason": "compromised"},
            ],
            "issued_at": "2026-06-01T00:00:00+00:00",
            "list_version": "1.0", "list_hash": "whatever",
        })
        assert rl.find_entry("k1").revoked_at == "2026-01-01T00:00:00+00:00"


# ===================================================================
# RV-2: verify_key_provenance check #6
# ===================================================================

class TestRevocationCheck:
    def test_not_checked_when_no_list(self, kit):
        _, _, manifest, cert = kit
        r = verify_key_provenance(cert, manifest)
        assert r.revocation_status == REVOCATION_NOT_CHECKED
        assert r.overall_valid is True

    def test_not_revoked_with_clean_list(self, kit):
        _, root_kp, manifest, cert = kit
        rl = derive_revocation_list(deployer_id="acme", entries=[],
            issued_at="2026-06-01T00:00:00+00:00",
            root_signing_callback=root_kp.sign, root_key_id="r")
        r = verify_key_provenance(cert, manifest,
            revocation_list=rl, root_public_key=root_kp.public_key)
        assert r.revocation_status == REVOCATION_NOT_REVOKED
        assert r.overall_valid is True

    def test_revoked_fails_overall(self, kit):
        kp, root_kp, manifest, cert = kit
        rl = derive_revocation_list(deployer_id="acme",
            entries=[{"key_id": kp.key_id,
                      "revoked_at": "2026-01-15T00:00:00+00:00",
                      "reason": "compromised"}],
            issued_at="2026-06-01T00:00:00+00:00",
            root_signing_callback=root_kp.sign, root_key_id="r")
        r = verify_key_provenance(cert, manifest,
            revocation_list=rl, root_public_key=root_kp.public_key)
        assert r.revocation_status == REVOCATION_REVOKED
        assert r.overall_valid is False
        assert any("revoked at" in n for n in r.notes)

    def test_cert_predates_revocation_stays_valid(self, kit):
        """X.509/OCSP semantics: certs from before the compromise window
        remain valid."""
        kp, _, manifest, cert = kit
        rl = derive_revocation_list(deployer_id="acme",
            entries=[{"key_id": kp.key_id,
                      "revoked_at": "2030-01-01T00:00:00+00:00",
                      "reason": "superseded"}],
            issued_at="2026-06-01T00:00:00+00:00")
        r = verify_key_provenance(cert, manifest, revocation_list=rl)
        assert r.revocation_status == REVOCATION_REVOKED_BUT_CERT_PREDATES
        assert r.overall_valid is True

    def test_tampered_list_is_list_invalid(self, kit):
        kp, _, manifest, cert = kit
        rl = derive_revocation_list(deployer_id="acme",
            entries=[{"key_id": kp.key_id,
                      "revoked_at": "2026-01-15T00:00:00+00:00",
                      "reason": "compromised"}],
            issued_at="2026-06-01T00:00:00+00:00")
        tampered = dataclasses.replace(rl, deployer_id="evil-corp")
        r = verify_key_provenance(cert, manifest, revocation_list=tampered)
        assert r.revocation_status == REVOCATION_LIST_INVALID
        assert r.overall_valid is False

    def test_deployer_mismatch_is_list_invalid(self, kit):
        """A valid list for a DIFFERENT deployer must not silently pass --
        a bad list is worse than no list."""
        _, _, manifest, cert = kit
        other = derive_revocation_list(deployer_id="other-corp", entries=[],
            issued_at="2026-06-01T00:00:00+00:00")
        r = verify_key_provenance(cert, manifest, revocation_list=other)
        assert r.revocation_status == REVOCATION_LIST_INVALID
        assert r.overall_valid is False

    def test_wrong_root_pk_on_list_is_list_invalid(self, kit):
        kp, root_kp, manifest, cert = kit
        wrong_root = DeploymentKeyPair.generate()
        rl = derive_revocation_list(deployer_id="acme", entries=[],
            issued_at="2026-06-01T00:00:00+00:00",
            root_signing_callback=root_kp.sign, root_key_id="r")
        r = verify_key_provenance(cert, manifest,
            revocation_list=rl, root_public_key=wrong_root.public_key)
        assert r.revocation_status == REVOCATION_LIST_INVALID

    def test_revocation_runs_standalone_without_manifest(self, kit):
        """A revoked key is a revoked key regardless of provenance status."""
        kp, _, _, cert = kit
        rl = derive_revocation_list(deployer_id="acme",
            entries=[{"key_id": kp.key_id,
                      "revoked_at": "2026-01-15T00:00:00+00:00",
                      "reason": "compromised"}],
            issued_at="2026-06-01T00:00:00+00:00")
        r = verify_key_provenance(cert, None, revocation_list=rl)
        assert r.revocation_status == REVOCATION_REVOKED
        assert r.overall_valid is False  # despite UNVERIFIED provenance

    def test_report_to_dict_includes_revocation_status(self, kit):
        _, _, manifest, cert = kit
        d = verify_key_provenance(cert, manifest).to_dict()
        assert d["revocation_status"] == REVOCATION_NOT_CHECKED


# ===================================================================
# RV-3: key_revoked advisory event + Shield own-key fail-hard
# ===================================================================

class TestKeyRevokedAdvisory:
    def test_record_key_revocation_writes_event(self, tmp_path):
        sh = Shield(config=ShieldConfig(
            audit_enabled=True, log_dir=str(tmp_path),
            compliance_mode="eu_ai_act_article12"))
        sh.record_key_revocation("old-key", "superseded",
                                 "2026-05-01T00:00:00+00:00")
        entries = []
        for f in sorted(tmp_path.glob("audit_*.jsonl")):
            for line in f.read_text(encoding="utf-8").splitlines():
                if line.strip():
                    entries.append(json.loads(line))
        ev = [e for e in entries if e["event_type"] == "key_revoked"]
        assert len(ev) == 1
        assert ev[0]["metadata"]["advisory"] is True
        assert ev[0]["metadata"]["reason"] == "superseded"

    def test_chain_verifies_with_key_revoked_event(self, tmp_path):
        sh = Shield(config=ShieldConfig(
            audit_enabled=True, log_dir=str(tmp_path),
            compliance_mode="eu_ai_act_article12"))
        sh.record_key_revocation("old-key", "compromised")
        sh.sanitize("a@b.com")
        r = Shield(config=ShieldConfig(
            audit_enabled=False, log_dir=str(tmp_path))).verify_audit()
        assert r["valid"] is True

    def test_rejects_bad_reason(self, tmp_path):
        sh = Shield(config=ShieldConfig(
            audit_enabled=True, log_dir=str(tmp_path)))
        with pytest.raises(ValueError, match="reason"):
            sh.record_key_revocation("k", "not-a-reason")


class TestShieldOwnKeyFailHard:
    def _write_list(self, tmp_path, key_id):
        rl = derive_revocation_list(deployer_id="acme",
            entries=[{"key_id": key_id,
                      "revoked_at": "2026-01-01T00:00:00+00:00",
                      "reason": "compromised"}],
            issued_at="2026-06-01T00:00:00+00:00")
        p = tmp_path / "revocations.json"
        p.write_text(json.dumps(rl.to_dict()), encoding="utf-8")
        return p

    def test_fail_hard_when_own_key_revoked(self, tmp_path):
        kp = DeploymentKeyPair.generate()
        p = self._write_list(tmp_path, kp.key_id)
        with pytest.raises(RuntimeError, match="REVOKED"):
            Shield(config=ShieldConfig(
                audit_enabled=True, log_dir=str(tmp_path / "audit"),
                attestation_key=kp, revocation_list_path=str(p)))

    def test_clean_key_passes(self, tmp_path):
        kp = DeploymentKeyPair.generate()
        p = self._write_list(tmp_path, "some-other-key")
        Shield(config=ShieldConfig(
            audit_enabled=True, log_dir=str(tmp_path / "audit"),
            attestation_key=kp, revocation_list_path=str(p)))

    def test_unreadable_list_fail_hard(self, tmp_path):
        """A deployer who configured revocation checking must not run blind."""
        kp = DeploymentKeyPair.generate()
        with pytest.raises(RuntimeError, match="could not be loaded"):
            Shield(config=ShieldConfig(
                audit_enabled=True, log_dir=str(tmp_path / "audit"),
                attestation_key=kp,
                revocation_list_path=str(tmp_path / "missing.json")))

    def test_error_messages_are_ascii(self, tmp_path):
        kp = DeploymentKeyPair.generate()
        p = self._write_list(tmp_path, kp.key_id)
        with pytest.raises(RuntimeError) as exc:
            Shield(config=ShieldConfig(
                audit_enabled=True, log_dir=str(tmp_path / "audit"),
                attestation_key=kp, revocation_list_path=str(p)))
        assert all(ord(c) < 128 for c in str(exc.value))


# ===================================================================
# RV-4: provenance_summary revocation fields
# ===================================================================

class TestRevocationSummaryInReport:
    def _shield(self, tmp_path):
        kp = DeploymentKeyPair.generate()
        sh = Shield(config=ShieldConfig(
            audit_enabled=True, log_dir=str(tmp_path),
            compliance_mode="eu_ai_act_article12",
            attestation_key=kp, deployer_id="acme",
            key_valid_from="2026-01-01T00:00:00+00:00",
            key_valid_until="2027-01-01T00:00:00+00:00"))
        sh.sanitize("a@b.com")
        sh.sanitize("c@d.com")
        return kp, sh

    def test_defaults_without_list(self, tmp_path):
        _, sh = self._shield(tmp_path)
        ps = sh.generate_compliance_report()["attestation"]["provenance_summary"]
        assert ps["revocation_checked"] is False
        assert ps["revoked_keys_found"] is None
        assert ps["certs_after_revocation"] is None
        # v0.8.1 KM-9 fields must coexist (the merge-fix regression guard)
        assert ps["manifests_found"] == 1

    def test_filled_with_revoked_key(self, tmp_path):
        kp, sh = self._shield(tmp_path)
        rl = derive_revocation_list(deployer_id="acme",
            entries=[{"key_id": kp.key_id,
                      "revoked_at": "2026-01-01T00:00:00+00:00",
                      "reason": "compromised"}],
            issued_at="2026-06-01T00:00:00+00:00")
        p = tmp_path / "rl.json"
        p.write_text(json.dumps(rl.to_dict()), encoding="utf-8")
        ps = sh.generate_compliance_report(
            revocation_list_path=str(p))["attestation"]["provenance_summary"]
        assert ps["revocation_checked"] is True
        assert ps["revoked_keys_found"] == 1
        assert ps["certs_after_revocation"] == 2

    def test_unloadable_list_raises(self, tmp_path):
        _, sh = self._shield(tmp_path)
        with pytest.raises(RuntimeError, match="could not be loaded"):
            sh.generate_compliance_report(
                revocation_list_path=str(tmp_path / "missing.json"))


# ===================================================================
# AUDIT-3 adversarial hardening
# ===================================================================

class TestRevocationAdversarialInputs:
    def test_from_dict_tolerates_garbage_entries(self):
        rl = RevocationList.from_dict({
            "deployer_id": "x",
            "entries": [42, "string", None, [], {"key_id": "ok",
                "revoked_at": "2026-01-01T00:00:00+00:00",
                "reason": "compromised"}],
            "issued_at": "t", "list_version": "1.0", "list_hash": "h",
        })
        # Only the one well-formed entry survives.
        assert len(rl.entries) == 1

    def test_derive_rejects_nul_in_deployer_id(self):
        with pytest.raises(ValueError, match="NUL"):
            derive_revocation_list(deployer_id="bad\x00", entries=[],
                                   issued_at="2026-06-01T00:00:00+00:00")

    def test_derive_rejects_non_list_entries(self):
        with pytest.raises(ValueError, match="list"):
            derive_revocation_list(deployer_id="x", entries="not-a-list",
                                   issued_at="2026-06-01T00:00:00+00:00")

    def test_unparseable_timestamps_on_listed_key_is_conservative_revoked(self, kit):
        """Listed key + garbage timestamps -> REVOKED (conservative)."""
        kp, _, manifest, cert = kit
        rl = RevocationList.from_dict({
            "deployer_id": "acme",
            "entries": [{"key_id": kp.key_id,
                         "revoked_at": "garbage", "reason": "compromised"}],
            "issued_at": "2026-06-01T00:00:00+00:00",
            "list_version": "1.0",
            "list_hash": "",  # recompute below
        })
        # Recompute a CONSISTENT hash so the integrity check passes and the
        # timestamp path is what's exercised.
        from cloakllm.attestation import _compute_revocation_list_hash
        good_hash = _compute_revocation_list_hash(
            deployer_id=rl.deployer_id,
            entries=[e.to_dict() for e in rl.entries],
            issued_at=rl.issued_at, list_version=rl.list_version,
            root_key_id=rl.root_key_id)
        rl = dataclasses.replace(rl, list_hash=good_hash)
        r = verify_key_provenance(cert, manifest, revocation_list=rl)
        assert r.revocation_status == REVOCATION_REVOKED
        assert r.overall_valid is False
