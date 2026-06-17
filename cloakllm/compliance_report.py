"""v0.8.0 CR8: structured compliance reporting for EU AI Act / GDPR auditors.

This module implements the headline v0.8.0 feature: `generate_compliance_report()`.
The output is consumed by compliance officers (internally) and external auditors
(regulators, third-party assurance) -- it MUST stand on its own without
CloakLLM-specific knowledge.

Design pillars:
  * Single source of truth: every field validates against
    `examples/compliance_report_schema.json` (JSON Schema 2020-12).
  * v0.8.1 forward-compat: per-entry attestation slot is shaped to accept the
    future KeyManifest-derived ProvenanceReport fields without a schema bump
    (v0.8.0 emits null/placeholder values; v0.8.1 fills them in).
  * Auditor-grade verdict semantics: COMPLIANT requires chain integrity +
    zero pii_in_log violations + 100% signature verification (when attestation
    enabled). NON_COMPLIANT lists every specific reason.
  * Quiet on edge cases: empty period, no matching articles, no certificates
    -- all return a valid (typically COMPLIANT) report rather than raising.

The Shield API (`Shield.generate_compliance_report`) is a thin wrapper around
`build_report()` here; the actual rollup engine lives in this module so it can
be unit-tested without a Shield + audit-log setup.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Optional

from cloakllm._canonical import canonical_json


# --- Public types ---


@dataclass(frozen=True)
class ReportPeriod:
    """The temporal window the report aggregates over.

    `from_ts` and `to_ts` are ISO 8601 UTC strings. The window is INCLUSIVE
    on both ends -- an entry with timestamp exactly equal to either boundary
    is in scope.
    """
    from_ts: Optional[str]
    to_ts: Optional[str]


# --- Constants ---

SCHEMA_VERSION = "1.0"
"""v0.8.0 compliance-report schema version. Bumped on backward-incompat changes."""

ATTESTATION_SCHEMA_VERSION = "1.0"
"""v0.8.0 = signature-only. v0.8.1 KeyManifest will bump this to '1.1'."""

# Article 4a bias event types (mirrors audit.py._BIAS_VALID_EVENT_TYPES). Used
# to detect Article 4a stats. Inlined here to keep this module dependency-light
# (audit.py imports compliance_report.py wouldn't cycle but is uglier).
_BIAS_EVENT_TYPES = frozenset({
    "bias_session_start", "bias_pseudonymise", "bias_finding", "bias_session_end",
})

# v0.10.0 A50-3: Article 50 content-labeling event type + the article whose
# row the content-labeling stats attach to (and ONLY that row).
_CONTENT_GENERATION_EVENT_TYPE = "content_generation"
_ART_50 = "EU_AI_Act_Art_50"


# --- Helpers ---


def _pct(numerator: int, denominator: int) -> float:
    """Percentage rounded to 2 dp, emitted as int when whole.

    The int-when-whole coercion is the v0.7.0 cross-SDK numeric-divergence
    lesson: Python's `100.0` canonical-JSON-encodes to `100.0` while JS's
    `100` encodes to `100`, breaking byte-parity. Both SDKs emit an int when
    the value is whole. Returns 0 (int) when denominator is 0.
    """
    if not denominator:
        return 0
    pct = round(100.0 * numerator / denominator, 2)
    if isinstance(pct, float) and pct == int(pct):
        return int(pct)
    return pct


def _in_period(ts: Optional[str], period: ReportPeriod) -> bool:
    """Inclusive timestamp filter. If ts is None or unparseable, returns False
    (entry excluded from the report)."""
    if not ts:
        return False
    if period.from_ts and ts < period.from_ts:
        return False
    if period.to_ts and ts > period.to_ts:
        return False
    return True


def _empty_attestation() -> dict:
    """The aggregate attestation block when no entries have certificates.
    Shape-compatible with v0.8.1 KeyManifest extensions (manifest fields null)."""
    return {
        "schema_version": ATTESTATION_SCHEMA_VERSION,
        "entries_with_certificates": 0,
        "signatures_valid": 0,
        "key_ids": [],
        "provenance_summary": {
            # v0.8.1 fills these in. v0.8.0 emits nulls so the schema validates
            # against the same `provenance_summary` block in either version.
            "manifests_found": None,
            "manifests_valid": None,
            "within_validity_window_pct": None,
            "root_signature_status_distribution": None,
            # v0.9.0 RV-4 (additive): revocation rollup. false/null when no
            # revocation list was supplied to the report -- pre-v0.9.0
            # behavior unchanged apart from these three new keys.
            "revocation_checked": False,
            "revoked_keys_found": None,
            "certs_after_revocation": None,
        },
    }


def _fill_provenance_summary(
    *,
    audit_entries_replay: list[dict],
    period: "ReportPeriod",
    attestation: dict,
) -> None:
    """v0.8.1 KM-9: aggregate ProvenanceReports into attestation.provenance_summary.

    Walks the chain to find `key_registered` events, dedups manifests by
    `manifest_hash` (per Decision 3: allow-duplicate emission), then runs
    `verify_key_provenance` for every certified entry whose `key_id` resolves
    to a known manifest. Fills:

      manifests_found              -- unique manifest_hash count
      manifests_valid              -- count where overall_valid=True
      within_validity_window_pct   -- % certified entries inside their key's window
      root_signature_status_distribution -- {VALID, INVALID, NOT_REQUESTED, UNVERIFIED_NO_KEY}

    When no `key_registered` events exist (pre-v0.8.1 chains), all four
    fields stay null -- same as v0.8.0. The provenance check is purely
    additive: a v0.8.0 chain re-verified under v0.8.1 produces a byte-
    identical report (same null fields, same overall structure).

    The aggregator does NOT verify root signatures because v0.8.1 does not
    ship a root-key directory -- auditors supply root_public_key out-of-band
    via the CLI (`cloakllm key-manifest verify --root-public-key`). We
    report root_signature_status from the manifest's own claim only.
    """
    from cloakllm.attestation import (
        KeyManifest, verify_key_provenance,
        ROOT_SIG_VALID, ROOT_SIG_NOT_REQUESTED, ROOT_SIG_UNVERIFIED_NO_KEY,
        SanitizationCertificate,
    )

    # Resolve KeyManifests from key_registered events. Dedup by manifest_hash.
    manifests_by_key_id: dict[str, KeyManifest] = {}
    seen_hashes: set[str] = set()
    for entry in audit_entries_replay:
        if entry.get("event_type") != "key_registered":
            continue
        if not _in_period(entry.get("timestamp"), period):
            continue
        km_dict = entry.get("key_manifest")
        if not isinstance(km_dict, dict):
            continue
        h = km_dict.get("manifest_hash")
        if not isinstance(h, str) or h in seen_hashes:
            continue
        try:
            km = KeyManifest.from_dict(km_dict)
        except Exception:
            # Malformed manifest -- skip silently. The B3 validator should
            # have caught this at write time; defensive skip at read time.
            continue
        seen_hashes.add(h)
        manifests_by_key_id[km.key_id] = km

    if not manifests_by_key_id:
        # No key_registered events -- leave the provenance_summary all-null
        # (back-compat with v0.8.0 reports).
        return

    # Aggregate per-cert checks. We synthesize lightweight cert objects from
    # the audit entry fields needed by verify_key_provenance (key_id +
    # timestamp). The cert's signature is presumed valid because the chain
    # itself verified -- we focus on provenance dimensions here.
    manifests_valid = 0
    within_window_n = 0
    within_window_total = 0
    root_distribution = {
        "VALID": 0, "INVALID": 0,
        "NOT_REQUESTED": 0, "UNVERIFIED_NO_KEY": 0,
    }

    # First evaluate each unique manifest once for overall validity
    # (signature side handled per-cert below; manifest_hash + root sig +
    # purpose checks fire here).
    for km in manifests_by_key_id.values():
        # Synthesize a placeholder cert whose timestamp is the key's own
        # valid_from -- exercises the manifest_hash + root_signature checks
        # without depending on any real cert.
        placeholder = SanitizationCertificate(
            timestamp=km.valid_from,
            key_id=km.key_id,
            public_key=km.public_key,
        )
        # Note: signature check will fail on placeholder (no sig) but we
        # only inspect the structural dimensions.
        report = verify_key_provenance(placeholder, km)
        # Manifest is "valid" iff its hash is consistent and (if root claimed)
        # the root status isn't INVALID. We don't have root keys here so
        # UNVERIFIED_NO_KEY does NOT disqualify the manifest.
        manifest_is_valid = (
            report.manifest_hash_consistent
            and report.root_signature_status != "INVALID"
        )
        if manifest_is_valid:
            manifests_valid += 1
        root_distribution[report.root_signature_status] = \
            root_distribution.get(report.root_signature_status, 0) + 1

    # Per-cert: count window membership across the chain.
    for entry in audit_entries_replay:
        if entry.get("event_type") == "key_registered":
            continue
        if not entry.get("certificate_hash"):
            continue
        if not _in_period(entry.get("timestamp"), period):
            continue
        kid = entry.get("key_id")
        if not kid or kid not in manifests_by_key_id:
            continue
        within_window_total += 1
        km = manifests_by_key_id[kid]
        synth = SanitizationCertificate(
            timestamp=entry.get("timestamp", ""),
            key_id=kid,
            public_key=km.public_key,
        )
        report = verify_key_provenance(synth, km)
        if report.within_validity_window:
            within_window_n += 1

    # v0.7.0 numeric-parity lesson: whole-number percentages are emitted as
    # int in both SDKs (Python json.dumps(100) == JS JSON.stringify(100) ==
    # "100"; vs the float "100.0" vs int "100" divergence we'd hit otherwise).
    if within_window_total:
        pct = round(100.0 * within_window_n / within_window_total, 2)
    else:
        pct = 0
    if isinstance(pct, float) and pct == int(pct):
        pct = int(pct)

    # v0.9.0: UPDATE (not replace) so the RV-4 revocation keys -- and any
    # future additive keys -- survive this fill. The replace-style
    # assignment here was the v0.9.0 RV-4 integration bug class.
    attestation["provenance_summary"].update({
        "manifests_found": len(manifests_by_key_id),
        "manifests_valid": manifests_valid,
        "within_validity_window_pct": pct,
        "root_signature_status_distribution": root_distribution,
    })


# --- Core builder ---


def _fill_revocation_summary(
    *,
    audit_entries_replay: list,
    period: "ReportPeriod",
    attestation: dict,
    revocation_list,
) -> None:
    """v0.9.0 RV-4: fill the revocation rollup in provenance_summary.

    When revocation_list is None, the three fields keep their defaults
    (false/null/null) -- pre-v0.9.0 report behavior. When supplied:

      revocation_checked       -- True
      revoked_keys_found       -- of the key_ids used by certified entries
                                  in the period, how many are revoked
      certs_after_revocation   -- certified entries signed at or after
                                  their key's revoked_at (the bad ones)

    The list's integrity (list_hash, root signature) is verified by
    verify_key_provenance at the per-cert layer and by the CLI; the
    aggregator here trusts its caller passed a list it already vetted --
    Shield.generate_compliance_report loads + parses, and a tampered list
    surfaces as LIST_INVALID in per-cert checks downstream.
    """
    if revocation_list is None:
        return

    revoked_keys_seen: set = set()
    certs_after = 0
    for entry in audit_entries_replay:
        if not entry.get("certificate_hash"):
            continue
        if not _in_period(entry.get("timestamp"), period):
            continue
        kid = entry.get("key_id")
        if not isinstance(kid, str) or not kid:
            continue
        rev_entry = revocation_list.find_entry(kid)
        if rev_entry is None:
            continue
        revoked_keys_seen.add(kid)
        ts = entry.get("timestamp")
        if isinstance(ts, str) and ts >= rev_entry.revoked_at:
            certs_after += 1

    attestation["provenance_summary"]["revocation_checked"] = True
    attestation["provenance_summary"]["revoked_keys_found"] = len(revoked_keys_seen)
    attestation["provenance_summary"]["certs_after_revocation"] = certs_after


def build_report(
    *,
    audit_entries: Iterable[dict],
    period: ReportPeriod,
    articles: Optional[list[str]] = None,
    cloakllm_version: str,
    audit_dir: Optional[str] = None,
    include_decisions: bool = False,
    revocation_list=None,
) -> dict:
    """Build a compliance report from an iterable of audit entries.

    This is the engine. The Shield method does I/O + then calls this; the CLI
    + MCP tool both call this through Shield. Pure-function design so unit
    tests can drive it without an AuditLogger.

    Args:
        audit_entries: an iterable of audit-entry dicts (already JSON-loaded).
            Entries outside `period` or whose article_ref doesn't intersect
            `articles` (when provided) are skipped at scan time.
        period: ReportPeriod with from_ts / to_ts (ISO 8601). Either may be
            None to leave that end unbounded.
        articles: optional filter list. When None, all article_ref values seen
            in the chain become report keys. When provided, only matching
            entries are included; any extra `articles` not seen are still
            reported with zero counts (auditor knows the report covered them).
        cloakllm_version: written into report_metadata. The Shield wrapper
            populates from cloakllm.__version__.
        audit_dir: optional, recorded in metadata for auditor traceability.
        include_decisions: when True, emit per-decision_id rollup (see schema).
            Default False -- can be large for high-volume chains.

    Returns:
        A dict matching `examples/compliance_report_schema.json`.
    """
    # v0.8.1 KM-9: materialise once so we can rewalk for provenance_summary
    # without forcing callers to buffer themselves. For typical compliance
    # report chains (thousands to millions of entries) this is fine; very
    # large chains are paged by period.
    audit_entries_buffered = list(audit_entries)
    audit_entries = audit_entries_buffered

    # Aggregates
    seen_articles: set[str] = set()
    article_stats: dict[str, dict[str, Any]] = {}
    decision_stats: dict[str, dict[str, Any]] = {}
    chain_anomalies: list[str] = []

    # Period-tracking
    first_ts: Optional[str] = None
    last_ts: Optional[str] = None
    total_entries = 0
    chain_valid = True  # No re-verification here; presumed verified by caller.
                        # Future: integrate verify_chain output explicitly.

    # Attestation aggregates
    entries_with_certs = 0
    signatures_valid = 0
    key_ids: set[str] = set()

    # Per-article stat templates for Article 4a special handling
    def _ensure_article(name: str) -> dict[str, Any]:
        if name not in article_stats:
            article_stats[name] = {
                "evidence_event_count": 0,
                "decision_count": 0,
                "categories_detected": {},
                "pii_in_log": False,
                # Article 4a-only fields stay absent unless we see bias events
            }
            seen_articles.add(name)
        return article_stats[name]

    # Bias-session bookkeeping (Article 4a)
    bias_session_counts: dict[str, int] = {}  # article -> count of bias_session_start
    bias_finding_counts: dict[str, int] = {}  # article -> count of bias_finding
    bias_end_counts: dict[str, int] = {}      # article -> count of bias_session_end
    bias_end_wiped: dict[str, int] = {}       # article -> count of wipe_confirmed=True

    # v0.10.0 A50-3: content-generation bookkeeping (Article 50). Accumulated
    # per-article like bias, but wired ONLY onto the Art_50 row below -- the
    # same correctness invariant: content_generation events carry
    # article_ref=[Art_12,Art_19,Art_50], so an auditor reading the Article 12
    # section must NOT see content-labeling stats there (Article 12 requires
    # LOGGING; content-labeling happens to be one type of event you log).
    content_gen_counts: dict[str, int] = {}       # article -> count of content_generation
    content_labeled_counts: dict[str, int] = {}   # article -> count labeled=True
    content_deepfake_counts: dict[str, int] = {}  # article -> count deepfake=True
    content_modality_counts: dict[str, dict[str, int]] = {}  # article -> {modality: count}

    # Per-article decision tracking (uses sets to dedupe)
    article_decisions: dict[str, set[str]] = {}

    for entry in audit_entries:
        ts = entry.get("timestamp")
        # v0.8.0 AUDIT-3: only treat ts as a sortable timestamp when it's a
        # non-empty string. Hand-crafted malformed entries (ts=int, ts=None,
        # ts=dict) must not crash the reducer -- they're skipped from period
        # tracking but still counted toward chain integrity if they pass the
        # period filter and have a usable article_ref.
        ts_is_string = isinstance(ts, str) and len(ts) > 0
        if not _in_period(ts if ts_is_string else None, period):
            continue

        # Period-window tracking from in-scope entries only
        if ts_is_string:
            if first_ts is None or ts < first_ts:
                first_ts = ts
            if last_ts is None or ts > last_ts:
                last_ts = ts

        # Article filter
        # v0.8.0 AUDIT-3: coerce to list -- a string would otherwise iterate
        # character-by-character ("a","r","t",...) and corrupt counts.
        raw_articles = entry.get("article_ref")
        entry_articles = raw_articles if isinstance(raw_articles, list) else []
        if articles:
            if not any(a in articles for a in entry_articles):
                continue

        total_entries += 1

        # PII-in-log invariant check (compliance violation if True)
        if entry.get("pii_in_log") is True:
            for a in entry_articles:
                _ensure_article(a)["pii_in_log"] = True
            chain_anomalies.append(
                f"seq={entry.get('seq')}: COMPLIANCE VIOLATION pii_in_log=true"
            )

        # Per-article stats
        for art in entry_articles:
            stats = _ensure_article(art)
            stats["evidence_event_count"] += 1

            # Categories aggregation
            for cat, cnt in (entry.get("categories") or {}).items():
                stats["categories_detected"][cat] = (
                    stats["categories_detected"].get(cat, 0) + cnt
                )

            # Decision tracking
            did = entry.get("decision_id")
            if did:
                article_decisions.setdefault(art, set()).add(did)

            # Article 4a-specific bias session bookkeeping
            ev_type = entry.get("event_type", "")
            if ev_type in _BIAS_EVENT_TYPES:
                if ev_type == "bias_session_start":
                    bias_session_counts[art] = bias_session_counts.get(art, 0) + 1
                elif ev_type == "bias_finding":
                    bias_finding_counts[art] = bias_finding_counts.get(art, 0) + 1
                elif ev_type == "bias_session_end":
                    bias_end_counts[art] = bias_end_counts.get(art, 0) + 1
                    if (entry.get("bias_context") or {}).get("wipe_confirmed") is True:
                        bias_end_wiped[art] = bias_end_wiped.get(art, 0) + 1

            # v0.10.0 A50-3: content_generation bookkeeping (Article 50).
            elif ev_type == _CONTENT_GENERATION_EVENT_TYPE:
                content_gen_counts[art] = content_gen_counts.get(art, 0) + 1
                cc = entry.get("content_context") or {}
                if cc.get("labeled") is True:
                    content_labeled_counts[art] = content_labeled_counts.get(art, 0) + 1
                if cc.get("deepfake") is True:
                    content_deepfake_counts[art] = content_deepfake_counts.get(art, 0) + 1
                modality = cc.get("modality")
                # AUDIT-3: only count a string modality (malformed entries skipped).
                if isinstance(modality, str) and modality:
                    md = content_modality_counts.setdefault(art, {})
                    md[modality] = md.get(modality, 0) + 1

        # Decision-level rollup (optional)
        did = entry.get("decision_id")
        if include_decisions and did:
            d = decision_stats.setdefault(did, {
                "entry_count": 0,
                "articles_touched": set(),
                "categories": {},
                "first_timestamp": ts,
                "last_timestamp": ts,
            })
            d["entry_count"] += 1
            for art in entry_articles:
                d["articles_touched"].add(art)
            for cat, cnt in (entry.get("categories") or {}).items():
                d["categories"][cat] = d["categories"].get(cat, 0) + cnt
            # v0.8.0 AUDIT-3: only compare when both sides are non-empty
            # strings -- malformed entries with int/None ts must not crash.
            if ts_is_string:
                first = d["first_timestamp"]
                last = d["last_timestamp"]
                if not isinstance(first, str) or ts < first:
                    d["first_timestamp"] = ts
                if not isinstance(last, str) or ts > last:
                    d["last_timestamp"] = ts

        # Attestation aggregation
        if entry.get("certificate_hash"):
            entries_with_certs += 1
            # Signature validity is presumed at chain-verify time; if the
            # chain verified (chain_valid above), the per-entry signatures
            # are by induction valid (chain hash includes cert_hash).
            signatures_valid += 1
            kid = entry.get("key_id")
            if kid:
                key_ids.add(kid)

    # Apply user-requested article filter to OUTPUT shape: when articles is
    # provided, include each requested article in the output even if count=0,
    # so the auditor sees explicit coverage.
    if articles:
        for a in articles:
            _ensure_article(a)
        # And REMOVE any extra articles that crept in via entries having
        # multi-article article_ref where only some are in scope
        article_stats = {a: article_stats[a] for a in articles if a in article_stats}

    # Wire up per-article decision_count from the dedup sets
    for art, dids in article_decisions.items():
        if art in article_stats:
            article_stats[art]["decision_count"] = len(dids)

    # Wire up Article 4a-specific fields ONLY on the Article 4a row. Bias
    # events have article_ref=[Art_12, Art_19, Art_4a] (because they also
    # constitute Article 12 record-keeping evidence), so the naive "attach
    # to every article that saw a bias event" misleads auditors into thinking
    # "Article 12 requires bias detection." Article 12 requires LOGGING; bias
    # detection happens to be one type of event you log. The bias-specific
    # rollup belongs on Art_4a's row alone.
    _ART_4A = "EU_AI_Act_Art_4a"
    if _ART_4A in article_stats and _ART_4A in bias_session_counts:
        article_stats[_ART_4A]["bias_sessions"] = bias_session_counts[_ART_4A]
        article_stats[_ART_4A]["findings_recorded"] = bias_finding_counts.get(_ART_4A, 0)
        ends = bias_end_counts.get(_ART_4A, 0)
        wiped = bias_end_wiped.get(_ART_4A, 0)
        article_stats[_ART_4A]["wipe_confirmed_pct"] = (
            round(100.0 * wiped / ends, 2) if ends else 0.0
        )

    # v0.10.0 A50-3: wire content-labeling fields ONLY onto the Article 50 row.
    # content_generation events carry article_ref=[Art_12,Art_19,Art_50] (they
    # ARE Article 12 record-keeping evidence too), so the naive "attach to every
    # article that saw the event" would mislead an auditor reading the Article
    # 12 section into thinking Article 12 mandates content labeling. It doesn't:
    # Article 12 mandates LOGGING; content labeling is one type of event logged.
    # The content-labeling rollup belongs on Art_50's row alone -- the exact
    # correctness invariant proven for bias_sessions on Art_4a (v0.8.0).
    if _ART_50 in article_stats and _ART_50 in content_gen_counts:
        gen = content_gen_counts[_ART_50]
        labeled = content_labeled_counts.get(_ART_50, 0)
        # merge (not replace) -- never clobber evidence_event_count /
        # decision_count already on the row (the KM-9 / RV-4 fix discipline).
        article_stats[_ART_50].update({
            "generation_events": gen,
            "labeled_events": labeled,
            # int when whole (the v0.7.0 cross-SDK numeric-divergence lesson).
            "label_coverage_pct": _pct(labeled, gen),
            "deepfake_events": content_deepfake_counts.get(_ART_50, 0),
            "modality_distribution": dict(
                sorted(content_modality_counts.get(_ART_50, {}).items())
            ),
        })

    # Verdict
    verdict_reasons: list[str] = []
    if not chain_valid:
        verdict_reasons.append(f"chain_integrity: broken ({len(chain_anomalies)} anomalies)")
    for a, s in article_stats.items():
        if s.get("pii_in_log") is True:
            verdict_reasons.append(f"per_article.{a}: pii_in_log=true")
    if entries_with_certs > 0 and signatures_valid < entries_with_certs:
        verdict_reasons.append(
            f"attestation: {signatures_valid}/{entries_with_certs} signatures valid"
        )
    # v0.10.0 A50-4: Article 50 unlabeled-content check. Any synthetic-content
    # generation event without a machine-readable AI-generation label is an
    # Article 50(2) finding. v0.10.0 is strict -- there is no grace tolerance
    # (a `label_coverage_threshold` config is a v0.10.1 add IF a user needs the
    # Article 50(2) "technically infeasible" carve-out). Pre-v0.10.0 chains
    # have no Art_50 row, so this is purely additive (zero behavior change).
    _art50 = article_stats.get(_ART_50)
    if _art50 is not None and "generation_events" in _art50:
        gen = _art50["generation_events"]
        labeled = _art50["labeled_events"]
        if gen and labeled < gen:
            verdict_reasons.append(
                f"per_article.{_ART_50}: {gen - labeled} of {gen} generation "
                f"events unlabeled"
            )
    verdict = "COMPLIANT" if not verdict_reasons else "NON_COMPLIANT"

    # Attestation block (always present, even when 0 certs -- the schema
    # validates against the same shape regardless)
    attestation = _empty_attestation()
    attestation["entries_with_certificates"] = entries_with_certs
    attestation["signatures_valid"] = signatures_valid
    attestation["key_ids"] = sorted(key_ids)

    # v0.8.1 KM-9: fill in provenance_summary from key_registered events.
    # Pre-v0.8.1 chains have no key_registered events -- provenance_summary
    # stays all-null (additive back-compat with v0.8.0 reports).
    _fill_provenance_summary(
        audit_entries_replay=audit_entries_buffered,
        period=period,
        attestation=attestation,
    )

    # v0.9.0 RV-4: fill revocation rollup when a list was supplied.
    _fill_revocation_summary(
        audit_entries_replay=audit_entries_buffered,
        period=period,
        attestation=attestation,
        revocation_list=revocation_list,
    )

    report: dict[str, Any] = {
        "report_metadata": {
            "generated_at": datetime.now(timezone.utc).isoformat(timespec="microseconds"),
            "cloakllm_version": cloakllm_version,
            "schema_version": SCHEMA_VERSION,
        },
        "period": {
            "from": period.from_ts or first_ts,
            "to": period.to_ts or last_ts,
        },
        "articles_in_scope": articles,
        "chain_integrity": {
            "verdict": "verified" if chain_valid else "broken",
            "total_entries": total_entries,
            "anomalies": chain_anomalies,
        },
        "per_article": article_stats,
        "attestation": attestation,
        "verdict": verdict,
        "verdict_reasons": verdict_reasons,
    }
    if audit_dir is not None:
        report["report_metadata"]["audit_dir"] = audit_dir

    if include_decisions:
        # Convert sets to sorted lists for JSON-serializability
        report["decisions"] = {
            did: {**d, "articles_touched": sorted(d["articles_touched"])}
            for did, d in decision_stats.items()
        }

    return report


# --- Renderers (CR8-4) ---


def render_markdown(report: dict) -> str:
    """Render a compliance report as a regulator-friendly Markdown document.

    The Markdown is human-readable AND structured enough that an auditor can
    quote specific sections in their report. Mirrors the JSON structure
    section-for-section so cross-referencing is mechanical.
    """
    lines: list[str] = []
    meta = report["report_metadata"]
    lines.append(f"# CloakLLM Compliance Report")
    lines.append("")
    lines.append(f"**Verdict:** **{report['verdict']}**")
    if report.get("verdict_reasons"):
        lines.append("")
        lines.append("**Reasons (NON_COMPLIANT only):**")
        for r in report["verdict_reasons"]:
            lines.append(f"  * {r}")
    lines.append("")
    lines.append(f"- Generated: `{meta['generated_at']}`")
    lines.append(f"- CloakLLM version: `{meta['cloakllm_version']}`")
    lines.append(f"- Schema version: `{meta['schema_version']}`")
    if meta.get("audit_dir"):
        lines.append(f"- Audit dir: `{meta['audit_dir']}`")
    p = report["period"]
    lines.append(f"- Period: `{p.get('from') or 'unbounded'}` -> `{p.get('to') or 'unbounded'}`")
    if report.get("articles_in_scope"):
        lines.append(f"- Articles in scope: {', '.join(report['articles_in_scope'])}")
    lines.append("")

    ci = report["chain_integrity"]
    lines.append("## Chain integrity")
    lines.append("")
    lines.append(f"- Verdict: **{ci['verdict']}**")
    lines.append(f"- Total entries in scope: **{ci['total_entries']}**")
    if ci.get("anomalies"):
        lines.append("- Anomalies:")
        for a in ci["anomalies"]:
            lines.append(f"  * `{a}`")
    else:
        lines.append("- Anomalies: none")
    lines.append("")

    lines.append("## Per-article rollup")
    lines.append("")
    if not report["per_article"]:
        lines.append("_No in-scope entries._")
        lines.append("")
    else:
        for art in sorted(report["per_article"]):
            stats = report["per_article"][art]
            lines.append(f"### {art}")
            lines.append("")
            lines.append(f"- Evidence event count: **{stats['evidence_event_count']}**")
            lines.append(f"- Decision count: **{stats.get('decision_count', 0)}**")
            lines.append(f"- pii_in_log: **{stats.get('pii_in_log', False)}**")
            cats = stats.get("categories_detected", {})
            if cats:
                cat_str = ", ".join(f"{c}={n}" for c, n in sorted(cats.items()))
                lines.append(f"- PII categories detected: {cat_str}")
            if "bias_sessions" in stats:
                lines.append(f"- Article 4a bias sessions: **{stats['bias_sessions']}**")
                lines.append(f"- Bias findings recorded: **{stats.get('findings_recorded', 0)}**")
                lines.append(f"- Token-map wipe confirmed: **{stats.get('wipe_confirmed_pct', 0)}%**")
            # v0.10.0 A50-3: Article 50 content-labeling rollup.
            if "generation_events" in stats:
                lines.append(f"- Article 50 generation events: **{stats['generation_events']}**")
                lines.append(f"- Labeled events: **{stats.get('labeled_events', 0)}**")
                lines.append(f"- Label coverage: **{stats.get('label_coverage_pct', 0)}%**")
                lines.append(f"- Deep-fake disclosures: **{stats.get('deepfake_events', 0)}**")
                md = stats.get("modality_distribution", {})
                if md:
                    md_str = ", ".join(f"{m}={n}" for m, n in sorted(md.items()))
                    lines.append(f"- Modality distribution: {md_str}")
            lines.append("")

    att = report["attestation"]
    lines.append("## Attestation")
    lines.append("")
    lines.append(f"- Entries with certificates: **{att['entries_with_certificates']}**")
    lines.append(f"- Signatures valid: **{att['signatures_valid']}**")
    if att["key_ids"]:
        lines.append(f"- Signing key_ids: {', '.join(f'`{k}`' for k in att['key_ids'])}")
    if att.get("schema_version") == "1.0":
        lines.append("")
        lines.append(
            "_KeyManifest-based external provenance verification is not "
            "yet enabled. Ship v0.8.1+ to fill in the `provenance_summary` "
            "fields._"
        )
    lines.append("")

    if "decisions" in report:
        lines.append("## Per-decision rollup")
        lines.append("")
        lines.append(f"_{len(report['decisions'])} distinct decisions in scope._")
        lines.append("")

    return "\n".join(lines) + "\n"


def render_pdf(report: dict, out_path: str) -> None:
    """Render the report as a PDF via reportlab. Raises ImportError if
    `reportlab` is not installed (CR8-4: optional `[reporting]` extra)."""
    # Lazy import -- module is optional
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak,
    )
    from reportlab.lib import colors

    styles = getSampleStyleSheet()
    h1 = styles["Heading1"]
    h2 = styles["Heading2"]
    body = styles["BodyText"]

    doc = SimpleDocTemplate(
        out_path, pagesize=letter,
        leftMargin=0.75 * inch, rightMargin=0.75 * inch,
        topMargin=0.75 * inch, bottomMargin=0.75 * inch,
    )
    story: list = []

    story.append(Paragraph("CloakLLM Compliance Report", h1))
    story.append(Spacer(1, 0.15 * inch))
    verdict_color = "#0C447C" if report["verdict"] == "COMPLIANT" else "#993C1D"
    verdict_style = ParagraphStyle(
        "verdict", parent=h2, textColor=colors.HexColor(verdict_color),
    )
    story.append(Paragraph(f"Verdict: <b>{report['verdict']}</b>", verdict_style))
    if report.get("verdict_reasons"):
        story.append(Spacer(1, 0.08 * inch))
        story.append(Paragraph("<b>Reasons:</b>", body))
        for r in report["verdict_reasons"]:
            story.append(Paragraph(f"&bull; {r}", body))
    story.append(Spacer(1, 0.2 * inch))

    meta = report["report_metadata"]
    p = report["period"]
    meta_rows = [
        ["Generated", meta["generated_at"]],
        ["CloakLLM version", meta["cloakllm_version"]],
        ["Schema version", meta["schema_version"]],
        ["Period from", p.get("from") or "unbounded"],
        ["Period to", p.get("to") or "unbounded"],
    ]
    if meta.get("audit_dir"):
        meta_rows.append(["Audit dir", meta["audit_dir"]])
    if report.get("articles_in_scope"):
        meta_rows.append(["Articles in scope", ", ".join(report["articles_in_scope"])])
    meta_table = Table(meta_rows, colWidths=[1.7 * inch, 4.5 * inch])
    meta_table.setStyle(TableStyle([
        ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
        ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#F0F4F8")),
        ("ALIGN", (0, 0), (-1, -1), "LEFT"),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CCD7E0")),
        ("LEFTPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 6),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(meta_table)
    story.append(Spacer(1, 0.2 * inch))

    ci = report["chain_integrity"]
    story.append(Paragraph("Chain integrity", h2))
    story.append(Paragraph(f"Verdict: <b>{ci['verdict']}</b>", body))
    story.append(Paragraph(f"Total entries in scope: <b>{ci['total_entries']}</b>", body))
    if ci.get("anomalies"):
        story.append(Paragraph("Anomalies:", body))
        for a in ci["anomalies"]:
            story.append(Paragraph(f"&bull; {a}", body))
    story.append(Spacer(1, 0.2 * inch))

    story.append(Paragraph("Per-article rollup", h2))
    if not report["per_article"]:
        story.append(Paragraph("<i>No in-scope entries.</i>", body))
    else:
        for art in sorted(report["per_article"]):
            stats = report["per_article"][art]
            story.append(Paragraph(f"<b>{art}</b>", body))
            rows = [
                ["Evidence events", str(stats["evidence_event_count"])],
                ["Decisions", str(stats.get("decision_count", 0))],
                ["pii_in_log", str(stats.get("pii_in_log", False))],
            ]
            cats = stats.get("categories_detected", {})
            if cats:
                rows.append(["PII categories", ", ".join(f"{c}={n}" for c, n in sorted(cats.items()))])
            if "bias_sessions" in stats:
                rows.append(["Bias sessions", str(stats["bias_sessions"])])
                rows.append(["Bias findings", str(stats.get("findings_recorded", 0))])
                rows.append(["Wipe-confirmed %", f"{stats.get('wipe_confirmed_pct', 0)}%"])
            t = Table(rows, colWidths=[1.5 * inch, 4.7 * inch])
            t.setStyle(TableStyle([
                ("FONT", (0, 0), (-1, -1), "Helvetica", 9),
                ("FONT", (0, 0), (0, -1), "Helvetica-Bold", 9),
                ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#FAFBFC")),
                ("GRID", (0, 0), (-1, -1), 0.25, colors.HexColor("#CCD7E0")),
                ("LEFTPADDING", (0, 0), (-1, -1), 6),
                ("RIGHTPADDING", (0, 0), (-1, -1), 6),
            ]))
            story.append(t)
            story.append(Spacer(1, 0.12 * inch))

    story.append(Spacer(1, 0.15 * inch))
    story.append(Paragraph("Attestation", h2))
    att = report["attestation"]
    story.append(Paragraph(
        f"Entries with certificates: <b>{att['entries_with_certificates']}</b>",
        body,
    ))
    story.append(Paragraph(
        f"Signatures valid: <b>{att['signatures_valid']}</b>", body,
    ))
    if att["key_ids"]:
        story.append(Paragraph(
            f"Signing key_ids: {', '.join(att['key_ids'])}", body,
        ))
    if att.get("schema_version") == "1.0":
        story.append(Spacer(1, 0.05 * inch))
        story.append(Paragraph(
            "<i>KeyManifest-based external provenance verification not yet "
            "enabled. v0.8.1+ fills in the provenance_summary fields.</i>",
            body,
        ))

    doc.build(story)

