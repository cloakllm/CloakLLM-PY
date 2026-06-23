"""
CloakLLM CLI.

Usage:
    python -m cloakllm scan "Send email to john@acme.com, SSN 123-45-6789"
    python -m cloakllm verify ./cloakllm_audit/
    python -m cloakllm stats ./cloakllm_audit/
"""

import argparse
import json
import sys
from pathlib import Path


def _warn_if_outside_cwd(dir_path: str) -> None:
    resolved = Path(dir_path).resolve()
    cwd = Path.cwd().resolve()
    try:
        resolved.relative_to(cwd)
    except ValueError:
        print(f"Warning: Log directory '{resolved}' is outside the current working directory.",
              file=sys.stderr)


def cmd_scan(args):
    """Scan text for sensitive data and show what would be sanitized."""
    from cloakllm import Shield, ShieldConfig

    config = ShieldConfig(audit_enabled=False)
    shield = Shield(config)

    text = args.text
    if text == "-":
        text = sys.stdin.read()

    show_pii = getattr(args, "show_pii", False)

    # Analyze
    analysis = shield.analyze(text, redact_values=not show_pii)

    if not analysis["entities"]:
        print("[OK] No sensitive entities detected.")
        return

    print(f"[!] Found {analysis['entity_count']} sensitive entities:\n")

    for ent in analysis["entities"]:
        display = ent['text'] if show_pii else "***"
        print(f"  [{ent['category']}] \"{display}\"")
        print(f"    Position: {ent['start']}-{ent['end']} | "
              f"Confidence: {ent['confidence']:.0%} | Source: {ent['source']}")

    # Show sanitized version
    sanitized, token_map = shield.sanitize(text)
    print(f"\n{'-' * 60}")
    if show_pii:
        print(f"ORIGINAL:  {text}")
    else:
        print(f"ORIGINAL:  [use --show-pii to display]")
    print(f"SANITIZED: {sanitized}")
    print(f"{'-' * 60}")
    print(f"\nToken map ({token_map.entity_count} entities):")
    for token, original in token_map.reverse.items():
        display = original if show_pii else "***"
        print(f"  {token} -> \"{display}\"")

    # Context risk analysis (opt-in)
    if getattr(args, "context_risk", False):
        risk = shield.analyze_context_risk(sanitized)
        print(f"\n{'-' * 60}")
        print(f"CONTEXT RISK: {risk['risk_level'].upper()} (score: {risk['risk_score']:.3f})")
        print(f"  Token density: {risk['token_density']:.3f}")
        print(f"  Identifying descriptors: {risk['identifying_descriptors']}")
        print(f"  Relationship edges: {risk['relationship_edges']}")
        if risk["warnings"]:
            print(f"  Warnings:")
            for w in risk["warnings"]:
                print(f"    * {w}")


def cmd_verify(args):
    """Verify audit log chain integrity."""
    from cloakllm import ShieldConfig
    from cloakllm.audit import AuditLogger

    _warn_if_outside_cwd(args.log_dir)
    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        print(f"[ERROR] Log directory not found: {log_dir}")
        sys.exit(1)

    config = ShieldConfig(log_dir=log_dir)
    logger = AuditLogger(config)

    output_format = getattr(args, "format", None)
    # v0.9.0 LC-1: --legacy-canonical-json flag removed (sunset completed).

    if output_format == "compliance_report":
        report = logger.verify_chain(output_format="compliance_report")
        print(json.dumps(report, indent=2))
        if report["verdict"] != "COMPLIANT":
            sys.exit(1)
        return

    print(f"Verifying audit chain in {log_dir}...")
    is_valid, errors, final_seq = logger.verify_chain()

    # v0.7.0 AUDIT-11: ASCII-only output. Em-dash + emoji crash CLI output on
    # Windows non-UTF-8 console codepages (cp1255 Hebrew, cp932 Japanese, etc.).
    if is_valid:
        print("[OK] Audit chain integrity verified -- no tampering detected.")
    else:
        print(f"[FAIL] CHAIN INTEGRITY FAILURE -- {len(errors)} error(s):\n")
        for err in errors:
            print(f"  * {err}")
        sys.exit(1)


def cmd_stats(args):
    """Show audit log statistics."""
    from cloakllm import ShieldConfig
    from cloakllm.audit import AuditLogger

    _warn_if_outside_cwd(args.log_dir)
    log_dir = Path(args.log_dir)
    config = ShieldConfig(log_dir=log_dir)
    logger = AuditLogger(config)

    stats = logger.get_stats()
    print(json.dumps(stats, indent=2))


def cmd_compliance_report(args):
    """v0.8.0 CR8-6: Generate a regulatory-output compliance report.

    Exit codes: 0 = COMPLIANT, 1 = NON_COMPLIANT (CI-friendly so deployers
    can gate releases on `cloakllm compliance-report ...`).
    """
    from cloakllm import Shield, ShieldConfig

    _warn_if_outside_cwd(args.log_dir)
    log_dir = Path(args.log_dir)
    # audit_enabled=False -- the CLI doesn't write entries; it only reads.
    config = ShieldConfig(log_dir=log_dir, audit_enabled=False)
    shield = Shield(config=config)

    articles = args.articles.split(",") if args.articles else None
    result = shield.generate_compliance_report(
        period_from=args.from_ts,
        period_to=args.to_ts,
        articles=articles,
        format=args.format,
        out_path=args.out,
        include_decisions=args.include_decisions,
    )

    # Pretty-print the JSON to stdout when no out file requested AND format=json
    if args.format == "json" and not args.out:
        print(json.dumps(result, indent=2))
    elif args.format == "markdown" and not args.out:
        # Print to stdout
        print(result, end="")
    elif args.out:
        # All formats write to file; tell the user where it landed
        print(f"[OK] Wrote {args.format} compliance report to {args.out}")

    # Verdict exit code (the JSON dict has 'verdict'; markdown/pdf return the
    # rendered output, not a dict, so we need to compute verdict separately for
    # those formats by re-running in json mode -- cheap because the audit
    # entries are tiny in memory).
    if args.format in ("markdown", "pdf"):
        verdict_check = shield.generate_compliance_report(
            period_from=args.from_ts,
            period_to=args.to_ts,
            articles=articles,
            format="json",
        )
        verdict = verdict_check["verdict"]
    else:
        verdict = result["verdict"]

    if verdict != "COMPLIANT":
        # Print reasons to stderr so CI logs show why
        if args.format in ("markdown", "pdf"):
            reasons = verdict_check.get("verdict_reasons", [])
        else:
            reasons = result.get("verdict_reasons", [])
        print(f"[FAIL] Verdict: NON_COMPLIANT", file=sys.stderr)
        for r in reasons:
            print(f"  * {r}", file=sys.stderr)
        sys.exit(1)


def cmd_content_log(args):
    """v0.10.0 A50-5: human-readable EU AI Act Article 50 summary of
    content_generation events in an audit log directory.

    Shows label-coverage %, modality breakdown, deep-fake count, and the
    list of unlabeled generation events. Exit codes: 0 = full label
    coverage (COMPLIANT for Article 50), 1 = at least one unlabeled
    synthetic-content event (CI-friendly, mirrors compliance-report).
    """
    from cloakllm import Shield, ShieldConfig

    _warn_if_outside_cwd(args.log_dir)
    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        print(f"[FAIL] Log directory not found: {log_dir}", file=sys.stderr)
        sys.exit(1)

    # Official rollup via the report engine, filtered to Article 50.
    config = ShieldConfig(log_dir=log_dir, audit_enabled=False)
    shield = Shield(config=config)
    report = shield.generate_compliance_report(
        articles=["EU_AI_Act_Art_50"], format="json",
    )
    art50 = report.get("per_article", {}).get("EU_AI_Act_Art_50", {})
    gen = art50.get("generation_events", 0)

    print("CloakLLM -- EU AI Act Article 50 content-labeling summary")
    print(f"Audit dir: {log_dir}")
    print("")
    if not gen:
        print("No content_generation events found in scope.")
        return

    labeled = art50.get("labeled_events", 0)
    coverage = art50.get("label_coverage_pct", 0)
    print(f"Generation events:   {gen}")
    print(f"Labeled events:      {labeled}")
    print(f"Label coverage:      {coverage}%")
    print(f"Deep-fake events:    {art50.get('deepfake_events', 0)}")
    md = art50.get("modality_distribution", {})
    if md:
        md_str = ", ".join(f"{m}={n}" for m, n in sorted(md.items()))
        print(f"Modality breakdown:  {md_str}")

    # List the unlabeled events (read raw entries -- the report rollup is
    # aggregate-only). ASCII-only output (the v0.7.0 Windows console lesson).
    unlabeled = []
    for jsonl in sorted(log_dir.glob("*.jsonl")):
        with open(jsonl, encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                try:
                    entry = json.loads(line)
                except (ValueError, TypeError):
                    continue
                if entry.get("event_type") != "content_generation":
                    continue
                cc = entry.get("content_context") or {}
                if cc.get("labeled") is not True:
                    unlabeled.append((
                        entry.get("seq"),
                        entry.get("decision_id"),
                        cc.get("modality"),
                        cc.get("disclosure_method"),
                    ))

    if unlabeled:
        print("")
        print(f"Unlabeled generation events ({len(unlabeled)}):")
        for seq, did, modality, disc in unlabeled:
            print(
                f"  * seq={seq} decision_id={did} modality={modality} "
                f"disclosure_method={disc}"
            )

    if report.get("verdict") != "COMPLIANT":
        print("", file=sys.stderr)
        print("[FAIL] Article 50 verdict: NON_COMPLIANT", file=sys.stderr)
        for r in report.get("verdict_reasons", []):
            print(f"  * {r}", file=sys.stderr)
        sys.exit(1)
    print("")
    print("[OK] Article 50: full label coverage.")


# --- v0.11.0 TS-6: timestamp CLI -------------------------------------

def cmd_timestamp_now(args):
    """Stamp the audit chain's latest entry_hash at an RFC 3161 TSA and append
    a chain_checkpoint event. Exit 0 on success, 1 on failure."""
    from cloakllm import Shield, ShieldConfig
    _warn_if_outside_cwd(args.log_dir)
    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        print(f"[FAIL] Log directory not found: {log_dir}", file=sys.stderr)
        sys.exit(1)
    tsa_url = args.tsa_url or os.getenv("CLOAKLLM_TSA_URL")
    if not tsa_url:
        print("[FAIL] No TSA URL. Pass --tsa-url or set CLOAKLLM_TSA_URL.", file=sys.stderr)
        sys.exit(1)
    shield = Shield(config=ShieldConfig(
        log_dir=log_dir, compliance_mode="eu_ai_act_article12",
        timestamp_authority_url=tsa_url,
    ))
    try:
        cc = shield.checkpoint()
    except Exception as e:
        print(f"[FAIL] checkpoint failed: {e}", file=sys.stderr)
        sys.exit(1)
    if cc is None:
        print("[FAIL] Nothing to stamp (empty chain).", file=sys.stderr)
        sys.exit(1)
    print("[OK] Chain checkpoint written.")
    print(f"  stamped_seq:        {cc['stamped_seq']}")
    print(f"  stamped_entry_hash: {cc['stamped_entry_hash']}")
    print(f"  tsa_url:            {cc['tsa_url']}")


def cmd_timestamp_verify(args):
    """Verify every chain_checkpoint token in an audit dir OFFLINE. Exit 0 if
    all verify, 1 otherwise."""
    import json as _json
    from cloakllm.timestamping import _ts_backend_available, verify_timestamp_token
    _warn_if_outside_cwd(args.log_dir)
    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        print(f"[FAIL] Log directory not found: {log_dir}", file=sys.stderr)
        sys.exit(1)
    if not _ts_backend_available():
        print("[FAIL] timestamping backend not installed: "
              "pip install cloakllm[timestamping]", file=sys.stderr)
        sys.exit(1)
    trusted = None
    if args.tsa_cert:
        import re as _re
        pem = Path(args.tsa_cert).read_text(encoding="utf-8")
        trusted = _re.findall(
            r"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----", pem, _re.DOTALL
        ) or [pem]

    found = verified = 0
    earliest = None
    for jf in sorted(log_dir.glob("*.jsonl")):
        for line in jf.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                e = _json.loads(line)
            except (ValueError, TypeError):
                continue
            if e.get("event_type") != "chain_checkpoint":
                continue
            cc = e.get("checkpoint_context") or {}
            found += 1
            try:
                r = verify_timestamp_token(
                    cc.get("tst_token_b64", ""),
                    bytes.fromhex(cc.get("stamped_entry_hash", "")), trusted,
                )
            except Exception as ex:
                print(f"  seq={e.get('seq')}: ERROR ({type(ex).__name__})")
                continue
            if r.valid:
                verified += 1
                if r.gen_time and (earliest is None or r.gen_time < earliest):
                    earliest = r.gen_time
                print(f"  seq={e.get('seq')}: OK   genTime={r.gen_time}"
                      + (f" chain={r.chain_valid}" if trusted else ""))
            else:
                print(f"  seq={e.get('seq')}: INVALID ({r.reason})")

    print("")
    print(f"CloakLLM -- RFC 3161 checkpoint verification ({log_dir})")
    print(f"  Checkpoints found:    {found}")
    print(f"  Checkpoints verified: {verified}")
    if earliest:
        print(f"  Earliest provable:    {earliest}")
    if found == 0:
        print("  (no chain_checkpoint events)")
        return
    if verified < found:
        print(f"[FAIL] {found - verified} checkpoint(s) failed verification.", file=sys.stderr)
        sys.exit(1)
    print("[OK] All checkpoints verified.")


# --- v0.8.1 KM-5: key-manifest CLI -----------------------------------

def cmd_key_manifest_generate(args):
    """Generate a KeyManifest binding a signing key to a deployer identity.

    The optional --root-key flow is the OFFLINE CEREMONY that anchors the
    chain of trust. The signing process here loads the root key from disk
    and signs the manifest_hash; the resulting manifest's root_signature
    is verifiable later by any auditor who has the root public key. The
    CloakLLM runtime never needs the root key after this generation step.
    """
    from cloakllm.attestation import DeploymentKeyPair, derive_key_manifest

    keypair = DeploymentKeyPair.from_file(args.signing_key_path)

    root_signing_callback = None
    if args.root_key:
        if not args.root_key_id:
            print("[FAIL] --root-key-id is required when --root-key is supplied", file=sys.stderr)
            sys.exit(1)
        root_kp = DeploymentKeyPair.from_file(args.root_key)
        def _sign(data: bytes) -> bytes:
            return root_kp.sign(data)
        root_signing_callback = _sign

    manifest = derive_key_manifest(
        keypair,
        deployer_id=args.deployer_id,
        valid_from=args.valid_from,
        valid_until=args.valid_until,
        root_signing_callback=root_signing_callback,
        root_key_id=args.root_key_id,
    )
    out_path = Path(args.out)
    if out_path.parent and not out_path.parent.exists():
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest.to_dict(), indent=2) + "\n", encoding="utf-8")
    print(f"[OK] Wrote KeyManifest to {out_path}")
    print(f"     key_id={manifest.key_id} deployer_id={manifest.deployer_id}")
    print(f"     manifest_hash={manifest.manifest_hash}")
    if manifest.root_signature:
        print(f"     root_key_id={manifest.root_key_id} (root-signed)")
    else:
        print(f"     root_signature=null (self-published; not the security boundary)")


def cmd_key_manifest_verify(args):
    """Verify a (certificate, KeyManifest) pair.

    Exit 0 = overall_valid=True. Exit 1 = any required check failed.
    Auditors can wire this into CI gates.
    """
    import base64
    from cloakllm.attestation import (
        KeyManifest, SanitizationCertificate, verify_key_provenance,
    )

    manifest_data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    cert_data = json.loads(Path(args.certificate).read_text(encoding="utf-8"))
    manifest = KeyManifest.from_dict(manifest_data)
    cert = SanitizationCertificate.from_dict(cert_data)

    root_pk_bytes = None
    if args.root_public_key:
        pk_data = json.loads(Path(args.root_public_key).read_text(encoding="utf-8"))
        # Accept either 'public_key' (base64) or 'public_key_hex'.
        if "public_key" in pk_data:
            root_pk_bytes = base64.b64decode(pk_data["public_key"])
        elif "public_key_hex" in pk_data:
            root_pk_bytes = bytes.fromhex(pk_data["public_key_hex"])
        else:
            print("[FAIL] root public key file must contain 'public_key' "
                  "(base64) or 'public_key_hex'", file=sys.stderr)
            sys.exit(1)

    # v0.9.0 RV-5: optional revocation list -> check #6.
    revocation_list = None
    if getattr(args, "revocation_list", None):
        from cloakllm.attestation import RevocationList
        rl_data = json.loads(Path(args.revocation_list).read_text(encoding="utf-8"))
        revocation_list = RevocationList.from_dict(rl_data)

    report = verify_key_provenance(
        cert, manifest,
        root_public_key=root_pk_bytes,
        revocation_list=revocation_list,
    )

    if args.format == "json":
        print(json.dumps(report.to_dict(), indent=2))
    else:
        status_marker = "[OK]" if report.overall_valid else "[FAIL]"
        print(f"{status_marker} provenance_status: {report.provenance_status}")
        print(f"      overall_valid:            {report.overall_valid}")
        print(f"      signature_valid:          {report.signature_valid}")
        print(f"      key_id_matches:           {report.key_id_matches}")
        print(f"      within_validity_window:   {report.within_validity_window}")
        print(f"      root_signature_status:    {report.root_signature_status}")
        print(f"      revocation_status:        {report.revocation_status}")
        print(f"      manifest_hash_consistent: {report.manifest_hash_consistent}")
        if report.notes:
            print(f"      notes:")
            for n in report.notes:
                print(f"        * {n}")

    if not report.overall_valid:
        sys.exit(1)


def cmd_key_manifest_revoke(args):
    """v0.9.0 RV-5: the offline revocation ceremony.

    Appends one entry to the deployer's RevocationList (or creates a new
    list) and re-signs with the offline root key. Entries are never
    removed -- revocation is permanent; rotate to a new key instead.

    Exit 0 on success.
    """
    from cloakllm.attestation import (
        DeploymentKeyPair, RevocationList, derive_revocation_list,
    )

    existing_entries = []
    if args.existing_list:
        prior = RevocationList.from_dict(
            json.loads(Path(args.existing_list).read_text(encoding="utf-8"))
        )
        if prior.deployer_id != args.deployer_id:
            print(f"[FAIL] existing list deployer_id ({prior.deployer_id}) "
                  f"does not match --deployer-id ({args.deployer_id})",
                  file=sys.stderr)
            sys.exit(1)
        existing_entries = [e.to_dict() for e in prior.entries]
        if any(e["key_id"] == args.key_id for e in existing_entries):
            print(f"[FAIL] key_id {args.key_id} is already revoked in "
                  f"{args.existing_list}. Revocation is permanent.",
                  file=sys.stderr)
            sys.exit(1)

    from datetime import datetime, timezone
    revoked_at = args.revoked_at or datetime.now(timezone.utc).isoformat()

    root_signing_callback = None
    if args.root_key:
        if not args.root_key_id:
            print("[FAIL] --root-key-id is required when --root-key is supplied",
                  file=sys.stderr)
            sys.exit(1)
        root_kp = DeploymentKeyPair.from_file(args.root_key)
        root_signing_callback = root_kp.sign

    new_list = derive_revocation_list(
        deployer_id=args.deployer_id,
        entries=existing_entries + [{
            "key_id": args.key_id,
            "revoked_at": revoked_at,
            "reason": args.reason,
        }],
        root_signing_callback=root_signing_callback,
        root_key_id=args.root_key_id,
    )
    out_path = Path(args.out)
    if out_path.parent and not out_path.parent.exists():
        out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        json.dumps(new_list.to_dict(), indent=2) + "\n", encoding="utf-8"
    )
    print(f"[OK] Wrote RevocationList to {out_path}")
    print(f"     revoked: {args.key_id} at {revoked_at} (reason: {args.reason})")
    print(f"     total entries: {len(new_list.entries)}")
    if new_list.root_signature:
        print(f"     root-signed by {new_list.root_key_id}")
    else:
        print("     WARNING: unsigned list -- not the security boundary. "
              "Re-run with --root-key for production.")


def cmd_key_manifest_show(args):
    """Pretty-print a manifest's fields in human-readable form."""
    manifest_data = json.loads(Path(args.manifest).read_text(encoding="utf-8"))
    print(f"KeyManifest:")
    print(f"  key_id:           {manifest_data.get('key_id')}")
    print(f"  deployer_id:      {manifest_data.get('deployer_id')}")
    print(f"  purpose:          {manifest_data.get('purpose')}")
    print(f"  valid_from:       {manifest_data.get('valid_from')}")
    print(f"  valid_until:      {manifest_data.get('valid_until') or '(open-ended)'}")
    print(f"  manifest_version: {manifest_data.get('manifest_version')}")
    print(f"  manifest_hash:    {manifest_data.get('manifest_hash')}")
    root_sig = manifest_data.get('root_signature')
    if root_sig:
        print(f"  root_signature:   present (root_key_id={manifest_data.get('root_key_id')})")
    else:
        print(f"  root_signature:   null (self-published; not the security boundary)")


def main():
    parser = argparse.ArgumentParser(
        prog="cloakllm",
        description="CloakLLM -- AI Compliance Middleware CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available commands")

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan text for sensitive data")
    scan_parser.add_argument("text", help="Text to scan (use '-' for stdin)")
    scan_parser.add_argument("--show-pii", action="store_true", default=False,
                             help="Show raw PII values (default: redacted)")
    scan_parser.add_argument("--context-risk", action="store_true", default=False,
                             help="Analyze sanitized output for context-based PII leakage risk")

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify audit log integrity")
    verify_parser.add_argument("log_dir", help="Path to audit log directory")
    verify_parser.add_argument(
        "--format",
        choices=["compliance_report"],
        default=None,
        help="Output format. 'compliance_report' returns a structured EU AI Act Article 12 report (JSON).",
    )
    # v0.9.0 LC-1: --legacy-canonical-json flag REMOVED (sunset phase 2,
    # per the v0.7.1 phase-1 commitment). Pre-v0.6.1 chains must be
    # re-archived under a v0.6.1..v0.8.x release. argparse now rejects
    # the flag with its standard unrecognized-arguments error.

    # stats
    stats_parser = subparsers.add_parser("stats", help="Show audit statistics")
    stats_parser.add_argument("log_dir", help="Path to audit log directory")

    # compliance-report (v0.8.0 CR8-6)
    cr_parser = subparsers.add_parser(
        "compliance-report",
        help="Generate a regulatory-output compliance report from the audit log",
    )
    cr_parser.add_argument(
        "log_dir", help="Path to audit log directory",
    )
    cr_parser.add_argument(
        "--from", dest="from_ts", default=None,
        help="Period start (ISO 8601 UTC). Default: unbounded.",
    )
    cr_parser.add_argument(
        "--to", dest="to_ts", default=None,
        help="Period end (ISO 8601 UTC). Default: unbounded.",
    )
    cr_parser.add_argument(
        "--articles", default=None,
        help="Comma-separated article filter (e.g. EU_AI_Act_Art_12,EU_AI_Act_Art_4a). Default: all.",
    )
    cr_parser.add_argument(
        "--format", choices=["json", "markdown", "pdf"], default="json",
        help="Output format. PDF requires `pip install cloakllm[reporting]`.",
    )
    cr_parser.add_argument(
        "--out", default=None,
        help="Output file path. Required for --format=pdf. Otherwise prints to stdout.",
    )
    cr_parser.add_argument(
        "--include-decisions", action="store_true", default=False,
        dest="include_decisions",
        help="Include per-decision_id rollup (large on high-volume chains).",
    )

    # content-log (v0.10.0 A50-5) -- EU AI Act Article 50 summary view.
    cl_parser = subparsers.add_parser(
        "content-log",
        help="Summarize Article 50 content_generation events (label coverage, "
             "modality breakdown, unlabeled events). Exit 1 if any unlabeled.",
    )
    cl_parser.add_argument("log_dir", help="Path to audit log directory")

    # timestamp (v0.11.0 TS-6) -- RFC 3161 trusted timestamping.
    ts_parser = subparsers.add_parser(
        "timestamp",
        help="RFC 3161 trusted timestamping of the audit chain (v0.11.0+)",
    )
    ts_sub = ts_parser.add_subparsers(dest="ts_action", help="Action")
    ts_now = ts_sub.add_parser("now", help="Stamp the chain's latest entry_hash at a TSA")
    ts_now.add_argument("log_dir", help="Path to audit log directory")
    ts_now.add_argument("--tsa-url", default=None,
                        help="TSA endpoint (https). Default: CLOAKLLM_TSA_URL env.")
    ts_ver = ts_sub.add_parser("verify", help="Verify all checkpoint tokens offline")
    ts_ver.add_argument("log_dir", help="Path to audit log directory")
    ts_ver.add_argument("--tsa-cert", default=None,
                        help="Optional PEM of trusted TSA cert(s) to also check the chain.")

    # key-manifest (v0.8.1 KM-5) -- externally-verifiable key provenance.
    # Three actions: generate (one-time ceremony to bind a key to a deployer),
    # verify (an auditor checks a cert+manifest pair), show (read-only inspect).
    km_parser = subparsers.add_parser(
        "key-manifest",
        help="Manage externally-verifiable key provenance (v0.8.1+)",
    )
    km_sub = km_parser.add_subparsers(dest="km_action", help="Action")

    # generate
    km_gen = km_sub.add_parser(
        "generate",
        help="Generate a KeyManifest binding a signing key to a deployer identity",
    )
    km_gen.add_argument("--signing-key-path", required=True,
                        help="Path to the signing keypair JSON file (DeploymentKeyPair).")
    km_gen.add_argument("--deployer-id", required=True,
                        help="Free-form deployer identifier (org name, URN, etc.). 1..256 chars.")
    km_gen.add_argument("--valid-from", default=None,
                        help="ISO 8601 UTC. Default: now.")
    km_gen.add_argument("--valid-until", default=None,
                        help="ISO 8601 UTC. Default: open-ended (less secure).")
    km_gen.add_argument("--root-key", default=None,
                        help="OPTIONAL path to an offline root key file. "
                             "When set, --root-key-id is required, and the "
                             "manifest's manifest_hash will be signed by the "
                             "root key. The runtime never holds this key.")
    km_gen.add_argument("--root-key-id", default=None,
                        help="Identifier of the root key (required iff --root-key set).")
    km_gen.add_argument("--out", required=True,
                        help="Output file path for the manifest JSON.")

    # verify
    km_ver = km_sub.add_parser(
        "verify",
        help="Verify a (certificate, KeyManifest) pair",
    )
    km_ver.add_argument("--manifest", required=True,
                        help="Path to manifest JSON file.")
    km_ver.add_argument("--certificate", required=True,
                        help="Path to certificate JSON file.")
    km_ver.add_argument("--root-public-key", default=None,
                        help="OPTIONAL path to root public key (32-byte raw, "
                             "base64-encoded in a JSON file with field 'public_key'). "
                             "Required to verify the manifest's root_signature.")
    km_ver.add_argument("--revocation-list", default=None,
                        help="OPTIONAL path to the deployer's RevocationList JSON "
                             "(v0.9.0). Adds check #6: REVOKED certs fail.")
    km_ver.add_argument("--format", choices=["json", "text"], default="text",
                        help="Output format.")

    # show
    km_show = km_sub.add_parser(
        "show",
        help="Print a manifest's fields in human-readable form",
    )
    km_show.add_argument("--manifest", required=True,
                         help="Path to manifest JSON file.")

    # revoke (v0.9.0 RV-5) -- the offline revocation ceremony
    km_rev = km_sub.add_parser(
        "revoke",
        help="Add a key to the deployer's RevocationList (offline root ceremony)",
    )
    km_rev.add_argument("--key-id", required=True,
                        help="The key_id to revoke.")
    km_rev.add_argument("--reason", required=True,
                        choices=["compromised", "superseded", "ceased_operation", "unspecified"],
                        help="Revocation reason.")
    km_rev.add_argument("--revoked-at", default=None,
                        help="ISO 8601 UTC. Default: now. Certs signed at or "
                             "after this moment become untrusted.")
    km_rev.add_argument("--deployer-id", required=True,
                        help="Deployer identifier (must match the KeyManifests).")
    km_rev.add_argument("--list", dest="existing_list", default=None,
                        help="Path to the EXISTING revocation list to append to. "
                             "Omit to create a new list.")
    km_rev.add_argument("--root-key", default=None,
                        help="Path to the offline root key file (recommended -- "
                             "an unsigned list is not the security boundary).")
    km_rev.add_argument("--root-key-id", default=None,
                        help="Root key identifier (required iff --root-key set).")
    km_rev.add_argument("--out", required=True,
                        help="Output path for the new revocation list JSON.")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "compliance-report":
        cmd_compliance_report(args)
    elif args.command == "content-log":
        cmd_content_log(args)
    elif args.command == "timestamp":
        if args.ts_action == "now":
            cmd_timestamp_now(args)
        elif args.ts_action == "verify":
            cmd_timestamp_verify(args)
        else:
            ts_parser.print_help()
    elif args.command == "key-manifest":
        if args.km_action == "generate":
            cmd_key_manifest_generate(args)
        elif args.km_action == "verify":
            cmd_key_manifest_verify(args)
        elif args.km_action == "show":
            cmd_key_manifest_show(args)
        elif args.km_action == "revoke":
            cmd_key_manifest_revoke(args)
        else:
            km_parser.print_help()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
