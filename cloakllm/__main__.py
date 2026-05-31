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
        print("✅ No sensitive entities detected.")
        return

    print(f"⚠️  Found {analysis['entity_count']} sensitive entities:\n")

    for ent in analysis["entities"]:
        display = ent['text'] if show_pii else "***"
        print(f"  [{ent['category']}] \"{display}\"")
        print(f"    Position: {ent['start']}-{ent['end']} | "
              f"Confidence: {ent['confidence']:.0%} | Source: {ent['source']}")

    # Show sanitized version
    sanitized, token_map = shield.sanitize(text)
    print(f"\n{'─' * 60}")
    if show_pii:
        print(f"ORIGINAL:  {text}")
    else:
        print(f"ORIGINAL:  [use --show-pii to display]")
    print(f"SANITIZED: {sanitized}")
    print(f"{'─' * 60}")
    print(f"\nToken map ({token_map.entity_count} entities):")
    for token, original in token_map.reverse.items():
        display = original if show_pii else "***"
        print(f"  {token} → \"{display}\"")

    # Context risk analysis (opt-in)
    if getattr(args, "context_risk", False):
        risk = shield.analyze_context_risk(sanitized)
        print(f"\n{'─' * 60}")
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
        print(f"❌ Log directory not found: {log_dir}")
        sys.exit(1)

    config = ShieldConfig(log_dir=log_dir)
    logger = AuditLogger(config)

    output_format = getattr(args, "format", None)
    legacy = getattr(args, "legacy_canonical_json", False)

    if output_format == "compliance_report":
        report = logger.verify_chain(
            output_format="compliance_report",
            legacy_canonical=legacy,
        )
        print(json.dumps(report, indent=2))
        if report["verdict"] != "COMPLIANT":
            sys.exit(1)
        return

    print(f"Verifying audit chain in {log_dir}...")
    is_valid, errors, final_seq = logger.verify_chain(legacy_canonical=legacy)

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

    report = verify_key_provenance(cert, manifest, root_public_key=root_pk_bytes)

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
        print(f"      manifest_hash_consistent: {report.manifest_hash_consistent}")
        if report.notes:
            print(f"      notes:")
            for n in report.notes:
                print(f"        * {n}")

    if not report.overall_valid:
        sys.exit(1)


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
    verify_parser.add_argument(
        "--legacy-canonical-json",
        action="store_true",
        default=False,
        dest="legacy_canonical_json",
        help=(
            "Use the v0.6.0 canonical JSON encoding (ensure_ascii=True) when "
            "verifying. Required for audit chains written by CloakLLM <= 0.6.0 "
            "that contain non-ASCII characters. Sunset in v0.7.0."
        ),
    )

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
    km_ver.add_argument("--format", choices=["json", "text"], default="text",
                        help="Output format.")

    # show
    km_show = km_sub.add_parser(
        "show",
        help="Print a manifest's fields in human-readable form",
    )
    km_show.add_argument("--manifest", required=True,
                         help="Path to manifest JSON file.")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "stats":
        cmd_stats(args)
    elif args.command == "compliance-report":
        cmd_compliance_report(args)
    elif args.command == "key-manifest":
        if args.km_action == "generate":
            cmd_key_manifest_generate(args)
        elif args.km_action == "verify":
            cmd_key_manifest_verify(args)
        elif args.km_action == "show":
            cmd_key_manifest_show(args)
        else:
            km_parser.print_help()
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
