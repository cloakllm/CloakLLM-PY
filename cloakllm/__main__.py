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
                print(f"    • {w}")


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

    if output_format == "compliance_report":
        report = logger.verify_chain(output_format="compliance_report")
        print(json.dumps(report, indent=2))
        if report["verdict"] != "COMPLIANT":
            sys.exit(1)
        return

    print(f"Verifying audit chain in {log_dir}...")
    is_valid, errors, final_seq = logger.verify_chain()

    if is_valid:
        print("✅ Audit chain integrity verified — no tampering detected.")
    else:
        print(f"❌ CHAIN INTEGRITY FAILURE — {len(errors)} error(s):\n")
        for err in errors:
            print(f"  • {err}")
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


def main():
    parser = argparse.ArgumentParser(
        prog="cloakllm",
        description="CloakLLM — AI Compliance Middleware CLI",
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

    # stats
    stats_parser = subparsers.add_parser("stats", help="Show audit statistics")
    stats_parser.add_argument("log_dir", help="Path to audit log directory")

    args = parser.parse_args()

    if args.command == "scan":
        cmd_scan(args)
    elif args.command == "verify":
        cmd_verify(args)
    elif args.command == "stats":
        cmd_stats(args)
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
