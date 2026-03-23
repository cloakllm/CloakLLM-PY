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

    # verify
    verify_parser = subparsers.add_parser("verify", help="Verify audit log integrity")
    verify_parser.add_argument("log_dir", help="Path to audit log directory")

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
