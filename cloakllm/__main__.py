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


def cmd_scan(args):
    """Scan text for sensitive data and show what would be sanitized."""
    from cloakllm import Shield, ShieldConfig

    config = ShieldConfig(audit_enabled=False)
    shield = Shield(config)

    text = args.text
    if text == "-":
        text = sys.stdin.read()

    # Analyze
    analysis = shield.analyze(text)

    if not analysis["entities"]:
        print("✅ No sensitive entities detected.")
        return

    print(f"⚠️  Found {analysis['entity_count']} sensitive entities:\n")

    for ent in analysis["entities"]:
        print(f"  [{ent['category']}] \"{ent['text']}\"")
        print(f"    Position: {ent['start']}-{ent['end']} | "
              f"Confidence: {ent['confidence']:.0%} | Source: {ent['source']}")

    # Show sanitized version
    sanitized, token_map = shield.sanitize(text)
    print(f"\n{'─' * 60}")
    print(f"ORIGINAL:  {text}")
    print(f"SANITIZED: {sanitized}")
    print(f"{'─' * 60}")
    print(f"\nToken map ({token_map.entity_count} entities):")
    for token, original in token_map.reverse.items():
        print(f"  {token} → \"{original}\"")


def cmd_verify(args):
    """Verify audit log chain integrity."""
    from cloakllm import ShieldConfig
    from cloakllm.audit import AuditLogger

    log_dir = Path(args.log_dir)
    if not log_dir.exists():
        print(f"❌ Log directory not found: {log_dir}")
        sys.exit(1)

    config = ShieldConfig(log_dir=log_dir)
    logger = AuditLogger(config)

    print(f"Verifying audit chain in {log_dir}...")
    is_valid, errors = logger.verify_chain()

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
