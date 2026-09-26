"""Command-line interface for batch log anonymization.

Usage examples:
    echo "error user john.smith@example.com ssn 123-45-6789" | python -m anonymizer
    python -m anonymizer input.log -o output.log
    python -m anonymizer --policy share-with-analytics input.log
    python -m anonymizer --audit-check
"""

import argparse
import json
import sys
from pathlib import Path

from .services import AnonymizationRequest, AnonymizerService


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="log-anonymizer",
        description="Log Anonymizer with Redactor - safe log sharing",
    )
    parser.add_argument("input", nargs="?", help="Input log file (stdin if omitted)")
    parser.add_argument("-o", "--output", help="Output file (stdout if omitted)")
    parser.add_argument("--policy", default="default", help="Sharing policy ID")
    parser.add_argument("--date-shift", type=int, default=0, help="Days to shift dates")
    parser.add_argument("--salt", default="", help="Token/salt for deterministic tokens")
    parser.add_argument("--audit-check", action="store_true", help="Verify audit chain integrity")
    parser.add_argument("--json", dest="as_json", action="store_true", help="Emit JSON output")
    return parser


def main(argv=None) -> int:
    args = _build_parser().parse_args(argv)

    svc = AnonymizerService()

    if args.audit_check:
        verified = svc.audit.rebuild_root_from_disk() == svc.audit.chain_root
        print(
            json.dumps(
                {
                    "audit_chain_verified": verified,
                    "record_count": svc.audit.record_count,
                    "chain_root": svc.audit.chain_root,
                },
                indent=2,
            )
        )
        return 0 if verified else 1

    # Read input lines
    if args.input:
        source = Path(args.input)
        if not source.exists():
            print(f"error: input file not found: {args.input}", file=sys.stderr)
            return 2
        lines = source.read_text(encoding="utf-8", errors="replace").splitlines()
    else:
        lines = [l for l in sys.stdin.read().splitlines() if l.strip()]

    request = AnonymizationRequest(
        lines=lines,
        policy_id=args.policy,
        date_shift_days=args.date_shift,
        token_salt=args.salt,
    )
    result = svc.anonymize(request)

    if args.as_json:
        payload = {
            "request_id": result.request_id,
            "policy_id": result.policy_id,
            "entity_stats": result.entity_stats,
            "processing_ms": result.total_processing_ms,
            "audit_events": result.audit_events,
            "chain_root": result.chain_root,
            "lines": result.redacted_lines,
        }
        output = json.dumps(payload, indent=2)
    else:
        output = "\n".join(result.redacted_lines)

    if args.output:
        Path(args.output).write_text(output + "\n", encoding="utf-8")
    else:
        print(output)

    # Summary to stderr so stdout stays clean for piping
    print(
        f"[summary] lines={len(lines)} entities={sum(result.entity_stats.values())} "
        f"audit_events={result.audit_events} time_ms={result.total_processing_ms}",
        file=sys.stderr,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
