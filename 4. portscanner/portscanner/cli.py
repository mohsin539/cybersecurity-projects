"""CLI front-end (architecture.md §4.1). Authorize → validate → scan → report."""
from __future__ import annotations

import argparse
import sys

from .config import ScanType, validate, ConfigError
from .security import authorization_gate, is_admin, safe_output_path, stderr_warn
from .scanner import Scanner

EPILOG = "Authorized use only: scanning systems without permission may be illegal."


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="portscan",
        description="Authorized-use TCP/UDP port scanner (see architecture.md)",
        epilog=EPILOG,
    )
    p.add_argument("targets", nargs="*", help="hosts, CIDRs, ranges (comma-separated)")
    p.add_argument("-p", "--ports", default="top100",
                   help="e.g. 22,80,443,8000-9000 | top100 | all (default: top100)")
    p.add_argument("-s", "--scan-type", default="connect",
                   choices=[t.value for t in ScanType])
    p.add_argument("-w", "--workers", type=int, default=256)
    p.add_argument("--rate", type=float, default=0.0, help="probes/sec (0=unbounded)")
    p.add_argument("--timeout", type=float, default=1.0)
    p.add_argument("--retries", type=int, default=2)
    p.add_argument("--jitter", type=int, default=0, help="ms of send jitter")
    p.add_argument("--no-servicedetect", action="store_true")
    p.add_argument("-o", "--output", default="-", help="output file (default stdout)")
    p.add_argument("-f", "--format", default="table",
                   choices=["table", "json", "jsonl", "csv", "greppable"])
    p.add_argument("--resume", metavar="WAL", help="resume a previous scan.wal")
    p.add_argument("--yes", action="store_true",
                   help="confirm authorization non-interactively")
    p.add_argument("--gui", action="store_true", help="launch the desktop GUI")
    return p


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.gui:
        from .gui import main as gui_main
        gui_main()
        return 0
    if not args.targets:
        build_parser().print_help()
        return 2

    targets = [t.strip() for t in ",".join(args.targets).split(",") if t.strip()]

    if not authorization_gate(targets, interactive=sys.stdin.isatty(), yes=args.yes):
        stderr_warn("authorization not confirmed — aborting (see audit log)")
        return 3

    try:
        cfg = validate(
            targets=targets,
            ports_spec=args.ports,
            scan_type=args.scan_type,
            workers=args.workers,
            rate_limit=args.rate,
            timeout_s=args.timeout,
            retries=args.retries,
            service_detect=not args.no_servicedetect,
            output_format=args.format,
            output_file=args.output,
            jitter_ms=args.jitter,
            resume_wal=args.resume or "",
            authorized=args.yes or sys.stdin.isatty(),
        )
    except ConfigError as exc:
        stderr_warn(f"configuration error: {exc}")
        return 2

    try:
        output = Scanner(cfg).run()
    except KeyboardInterrupt:
        stderr_warn("interrupted — partial results in scan.wal")
        return 130

    if args.output == "-":
        print(output)
    else:
        try:
            from pathlib import Path
            path = safe_output_path(args.output, Path.cwd())
            path.write_text(output, encoding="utf-8")
            stderr_warn(f"report written: {path}")
        except (OSError, ValueError) as exc:
            stderr_warn(f"cannot write output: {exc}")
            return 4
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
