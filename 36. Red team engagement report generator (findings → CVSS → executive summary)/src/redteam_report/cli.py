"""Command-line entrypoint for the Red Team Engagement Report Generator.

Usage:
    python -m redteam_report.cli input.json --out reports --formats csv,xlsx,html
"""

from __future__ import annotations

import argparse
import sys
import traceback
from pathlib import Path

from .pipeline import REPORTERS, generate, load_engagement


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(
        prog="red-team-report",
        description=(
            "Red Team Engagement Report Generator: findings -> CVSS v3.1 -> "
            "OWASP Top 10 / NIST 800-53 / ISO 27001 -> executive summary -> "
            ".xlsx / .csv / .html reports."
        ),
    )
    parser.add_argument("input", type=Path, help="Path to engagement JSON (see sample_findings.json)")
    parser.add_argument("--out", "-o", type=Path, default=Path("reports"), help="Output directory")
    parser.add_argument(
        "--formats", "-f",
        default="csv,xlsx,html",
        help="Comma-separated report formats to generate (default: csv,xlsx,html)",
    )
    parser.add_argument("--list-frameworks", action="store_true", help="Print supported framework catalog")
    args = parser.parse_args(argv)

    if args.list_frameworks:
        _print_frameworks()
        return 0

    formats = [f.strip().lower() for f in args.formats.split(",") if f.strip()]
    for fmt in formats:
        if fmt not in REPORTERS:
            parser.error(f"Unsupported format '{fmt}'. Supported: {', '.join(REPORTERS)}")

    try:
        engagement = load_engagement(args.input)
        results = generate(engagement, args.out, formats)
    except FileNotFoundError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 2
    except Exception:  # pragma: no cover - defensive reporting
        traceback.print_exc()
        return 1

    print(f"Engagement : {engagement.name}")
    print(f"Findings   : {len(engagement.findings)}")
    summary = engagement.executive_summary()
    print(f"Risk       : {summary.risk_rating} (index {summary.risk_score:.0f}/100)")
    for fmt, result in results.items():
        for kind, path in result.files.items():
            print(f"{fmt.upper():>5} [{kind}] -> {path}")
    return 0


def _print_frameworks() -> None:
    from .frameworks.iso27001 import ISO_CONTROLS
    from .frameworks.nist import NIST_CONTROLS
    from .frameworks.owasp import OWASP_TOP_10_2021

    print("Supported frameworks (embedded catalog)")
    print("=" * 70)
    print("\nOWASP Top 10 (2021):")
    for cat in OWASP_TOP_10_2021:
        print(f"  {cat.code}  {cat.name}")
    print("\nNIST SP 800-53 Rev.5 (curated):")
    for c in NIST_CONTROLS:
        print(f"  {c.code:<10} {c.name}")
    print("\nISO/IEC 27001:2022 Annex A (curated):")
    for c in ISO_CONTROLS:
        print(f"  {c.code:<7} {c.name}")


if __name__ == "__main__":
    raise SystemExit(main())