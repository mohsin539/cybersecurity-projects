"""Demo entry point: run detection, generate reports (XLSX/CSV/HTML/JSON)."""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path

from src.config import OUTPUT_DIR
from src.detection.engine import evaluate_all
from src.frameworks import build_catalog, summary_stats
from src.generator import build_dataset
from src.reporting import export_csv, export_html, export_json, export_xlsx
from src.reporting.bundle import ReportBundle


def _utcnow() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run(out_dir: Path, formats: tuple = ("xlsx", "csv", "html", "json")) -> Path:
    records = build_dataset()
    verdicts = list(evaluate_all(records).values())
    findings = [f for v in verdicts for f in v.findings]
    bundle = ReportBundle.build(records, verdicts, findings, _utcnow())

    stamp = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    run_dir = out_dir / f"report_{stamp}"
    run_dir.mkdir(parents=True, exist_ok=True)

    produced = []
    if "xlsx" in formats:
        produced.append(str(export_xlsx(bundle, run_dir / "traffic_obfuscation_report.xlsx")))
    if "csv" in formats:
        produced.extend(str(p) for p in export_csv(bundle, run_dir))
    if "html" in formats:
        produced.append(str(export_html(bundle, run_dir / "traffic_obfuscation_report.html")))
    if "json" in formats:
        produced.append(str(export_json(bundle, run_dir / "traffic_obfuscation_report.json")))

    _print_summary(bundle, produced)
    return run_dir


def _print_summary(bundle: ReportBundle, produced: list) -> None:
    print("=" * 68)
    print(f"  {bundle.project}  (v{bundle.version})")
    print("=" * 68)
    for v in bundle.verdicts:
        print(f"  {v.record_id:8} {v.scenario:14} {v.label.value:9}  score={v.score:3}")
    print("-" * 68)
    for fw, st in bundle.framework_stats.items():
        print(f"  {fw:18} controls={st['total']:2} relevant={st['relevant']:2} "
              f"adopt={st['adopt']:2} review={st['review']:2}")
    print("-" * 68)
    for p in produced:
        print(f"  ✔ {p}")
    print("=" * 68)


def main(argv=None) -> int:
    try:
        sys.stdout.reconfigure(encoding="utf-8")  # Windows console safety
    except Exception:
        pass
    ap = argparse.ArgumentParser(description="Traffic Obfuscation Techniques Demo")
    ap.add_argument("--out", type=Path, default=OUTPUT_DIR, help="output directory")
    ap.add_argument("--formats", nargs="+", default=["xlsx", "csv", "html", "json"],
                    choices=["xlsx", "csv", "html", "json"])
    args = ap.parse_args(argv)
    run(args.out, tuple(args.formats))
    return 0


if __name__ == "__main__":
    sys.exit(main())