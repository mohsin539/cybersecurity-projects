"""Entry point: launches the portable GUI, or runs a headless study via --cli."""
from __future__ import annotations

import argparse
import json
import os
import sys


def _run_cli(args: argparse.Namespace) -> int:
    from src.app.orchestrator import run_study
    from src.config import scenario_from_yaml
    from src.paths import audit_log_path, out_dir
    from src.reporting.bundle import write_full_bundle
    from src.reporting.report_data import build_report_model
    from src.security.audit import AuditLog

    if not os.path.exists(args.cli):
        print(f"scenario file not found: {args.cli}", file=sys.stderr)
        return 2
    scenario = scenario_from_yaml(args.cli)
    print(f"[config] agents={scenario.agents} jitter={scenario.jitter_type}@{scenario.jitter_pct}% "
          f"sleep={scenario.sleep_mode} engine={scenario.engine} seed={scenario.seed}")

    audit = AuditLog(audit_log_path())
    if not audit.verify():
        print("[security] AUDIT CHAIN FAILED - refusing to export", file=sys.stderr)
        return 3

    result = run_study(scenario, progress=lambda f, m: print(f"[{f*100:5.1f}%] {m}", flush=True))
    model = build_report_model(result)

    output = args.out or out_dir()
    paths = write_full_bundle(model, output, audit, passphrase=args.passphrase)
    print(f"\nverdict: {model['verdict_badge']} - {model['verdict_text']}")
    for name, path in sorted(paths.items()):
        print(f"  {name:24} -> {path}")
    if args.print_summary:
        for r in model["summary_rows"]:
            base = r.get("baseline", "-")
            print(f"  {r['metric']:<32}{r['candidate']:<18}{base}")
    return 0


def main(argv: list[str] | None = None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    parser = argparse.ArgumentParser(prog="AgentJitterStudy", description="Agent check-in jitter & sleep portable study toolkit")
    parser.add_argument("--cli", metavar="SCENARIO.yml", help="headless run from a scenario profile")
    parser.add_argument("--out", metavar="DIR", help="output folder for headless runs")
    parser.add_argument("--passphrase", default=None, help="AES-GCM protect the ZIP bundle")
    parser.add_argument("--print-summary", action="store_true", help="print KPI summary after headless run")
    parser.add_argument("--version", action="version", version="AgentJitterStudy 1.0.0")
    args = parser.parse_args(argv)

    if args.cli:
        return _run_cli(args)

    from src.presentation.gui import run_gui
    run_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())