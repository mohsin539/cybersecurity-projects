"""FW auditor CLI. Read-only; never mutates external state by default.

Usage:
    py main.py --rules fixtures/aws_sg.json --out data
    py main.py --rules fixtures/aws_sg.json --out data --formats html,csv
    py main.py --self-test
"""
from __future__ import annotations

import argparse
import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.chdir(Path(__file__).resolve().parent)

import fw_auditor.analyze as analyze
import fw_auditor.score as score
import fw_auditor.report as report
from fw_auditor.collect import load_fixture
from fw_auditor.report import diff, remediation_suggestion, VALID_FORMATS, write_reports

SELF_TEST_EXPECT = {
    "broad_exposure": 1,
    "shadowed": 1,
    "any_any": 1,
    "default_policy": 0,
    "logging_disabled": 1,
    "redundant": 1,
}


def self_test() -> int:
    rules = load_fixture(Path("fixtures/aws_sg.json"))
    got = {}
    for probe in analyze.PROBES:
        fs = probe(rules)
        print(f"  {probe.__name__:<28} {len(fs)}")
        for f in fs:
            got[f["kind"]] = got.get(f["kind"], 0) + 1
    ok = True
    for k, v in SELF_TEST_EXPECT.items():
        if got.get(k, 0) != v:
            print(f"  MISMATCH {k}: expected {v}, got {got.get(k, 0)}")
            ok = False
    print(f"{'PASS' if ok else 'FAIL'} self-test")
    return 0 if ok else 1


def run(rules_path: Path, out_dir: Path, formats) -> int:
    rules = load_fixture(rules_path)
    all_findings = []
    for probe in analyze.PROBES:
        all_findings.extend(probe(rules))
    for f in all_findings:
        f["remediation"] = report.remediation_suggestion(f)
    snap = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    agg = score.aggregate(all_findings, device=rules[0].device if rules else "fixture")
    written = write_reports(all_findings, out_dir, snap, formats=formats, summary=agg)
    print(f"--- fw-auditor report ({snap}) ---")
    print(f"rules: {len(rules)}   findings: {len(all_findings)}")
    print(f"device score (0-100, lower is better): {agg['score']}")
    print("--- remediation proposals (top by severity) ---")
    for f in sorted(all_findings, key=lambda x: -score.BASE.get(x['severity'], 1))[:10]:
        print(f"  [{f['severity']:>8}] {f['kind']:<20} {f.get('rule_id','?'):<24} -> "
              f"{f['remediation']}")
    print(f"formats: {', '.join(formats)}")
    for p in written:
        print(f"report written: {p}")
    return 0


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rules", default="fixtures/aws_sg.json")
    ap.add_argument("--out", default="data")
    ap.add_argument("--formats", default="json,html,csv,xlsx",
                    help=f"comma-separated report formats: {', '.join(VALID_FORMATS)} "
                         f"(default: json,html,csv,xlsx)")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()
    if args.self_test:
        return self_test()
    formats = tuple(f.strip().lower() for f in args.formats.split(",") if f.strip())
    unknown = [f for f in formats if f not in VALID_FORMATS]
    if unknown:
        print(f"unknown format(s): {', '.join(unknown)}; choose from {', '.join(VALID_FORMATS)}")
        return 2
    return run(Path(args.rules), Path(args.out), formats)


def _pause_on_windows() -> None:
    if os.name == "nt" and not os.environ.get("TI_NO_PAUSE"):
        try:
            interactive = (sys.stdin and sys.stdin.isatty()
                           and sys.stdout and sys.stdout.isatty())
            if interactive:
                input("\nPress Enter to exit...")
        except (EOFError, KeyboardInterrupt, OSError):
            pass


if __name__ == "__main__":
    try:
        _rc = main()
    except KeyboardInterrupt:
        _rc = 130
    finally:
        _pause_on_windows()
    raise SystemExit(_rc)