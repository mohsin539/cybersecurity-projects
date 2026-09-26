"""Headless CLI (offline report generation / demos / integrity checks).

Usage:
    python -m acsv demo --events 600             # run demo session
    python -m acsv report --session <id> --fmt pdf --out data/reports
    python -m acsv audit-verify                   # chain integrity check
    python -m acsv schema-export                  # writes schemas to ./schemas
"""

from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path

from .capture.generator import build_trace
from .capture.runner import CaptureRunner
from .services import AppServices


def _fresh_demo(services, events: int) -> str:
    sample = services.intake.register_virtual(name="demo-replay.bin")
    runner = CaptureRunner(services.store, services.audit, services.policy,
                           services.redaction)
    sid = runner.create_session(int(sample["id"]))
    trace = build_trace(sample["sha256"], count=events)
    runner.run_trace(sid, trace, driver_meta={"kind": "synthetic"})
    return sid


def cmd_demo(args) -> int:
    services = AppServices()
    t0 = time.perf_counter()
    sid = _fresh_demo(services, args.events)
    analysis = services.analysis.analyze(sid)
    print(f"session    : {sid}")
    print(f"sample     : {services.store.get_sample(analysis and services.store.list_sessions()[0].get('sample_id') or 0)}")
    print(f"events     : {analysis['event_count']}  unique_apis={analysis['unique_apis']}")
    print(f"calls/sec  : {analysis['calls_per_second']}")
    for f in analysis["findings"]:
        print(f"  [{f['severity'].upper():8s}] {f['title']}")
    print(f"elapsed    : {time.perf_counter() - t0:.2f}s")
    services.close()
    return 0


def cmd_report(args) -> int:
    services = AppServices()
    if not args.session:
        sid = _fresh_demo(services, 600)
    else:
        sid = args.session
    out = Path(args.out)
    res = services.report_engine.render_and_save(sid, args.fmt, out)
    print(f"report     : {res['path']}")
    print(f"format     : {res['format']}  sha256={res['sha256']}")
    print(f"size       : {res['size']} bytes")
    services.close()
    return 0


def cmd_audit(args) -> int:
    services = AppServices()
    ok, fails = services.audit.verify_chain()
    print(f"chain      : {'PASS' if ok else 'FAIL'}")
    print(f"entries    : {services.audit.count()}  failures={len(fails)}")
    services.close()
    return 0 if ok else 2


def cmd_schema(args) -> int:
    from .registry import SchemaRegistry
    SchemaRegistry.export_dir(Path(args.out))
    print(f"schemas    : exported to {Path(args.out).resolve()}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="acsv", description="ACSV offline tooling")
    sub = p.add_subparsers(dest="cmd", required=True)
    d = sub.add_parser("demo", help="run synthetic demo capture")
    d.add_argument("--events", type=int, default=600)
    d.set_defaults(fn=cmd_demo)
    r = sub.add_parser("report", help="generate report for a session")
    r.add_argument("--session", default="")
    r.add_argument("--fmt", default="pdf", choices=["json", "csv", "html", "pdf", "stix"])
    r.add_argument("--out", default="data/reports")
    r.set_defaults(fn=cmd_report)
    a = sub.add_parser("audit-verify", help="verify audit chain")
    a.set_defaults(fn=cmd_audit)
    s = sub.add_parser("schema-export", help="export JSON schemas")
    s.add_argument("--out", default="schemas")
    s.set_defaults(fn=cmd_schema)
    return p


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    return args.fn(args)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))