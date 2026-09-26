from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from . import __version__
from .collectors import FilesystemCollector, LogCollector
from .collectors.base import CollectorContext
from .config import AppSettings, ScanOptions
from .correlation import Correlator
from .export import export_csv, export_html, export_json
from .normalizer import TimelineNormalizer
from .security.audit import AuditLogger, verify_audit_chain
from .security.integrity import build_manifest, write_manifest
from .storage import CaseStore


def _resolve_kind(path: Path, requested: str) -> str:
    if requested != "auto":
        return requested
    return "filesystem" if path.is_dir() else "log"


def _cmd_scan(args) -> int:
    settings = AppSettings()
    out = Path(args.out)
    audit_path = Path(args.audit) if args.audit else out.with_suffix(".audit.jsonl")
    audit = AuditLogger(audit_path, actor=args.actor, case_id=out.stem)
    audit.log("cli.scan.start", sources=json.dumps(args.sources), kind=args.kind)
    options = ScanOptions(compute_hashes=args.hashes)

    events = []
    errors = []
    with CaseStore(out, case_id=out.stem) as store:
        store.audit = audit
        for source in args.sources:
            path = Path(source)
            if not path.exists():
                errors.append(f"missing source: {path}")
                continue
            kind = _resolve_kind(path, args.kind)
            collector = FilesystemCollector(path, options=options, audit=audit) if kind == "filesystem" else LogCollector(
                path, options=options, audit=audit
            )
            result = collector.collect(CollectorContext())
            events.extend(result.events)
            errors.extend(result.errors)
            store.add_source(str(path), collector.name, len(result.events))
            print(f"  [{collector.name}] {path}: {len(result.events):,} events ({len(result.errors)} errors)")

        normalizer = TimelineNormalizer(options)
        normalized = normalizer.normalize(events)
        store.add_events(normalized)
        groups = Correlator().correlate(normalized)
        summary = normalizer.summarize(normalized)
        summary["correlation_groups"] = len(groups)

        manifest_path = out.with_suffix(".manifest.json")
        write_manifest(manifest_path, build_manifest(args.sources, case_id=out.stem))

    if args.csv:
        export_csv(normalized, args.csv)
    if args.json:
        export_json(normalized, args.json, metadata={"case_id": out.stem})
    if args.html:
        export_html(normalized, args.html, case_id=out.stem, chain_status="INTACT", version=__version__)

    audit.log("cli.scan.complete", events=len(normalized), errors=len(errors))
    print(f"\nCase store : {out}")
    print(f"Audit log  : {audit_path}")
    print(f"Manifest   : {manifest_path}")
    print(f"Events     : {summary['total']:,}")
    print(f"High/Crit  : {summary['high_or_above']:,}")
    print(f"Correlated : {summary['correlation_groups']} burst group(s)")
    if errors:
        print(f"Errors     : {len(errors)}")
        for error in errors[:10]:
            print(f"  - {error}")
    return 0 if not errors else 2


def _cmd_verify(args) -> int:
    ok, message = verify_audit_chain(args.audit)
    print(f"[{'OK' if ok else 'FAIL'}] {message}")
    return 0 if ok else 1


def _cmd_demo(args) -> int:
    root = Path(args.dir)
    logs = root / "logs"
    data = root / "data"
    logs.mkdir(parents=True, exist_ok=True)
    data.mkdir(parents=True, exist_ok=True)

    (data / "payroll.xlsx").write_text("confidential payroll", encoding="utf-8")
    (data / "notes.txt").write_text("project notes", encoding="utf-8")
    auth_log = logs / "auth.log"
    lines = []
    base = datetime(2026, 6, 1, 8, 0, 0, tzinfo=timezone.utc)
    samples = [
        ("INFO", "user=alice login successful from 10.0.0.5"),
        ("WARNING", "user=bob failed password attempt from 10.0.0.9"),
        ("ERROR", "user=bob failed password attempt from 10.0.0.9"),
        ("ERROR", "user=root authentication failure from 10.0.0.9"),
        ("CRITICAL", "possible brute force detected from 10.0.0.9"),
        ("INFO", "user=alice file access /data/payroll.xlsx"),
    ]
    for i, (level, message) in enumerate(samples):
        ts = (base.replace(minute=i * 3)).strftime("%Y-%m-%dT%H:%M:%SZ")
        lines.append(f"{ts} {level} {message}")
    auth_log.write_text("\n".join(lines) + "\n", encoding="utf-8")

    events = logs / "events.jsonl"
    rows = [
        {"@timestamp": "2026-06-01T08:05:00Z", "level": "info", "host": "srv-01", "user": "alice", "message": "process started", "pid": 4242},
        {"@timestamp": "2026-06-01T08:09:00Z", "level": "error", "host": "srv-01", "user": "bob", "message": "privilege escalation attempt"},
    ]
    events.write_text("\n".join(json.dumps(r) for r in rows) + "\n", encoding="utf-8")

    print(f"Demo case created at {root}")
    print(f"  {auth_log}")
    print(f"  {events}")
    print(f"  {data}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="timeline_builder",
        description=f"TimelineBuilder {__version__} - portable DFIR timeline builder (filesystem + log artifacts)",
    )
    parser.add_argument("--version", action="version", version=f"TimelineBuilder {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    scan = sub.add_parser("scan", help="collect artifacts and build a timeline")
    scan.add_argument("sources", nargs="+", help="files or folders to analyze")
    scan.add_argument("--kind", choices=["auto", "filesystem", "log"], default="auto")
    scan.add_argument("--out", default="timeline.tbcase", help="case store path (SQLite)")
    scan.add_argument("--csv", help="export CSV to this path")
    scan.add_argument("--json", help="export JSON to this path")
    scan.add_argument("--html", help="export colorful HTML report to this path")
    scan.add_argument("--hashes", action="store_true", help="compute SHA-256 for files")
    scan.add_argument("--audit", help="audit log path (default: <case>.audit.jsonl)")
    scan.add_argument("--actor", default="analyst")
    scan.set_defaults(func=_cmd_scan)

    verify = sub.add_parser("verify", help="verify the tamper-evident audit chain")
    verify.add_argument("audit", help="path to audit JSONL")
    verify.set_defaults(func=_cmd_verify)

    demo = sub.add_parser("demo", help="generate a sample case with logs")
    demo.add_argument("--dir", default="demo_case")
    demo.set_defaults(func=_cmd_demo)
    return parser


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    return args.func(args)


if __name__ == "__main__":
    raise SystemExit(main())
