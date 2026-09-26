"""`cisguard` CLI: scan / report / history."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from cisguard import APP_NAME, __version__
from cisguard.domain.errors import CGError


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser(prog="cisguard", description=f"{APP_NAME} — CIS benchmark assessment (read-only)")
    ap.add_argument("--data-dir", default=str(Path.home() / "CISGuard"))
    ap.add_argument("--demo", action="store_true", help="use in-memory collectors (offline demo mode)")
    ap.add_argument("--version", action="version", version=f"cisguard {__version__}")
    sub = ap.add_subparsers(dest="cmd", required=True)

    p_scan = sub.add_parser("scan", help="run an assessment")
    p_scan.add_argument("--out", default=None, help="output base path (writes .html/.json/.csv)")
    p_scan.add_argument("--json", action="store_true", help="print JSON summary to stdout")

    sub.add_parser("history", help="list past scans")

    args = ap.parse_args(argv)

    try:
        from cisguard.composition import AppContext

        ctx = AppContext.open(Path(args.data_dir), use_test_collectors=args.demo)
        try:
            if args.cmd == "scan":
                record = ctx.scan_service.scan(
                    progress=lambda d, t, cid: print(f"\r[{d}/{t}] {cid}", end="", flush=True)
                )
                print()
                s = record.summary
                print(f"score={s.score}  passed={s.passed}  failed={s.failed}  "
                      f"errors={s.errors}  n/a={s.not_applicable}  (scan {s.scan_id})")
                ctx.history.save(record)
                if args.out:
                    base = Path(args.out)
                    base.parent.mkdir(parents=True, exist_ok=True)
                    ctx.reports.export_html(record, base.with_suffix(".html"))
                    ctx.reports.export_json(record, base.with_suffix(".json"))
                    ctx.reports.export_csv(record, base.with_suffix(".csv"))
                    print(f"reports written: {base}.html/.json/.csv")
                if args.json:
                    import json

                    print(json.dumps({
                        "scan_id": s.scan_id, "score": s.score, "passed": s.passed,
                        "failed": s.failed, "errors": s.errors,
                    }))
                # rc: 0 = fully compliant; 1 = failures; 2 = errors only
                return 1 if s.failed else 0

            if args.cmd == "history":
                rows = ctx.history.list_scans()
                print(f"{'scan id':12s}  {'started':20s}  {'host':15s}  {'score':>5s}  P/F/E")
                for rid, started, host, score, passed, failed, errors in rows:
                    print(f"{rid:12s}  {started[:19]:20s}  {host[:15]:15s}  {score:5.1f}  {passed}/{failed}/{errors}")
        finally:
            ctx.close()
    except CGError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 3
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
