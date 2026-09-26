"""Browser Artifact Extractor - application entry point.

Usage
-----
GUI (default)::

    python main.py

Headless / automation (no display required)::

    python main.py --cli --out .\\BAE_Output --decrypt --formats html,csv,json

The CLI mode is convenient for scheduled, auditable collections; the GUI offers
the same engine with an interactive console.
"""
from __future__ import annotations

import argparse
import os
import sys
from datetime import datetime

os.environ.setdefault("PYTHONUTF8", "1")

# Ensure the project root is importable when frozen or launched from elsewhere.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))


def _enable_dpi_awareness() -> None:
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(1)
        except Exception:  # noqa: BLE001
            ctypes.windll.user32.SetProcessDPIAware()
    except Exception:  # noqa: BLE001
        pass


def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(prog="BrowserArtifactExtractor",
                                description="Portable browser artifact extractor (history, cookies, cache).")
    p.add_argument("--cli", action="store_true", help="Run headless instead of opening the GUI.")
    p.add_argument("--out", default="", help="Output directory for reports.")
    p.add_argument("--formats", default="html,csv,json,xlsx",
                   help="Comma-separated report formats (html,csv,json,xml,xlsx,pdf,md).")
    p.add_argument("--categories", default="history,downloads,cookies,bookmarks,autofill,logins,search_terms,cache",
                   help="Comma-separated artifact categories to collect.")
    p.add_argument("--profiles", default="", help="Comma-separated profile labels to include (default: all).")
    p.add_argument("--decrypt", action="store_true", help="Decrypt cookie/login secrets (opt-in consent).")
    p.add_argument("--max-records", type=int, default=0, help="Max records per category (0 = unlimited).")
    p.add_argument("--operator", default=os.environ.get("USERNAME", "operator"))
    p.add_argument("--case", default="", help="Case reference for the report header.")
    return p


def run_cli(args: argparse.Namespace) -> int:
    from core.engine import Engine
    from core.models import ScanOptions
    from report import exporters
    from sec import compliance
    from sec.audit import AuditLogger

    out_dir = args.out or os.path.join(os.getcwd(), "BAE_Output",
                                       f"run_{datetime.now():%Y%m%d_%H%M%S}")
    os.makedirs(out_dir, exist_ok=True)
    log_path = os.path.join(out_dir, "audit_log.jsonl")
    logger = AuditLogger(path=log_path, actor=args.operator)

    categories = [c.strip() for c in args.categories.split(",") if c.strip()]
    formats = ["." + f.strip().lstrip(".") for f in args.formats.split(",") if f.strip()]

    opts = ScanOptions(
        categories=categories,
        profile_filter=[p.strip() for p in args.profiles.split(",") if p.strip()],
        decrypt_secrets=args.decrypt,
        extract_cache_urls=True,
        max_records_per_category=args.max_records,
    )
    logger.notice("cli.start", "CLI collection started", case=args.case,
                  categories=categories, decrypt=args.decrypt)

    def progress(message: str, fraction: float) -> None:
        sys.stdout.write(f"\r[{fraction * 100:5.1f}%] {message[:70]:<70}")
        sys.stdout.flush()

    engine = Engine(opts, logger, progress=progress)
    scan = engine.run()
    scan.case_ref = args.case
    scan.operator = args.operator
    print()

    written = exporters.export_all(out_dir, scan, formats)
    exporters.export_audit_log(os.path.join(out_dir, "audit_log.jsonl"), logger.entries)

    print("\n=== Collection summary ===")
    print(f"Scan ID      : {scan.scan_id}")
    print(f"Host         : {scan.host} ({scan.platform})")
    print(f"Profiles     : {scan.statistics.get('profiles_scanned', 0)}")
    print(f"Records      : {scan.statistics.get('total_records', 0):,}")
    print(f"Elapsed      : {scan.statistics.get('elapsed_seconds', 0)}s")
    print(f"Audit chain  : {'VALID' if scan.integrity.get('audit_chain_valid') else 'BROKEN'}")
    print(f"Manifest     : {scan.integrity.get('manifest', {}).get('manifest_sha256', '')}")
    print(f"Coverage     : {scan.integrity.get('compliance', {}).get('coverage_percent', 0)}% "
          f"({compliance.assessment()['control_count']} controls)")
    print("\nReports:")
    for name, path in written.items():
        print(f"  {name:<8} -> {path}")
    if scan.errors:
        print("\nWarnings:")
        for err in scan.errors:
            print(f"  - {err}")
    return 0


def main(argv=None) -> int:
    args = build_parser().parse_args(argv)
    if args.cli:
        return run_cli(args)
    _enable_dpi_awareness()
    from ui.app import run as run_gui
    run_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
