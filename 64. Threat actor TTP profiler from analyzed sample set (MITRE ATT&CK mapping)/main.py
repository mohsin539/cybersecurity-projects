#!/usr/bin/env python3
"""Threat Actor TTP Profiler — portable entry point.

Usage:
  TTPProfiler.exe                        # launch GUI
  TTPProfiler.exe --import <dir> --name "set" --profile --export <out>   # headless
  TTPProfiler.exe --verify               # self-audit
Flags:
  --workspace <dir>   runtime data root (default: ./workspace)
  --no-encrypt        disable DPAPI field encryption (explicit opt-out)
  --offscreen         force Qt offscreen platform (CI/headless)
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import tempfile
from pathlib import Path

from app import APP_NAME, APP_SLUG, __version__
from app.security import AuditChain
from app.services import Importer, ImportError_, ProfilerEngine
from app.store import SecureStore


def _default_workspace() -> Path:
    here = Path(sys.argv[0]).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parent
    return here / "workspace"


def bootstrap(workspace: Path, no_encrypt: bool = False):
    ws = Path(workspace)
    ws.mkdir(parents=True, exist_ok=True)
    store = SecureStore(ws, encrypt_evidence=not no_encrypt)
    audit = AuditChain(store)
    return store, audit, ws


def run_headless(args: argparse.Namespace) -> int:
    store, audit, ws = bootstrap(Path(args.workspace), no_encrypt=getattr(args, "no_encrypt", False))
    if args.verify:
        print(json.dumps(verify_self(store, audit), indent=2))
        return 0
    set_id = f"local-cmdline"
    imp = Importer(store, audit, namespace="cli")
    try:
        result = imp.ingest_directory(args.import_dir, set_id, args.name or Path(args.import_dir).name)
    except ImportError_ as exc:
        print(f"IMPORT_ERROR {exc}", file=sys.stderr)
        return 2
    print(json.dumps({
        "import": {"set": set_id, "samples": len(result.samples), "errors": result.errors},
    }, indent=2))
    if args.profile:
        engine = ProfilerEngine(store, audit)
        profile = engine.build_profile(set_id, namespace="cli")
        if not profile:
            print("NO_PROFILE", file=sys.stderr)
            return 3
        payload = profile.summary()
        if args.export:
            from app import reports as R
            manifest = R.write_all(profile, Path(args.export), args.name or "", result.samples)
            payload["exports"] = manifest
        print(json.dumps(payload, indent=2))
    store.close()
    return 0


def verify_self(store: SecureStore, audit: AuditChain) -> dict:
    out = {"app": APP_NAME, "version": __version__}
    try:
        rows = store.conn.execute("PRAGMA integrity_check").fetchall()
        out["sqlite_integrity"] = all(r[0] == "ok" for r in rows)
    except Exception as exc:  # noqa: BLE001
        out["sqlite_integrity"] = False
        out["sqlite_error"] = str(exc)
    out["encryption"] = "DPAPI AES-256-GCM" if store.encrypt_evidence else "PLAINTEXT (opt-out)"
    audit_rows = store.audit_rows(5)
    out["audit_entries"] = len(store.audit_rows(10000))
    out["audit_chain_head"] = audit.last_hash[:24] + "…"
    out["database"] = str(store.db_path)
    return out


def launch_gui(workspace: Path, no_encrypt: bool, offscreen: bool) -> int:
    from PySide6.QtWidgets import QApplication
    if offscreen:
        os.environ.setdefault("QT_QPA_PLATFORM", "offscreen")
    store, audit, ws = bootstrap(workspace, no_encrypt=no_encrypt)
    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setOrganizationName(APP_SLUG)
    from app.windows import MainWindow
    win = MainWindow(store, audit, ws)
    win.show()
    code = app.exec()
    store.close()
    return code


def main() -> int:
    parser = argparse.ArgumentParser(prog=APP_SLUG, description=APP_NAME)
    parser.add_argument("--workspace", default=str(_default_workspace()))
    parser.add_argument("--no-encrypt", action="store_true")
    parser.add_argument("--offscreen", action="store_true")
    parser.add_argument("--verify", action="store_true")
    parser.add_argument("--import", dest="import_dir")
    parser.add_argument("--name", default="Sample Set")
    parser.add_argument("--profile", action="store_true")
    parser.add_argument("--export")
    args = parser.parse_args()

    if args.verify and not args.import_dir:
        store, audit, ws = bootstrap(Path(args.workspace), no_encrypt=args.no_encrypt)
        print(json.dumps(verify_self(store, audit), indent=2))
        return 0
    if args.import_dir:
        return run_headless(args)
    return launch_gui(Path(args.workspace), args.no_encrypt, args.offscreen)


if __name__ == "__main__":
    raise SystemExit(main())