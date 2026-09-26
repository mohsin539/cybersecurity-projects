"""StaticLab entry point: `python -m app [--cli FILE [--json]]` or GUI by default."""

from __future__ import annotations

import argparse
import json
import os
import sys

from . import __version__
from .config import app_data_dir


def _cli(args: argparse.Namespace) -> int:
    from .config import Config
    from .core.audit import AuditStore
    from .core.pipeline import analyze
    from .report.exporter import export_html, export_json, export_txt

    if not args.file or not os.path.isfile(args.file):
        print(f"[StaticLab v{__version__}] error: file not found: {args.file}", file=sys.stderr)
        return 2

    cfg = Config(app_data_dir())
    store = AuditStore(app_data_dir() / "audit.db", _load_audit_key())
    enabled = [p for p in cfg.get("providers", [])] if args.lookup else []

    def repo(step: int, total: int, label: str) -> None:
        print(f"[{step}/{total}] {label}", file=sys.stderr)

    result = analyze(
        args.file,
        config=cfg.secrets_payload(),
        audit=store,
        progress=repo,
        min_string_len=int(cfg.get("min_string_len", 4)),
        lookups_enabled=enabled,
    )
    store.close()

    if args.format == "json":
        print(export_json(result))
    elif args.format == "txt":
        print(export_txt(result))
    else:
        print(export_html(result))
    return 0


def _load_audit_key() -> bytes:
    from .core.audit import AuditStore  # noqa: F401 (module side effect import)
    key_file = app_data_dir() / "audit.key"
    if key_file.exists():
        return key_file.read_bytes()
    key = os.urandom(32)
    key_file.write_bytes(key)
    return key


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="staticlab", description="Portable static-analysis pipeline")
    parser.add_argument("--cli", dest="file", metavar="FILE", help="headless analysis of FILE")
    parser.add_argument("--format", choices=["html", "json", "txt"], default="html", help="CLI output format")
    parser.add_argument("--no-lookup", dest="lookup", action="store_false", help="skip threat-intel lookups")
    parser.add_argument("--version", action="version", version=f"StaticLab {__version__}")
    ns = parser.parse_args(argv)

    if ns.file:
        return _cli(ns)

    from .gui.app import run_gui

    run_gui()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())