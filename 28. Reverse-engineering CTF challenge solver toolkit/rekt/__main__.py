"""REkt entry point. Strict stdlib bootstrap before any GUI import (§3.1)."""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from rekt import APP_NAME, __version__


def _default_plugin_dir() -> Path:
    """Bundled plugins: next to the code (frozen: sys._MEIPASS/_internal)."""
    if getattr(sys, "frozen", False):
        return Path(getattr(sys, "_MEIPASS", "")) / "plugins"
    return Path(__file__).resolve().parents[1] / "plugins"


def _resolve_paths(args) -> tuple[Path, Path, Path]:
    from rekt.platform.config import app_data_dir

    base = Path(args.data_dir) if args.data_dir else app_data_dir()
    plugin_dir = Path(args.plugins) if getattr(args, "plugins", None) else _default_plugin_dir()
    return base / "projects" / "default", base / "audit.log", plugin_dir


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    # Frozen sandbox child dispatch — must run before any GUI/bootstrap import.
    # (A frozen .exe cannot launch 'python child.py'; it re-invokes itself.)
    if argv and argv[0] == "--rekt-sandbox-child":
        from rekt.sandbox.child import run as run_child
        return run_child(argv[1])

    parser = argparse.ArgumentParser(prog="rekt", description=f"{APP_NAME} {__version__}")
    parser.add_argument("--data-dir", help="portable data directory (NFR-1)")
    parser.add_argument("--plugins", help="plugin directory override")
    parser.add_argument("--version", action="version", version=f"{APP_NAME} {__version__}")
    args = parser.parse_args(argv)

    project_dir, audit_path, plugin_dir = _resolve_paths(args)

    # Platform layer first (no GUI deps)
    from rekt.platform.audit import AuditLog
    from rekt.platform.config import Config, load_config

    cfg = load_config()
    audit = AuditLog(audit_path)
    ok, msg = audit.verify()
    if not ok:
        print(f"[rekt] WARNING: audit log failed integrity check: {msg}", file=sys.stderr)

    from rekt.platform.store import ProjectStore

    store = ProjectStore(project_dir)

    from rekt.application.jobs import JobService

    jobs = JobService(store, audit, project_dir / "scratch")

    # GUI last
    try:
        from PySide6.QtWidgets import QApplication
    except ImportError:
        print("[rekt] PySide6 is not installed — run: pip install PySide6", file=sys.stderr)
        return 2

    from rekt.presentation.app import MainWindow
    from rekt.presentation.theme import QSS

    app = QApplication(sys.argv)
    app.setApplicationName(APP_NAME)
    app.setStyleSheet(QSS)
    audit.append("session.start", version=__version__)
    win = MainWindow(cfg, store, audit, jobs, plugin_dir)
    win.show()
    code = app.exec()
    store.close()
    return code


if __name__ == "__main__":
    sys.exit(main())
