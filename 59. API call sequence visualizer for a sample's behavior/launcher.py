"""Portable launcher (PyInstaller entry point).

Runs the `acsv` package from a top-level script so the package's relative
imports (`from .x import ...`) resolve correctly. In the frozen onefile build
`_MEIPASS` is already on sys.path, where the `acsv/` tree lives.
"""

from __future__ import annotations

import sys
import traceback
from pathlib import Path


def _crash_log() -> Path:
    base = Path.cwd()
    for cand in (
        Path.cwd() / "data",
        Path.home() / "AppData" / "Local" / "ACSV" if sys.platform == "win32" else Path.home() / ".acsv",
    ):
        try:
            cand.mkdir(parents=True, exist_ok=True)
            base = cand
            break
        except OSError:
            continue
    return base / "crash.log"


def main() -> int:
    from acsv.app import main as app_main

    return app_main()


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except BaseException as exc:  # noqa: BLE001 - last-ditch user-facing report
        try:
            _crash_log().write_text(
                "ACSV crash log\n" + traceback.format_exc(),
                encoding="utf-8",
            )
        except OSError:
            pass
        print(f"ACSV fatal error: {exc}", file=sys.stderr)
        from PySide6.QtWidgets import QMessageBox

        QMessageBox.critical(
            None,
            "ACSV error",
            f"An internal error occurred.\n\n{type(exc).__name__}: {exc}\n\n"
            "Details were written to the crash log.",
        )
        raise SystemExit(70)