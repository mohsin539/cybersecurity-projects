"""Launcher for the Log Anonymizer desktop GUI (also the PyInstaller entry)."""
from __future__ import annotations

import sys
from pathlib import Path

SRC_DIR = Path(__file__).resolve().parent / "src"
if SRC_DIR.exists() and str(SRC_DIR) not in sys.path:
    sys.path.insert(0, str(SRC_DIR))


def main() -> int:
    try:
        from anonymizer.gui.main_window import run_app

        run_app()
    except ImportError as exc:
        print(f"cannot start GUI: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())