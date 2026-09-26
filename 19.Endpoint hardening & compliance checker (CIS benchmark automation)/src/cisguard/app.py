"""GUI entrypoint: `python -m cisguard.app [--demo] [data_dir]`."""

from __future__ import annotations

import sys
from pathlib import Path


def main() -> int:
    from cisguard.gui.main_window import run_gui

    args = [a for a in sys.argv[1:]]
    demo = "--demo" in args
    args = [a for a in args if a != "--demo"]
    data_dir = Path(args[0]) if args else None
    return run_gui(data_dir, demo=demo)


if __name__ == "__main__":
    raise SystemExit(main())
