#!/usr/bin/env python3
"""Entry point: python main.py  →  launches the Tkinter GUI."""
from __future__ import annotations

import sys


def main() -> int:
    try:
        import tkinter  # noqa: F401
    except ImportError:
        print("tkinter is not available in this Python build.\n"
              "Install Python with tcl/tk enabled (python.org installer "
              "includes it by default).")
        return 1
    from gui.app import main as gui_main
    gui_main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
