"""Entry point: `python -m sap`.

- No CLI subcommand  -> launches the portable GUI (default UX for the .exe)
- With a subcommand  -> runs the headless CLI (`scan`, `verify`, `seal`, ...)
"""
from __future__ import annotations

import sys

from sap.cli import main

if __name__ == "__main__":
    sys.exit(main())