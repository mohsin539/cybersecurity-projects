"""GUI entry point (mirrors pyproject [project.scripts] portscan-gui).

Used by PyInstaller as the windowed-exe entry script; also runnable directly
with `py scripts/portscan_gui.py` from the repo root.
"""
from __future__ import annotations

import sys
from pathlib import Path

if not __package__:  # direct (non-frozen, non-module) execution
    sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from portscanner.gui import main  # noqa: E402

if __name__ == "__main__":
    main()
