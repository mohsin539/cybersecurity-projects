"""PyInstaller entry launcher for the portable desktop GUI.

The frozen bundle executes this script as ``__main__``. Launching through an
absolute import (instead of pointing PyInstaller directly at
``redteam_report.gui``) preserves the package context so the GUI's relative
imports resolve inside the one-file executable.
"""

from redteam_report.gui import main

if __name__ == "__main__":
    raise SystemExit(main())