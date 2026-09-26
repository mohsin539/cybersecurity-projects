"""RecovPro Secure — application entry point.

Usage:
    python app/main.py                    launch portable GUI
    python app/main.py --selftest         run engine self-test, then exit
    python app/main.py --diagnose         write diagnostics.txt, then exit
    python app/main.py --nowarn           suppress performance warnings

Consumer usage (portable bundle):
    RecovProSecure.exe  [--selftest | --diagnose]
"""

from __future__ import annotations

import argparse
import os
import sys

APP_DIR = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(APP_DIR)
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

os.environ.setdefault("QT_ENABLE_HIGHDPI_SCALING", "1")


def _selftest() -> int:
    from app.tests.smoke import run_smoke
    return 0 if run_smoke() else 1


def _diagnose() -> int:
    from app.launcher import write_diagnostics
    path = write_diagnostics()
    print("diagnostics written to", path)
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="recovpro")
    parser.add_argument("--selftest", action="store_true",
                        help="Run the read-only recovery self-test against "
                             "synthetic FAT32+NTFS images and exit.")
    parser.add_argument("--diagnose", action="store_true",
                        help="Probe the environment, write diagnostics.txt "
                             "next to the executable, then exit.")
    parser.add_argument("--nowarn", action="store_true",
                        help="Suppress performance-friendly warnings")
    args = parser.parse_args()

    if args.selftest:
        return _selftest()
    if args.diagnose:
        return _diagnose()

    from app.launcher import install_guard, write_fault, bundle_dir
    install_guard()

    from PySide6.QtWidgets import QApplication, QMessageBox
    from app import __product__, __version__

    app = QApplication(sys.argv)
    app.setApplicationName(__product__)
    app.setApplicationVersion(__version__)
    app.setOrganizationName("RecovPro")

    try:
        from app.ui.main_window import MainWindow
        win = MainWindow()
        win.show()
    except Exception as exc:  # noqa: BLE001  → never fail silently
        path = write_fault(exc, stage="gui-startup")
        box = QMessageBox()
        box.setIcon(QMessageBox.Critical)
        box.setWindowTitle(f"{__product__} — startup failed")
        box.setText("The application could not start.")
        box.setInformativeText(
            f"{type(exc).__name__}: {exc}\n\n"
            "A fault report was written to:\n"
            f"{path}\n\n"
            "If you copied only RecovProSecure.exe, also copy the entire "
            "folder (it needs the _internal directory next to it). "
            f"Bundle folder: {bundle_dir()}"
        )
        box.exec()
        return 3

    return app.exec()


if __name__ == "__main__":
    sys.exit(main())