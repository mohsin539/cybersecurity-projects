"""Portable application entry point (GUI)."""

from __future__ import annotations

import sys

from PySide6.QtWidgets import QApplication

from .services import AppServices
from .ui.theme import STYLE_SHEET
from .ui.main_window import MainWindow
from .version import APP_NAME


def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName("ACSV")
    app.setOrganizationName("ACSV")
    app.setStyleSheet(STYLE_SHEET)

    services = AppServices()
    win = MainWindow(services)
    win.show()
    exit_code = app.exec()
    services.close()
    return exit_code


if __name__ == "__main__":
    raise SystemExit(main())