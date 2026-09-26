"""Qt application entry point. Handles the authorized-use consent gate, global
style, and crash logging (security.md — detectability & audit)."""

from __future__ import annotations

import sys
import traceback
from datetime import datetime, timezone

from arp_scanner.security import guard


def _install_excepthook() -> None:
    def hook(exc_type, exc_value, exc_tb):
        details = "".join(traceback.format_exception(exc_type, exc_value, exc_tb))
        stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        try:
            crash = guard.app_data_dir() / "crash.log"
            with crash.open("a", encoding="utf-8") as fh:
                fh.write(f"{stamp} process={__import__('os').getpid()}\n{details}\n")
        except OSError:
            pass
        sys.stderr.write(details)
        sys.exit(1)

    sys.excepthook = hook


def main(argv: list[str] | None = None) -> int:
    _install_excepthook()
    argv = list(sys.argv if argv is None else argv)

    from PySide6.QtWidgets import QApplication, QMessageBox

    app = QApplication(argv)
    app.setApplicationName("ARP Scanner")
    app.setOrganizationName("ArpScanner")
    app.setStyle("Fusion")

    if not guard.consent_given():
        box = QMessageBox(
            QMessageBox.Information,
            "Authorized-use notice",
            guard.CONSENT_NOTICE,
            QMessageBox.NoButton,
        )
        accept = box.addButton("I accept", QMessageBox.AcceptRole)
        box.addButton("Exit", QMessageBox.RejectRole)
        box.setDefaultButton(accept)
        box.exec()
        if box.clickedButton() is not accept:
            guard.audit("operator declined the authorized-use notice; application exited")
            return 0
        guard.acknowledge_consent()

    from arp_scanner.gui.main_window import MainWindow

    window = MainWindow()
    window.show()
    return app.exec()