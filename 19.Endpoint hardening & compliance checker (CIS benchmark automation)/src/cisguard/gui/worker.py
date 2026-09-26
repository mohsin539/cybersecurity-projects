"""GUI worker bridge: scan runs off the GUI thread; results via signals."""

from __future__ import annotations

from PySide6.QtCore import QObject, QThread, Signal


class ScanWorker(QObject):
    finished = Signal(object)          # ScanRecord
    failed = Signal(str)               # redacted message
    progress = Signal(int, int, str)   # done, total, control_id

    def __init__(self, scan_service) -> None:
        super().__init__()
        self._scan = scan_service
        self._thread: QThread | None = None

    def start(self) -> None:
        self._thread = QThread(self)
        self.moveToThread(self._thread)
        self._thread.started.connect(self._run)
        self._thread.start()

    def _run(self) -> None:
        try:
            record = self._scan.scan(progress=lambda d, t, cid: self.progress.emit(d, t, cid))
            self.finished.emit(record)
        except Exception as exc:
            self.failed.emit(f"{type(exc).__name__}: {exc}")
        finally:
            self._thread.quit()
