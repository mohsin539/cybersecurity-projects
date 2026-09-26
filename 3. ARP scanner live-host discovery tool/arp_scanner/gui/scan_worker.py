"""Background scan worker. Runs the scan engine in a dedicated QThread so the
GUI stays responsive; all cross-thread communication goes through Qt signals
(archetecture.md §7.3 / GUI design)."""

from __future__ import annotations

import threading

from PySide6.QtCore import QObject, Signal

from arp_scanner.core.config import ScannerConfig
from arp_scanner.core.engine import ScanError, run_scan
from arp_scanner.security import guard as _guard
from arp_scanner.security.guard import PermissionDenied


class ScanWorker(QObject):
    """One-shot worker: instantiate, moveToThread, connect, run()."""

    progress = Signal(int, int)          # done, total
    host_found = Signal(object)          # HostInfo (plain object, no QObject)
    scan_finished = Signal(object)       # ScanResult
    scan_error = Signal(str, str)        # kind ("privilege"|"config"|"runtime"), message
    audit = Signal(str)

    def __init__(self, config: ScannerConfig, parent=None) -> None:
        super().__init__(parent)
        self._config = config
        self._cancel = threading.Event()

    def request_cancel(self) -> None:
        self._cancel.set()

    def run(self) -> None:  # slots connected to QThread.started
        try:
            result = run_scan(
                self._config,
                cancel=self._cancel,
                on_progress=self._on_progress,
                on_host=self._on_host,
                audit=lambda msg: (_guard.audit(msg), self.audit.emit(msg)),
            )
            self.scan_finished.emit(result)
        except PermissionDenied as exc:
            self.audit.emit(f"error: {exc}")
            self.scan_error.emit("privilege", str(exc))
        except ScanError as exc:
            self.audit.emit(f"error: {exc}")
            self.scan_error.emit("runtime" if not isinstance(exc, ValueError) else "config", str(exc))
        except ValueError as exc:
            self.audit.emit(f"error: {exc}")
            self.scan_error.emit("config", str(exc))
        except Exception as exc:  # noqa: BLE001 - surface unexpected failures
            self.audit.emit(f"error: {type(exc).__name__}: {exc}")
            self.scan_error.emit("runtime", f"{type(exc).__name__}: {exc}")
        finally:
            self.thread().quit()

    def _on_progress(self, done: int, total: int) -> None:
        step = max(1, total // 1000)
        if done % step == 0 or done == total:
            self.progress.emit(done, total)

    def _on_host(self, ip: str, mac: str, rtt_ms: float) -> None:
        from arp_scanner.core.result import HostInfo

        self.host_found.emit(
            HostInfo(ip=ip, mac=mac, vendor=None, rtt_ms=rtt_ms, interface=self._config.interface)
        )