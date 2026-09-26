"""Main application window (PySide6). Provides the scan form, live results
table, progress reporting, audit pane, export actions, and worker lifecycle
management (archetecture.md §7.1, §9)."""

from __future__ import annotations

import time

from PySide6.QtCore import Qt, QThread
from PySide6.QtGui import QAction, QKeySequence
from PySide6.QtWidgets import (
    QAbstractItemView,
    QCheckBox,
    QComboBox,
    QDoubleSpinBox,
    QFileDialog,
    QGridLayout,
    QGroupBox,
    QHeaderView,
    QLabel,
    QLineEdit,
    QMainWindow,
    QMessageBox,
    QPlainTextEdit,
    QProgressBar,
    QPushButton,
    QSpinBox,
    QTableWidget,
    QTableWidgetItem,
    QVBoxLayout,
    QWidget,
)

from arp_scanner.core.config import ScannerConfig
from arp_scanner.core.engine import detect_interface, get_local_address, list_interfaces
from arp_scanner.gui.scan_worker import ScanWorker
from arp_scanner.report.exporters import write_export
from arp_scanner.security import guard
from arp_scanner.util.net import TargetError, expand_target

_COLUMNS = ("IP Address", "MAC Address", "Vendor", "RTT (ms)", "Interface")


class MainWindow(QMainWindow):
    def __init__(self) -> None:
        super().__init__()
        self._worker: ScanWorker | None = None
        self._thread: QThread | None = None
        self._last_result = None
        self._build_ui()
        self._build_menu()
        self._refresh_interfaces(autodetect=True)
        self.log("application started — scans are logged to the audit log")

    # ------------------------------------------------------------------ UI

    def _build_ui(self) -> None:
        self.setWindowTitle("ARP Scanner — Live-Host Discovery")
        self.resize(980, 720)

        central = QWidget(self)
        root = QVBoxLayout(central)

        title = QLabel("ARP Live-Host Discovery Tool")
        title.setStyleSheet("font-size: 18px; font-weight: 600;")
        root.addWidget(title)
        subtitle = QLabel(
            "Probes a subnet with ARP who-has requests and lists responding hosts (IP, MAC, vendor). "
            "Run only on networks you are authorized to scan."
        )
        subtitle.setWordWrap(True)
        root.addWidget(subtitle)

        # ---- scan parameters
        form = QGroupBox("Scan Parameters")
        grid = QGridLayout(form)

        grid.addWidget(QLabel("Target"), 0, 0)
        self.target_edit = QLineEdit()
        self.target_edit.setPlaceholderText("192.168.1.0/24  or  192.168.1.1-192.168.1.50")
        self.target_edit.returnPressed.connect(self._on_start)
        grid.addWidget(self.target_edit, 0, 1, 1, 3)

        grid.addWidget(QLabel("Interface"), 1, 0)
        self.iface_combo = QComboBox()
        self.iface_combo.setMinimumWidth(200)
        grid.addWidget(self.iface_combo, 1, 1)
        self.refresh_iface_btn = QPushButton("Refresh")
        self.refresh_iface_btn.clicked.connect(lambda: self._refresh_interfaces())
        grid.addWidget(self.refresh_iface_btn, 1, 2)

        grid.addWidget(QLabel("Timeout (s)"), 1, 3)
        self.timeout_spin = QDoubleSpinBox()
        self.timeout_spin.setRange(0.05, 60.0)
        self.timeout_spin.setValue(1.0)
        self.timeout_spin.setSingleStep(0.1)
        grid.addWidget(self.timeout_spin, 1, 4)

        grid.addWidget(QLabel("Retries"), 2, 0)
        self.retries_spin = QSpinBox()
        self.retries_spin.setRange(0, 10)
        self.retries_spin.setValue(1)
        grid.addWidget(self.retries_spin, 2, 1)

        self.reserved_chk = QCheckBox("Include network/broadcast addresses")
        grid.addWidget(self.reserved_chk, 2, 2, 1, 2)
        self.large_chk = QCheckBox("Allow very large subnets (…/16 and larger)")
        grid.addWidget(self.large_chk, 2, 4)

        self.start_btn = QPushButton("Start Scan")
        self.start_btn.setStyleSheet("font-weight: 600;")
        self.start_btn.clicked.connect(self._on_start)
        grid.addWidget(self.start_btn, 3, 0, 1, 2)
        self.stop_btn = QPushButton("Stop")
        self.stop_btn.setEnabled(False)
        self.stop_btn.clicked.connect(self._on_stop)
        grid.addWidget(self.stop_btn, 3, 2)

        self.local_label = QLabel("Local: —")
        self.local_label.setStyleSheet("color: #666;")
        grid.addWidget(self.local_label, 3, 3, 1, 2)

        root.addWidget(form)

        # ---- stats / progress
        self.stats_label = QLabel("No scan yet.")
        root.addWidget(self.stats_label)
        self.progress_bar = QProgressBar()
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        root.addWidget(self.progress_bar)

        # ---- results table
        self.table = QTableWidget(0, len(_COLUMNS))
        self.table.setHorizontalHeaderLabels(_COLUMNS)
        self.table.setEditTriggers(QAbstractItemView.NoEditTriggers)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.verticalHeader().setVisible(False)
        header = self.table.horizontalHeader()
        header.setSectionResizeMode(0, QHeaderView.Stretch)
        header.setSectionResizeMode(1, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(2, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        header.setSectionResizeMode(4, QHeaderView.ResizeToContents)
        root.addWidget(self.table, stretch=3)

        # ---- audit pane
        audit_box = QGroupBox("Audit Log")
        audit_layout = QVBoxLayout(audit_box)
        self.audit_pane = QPlainTextEdit()
        self.audit_pane.setReadOnly(True)
        self.audit_pane.setMaximumBlockCount(1500)
        self.audit_pane.setPlaceholderText("Scan and security events appear here.")
        audit_layout.addWidget(self.audit_pane)
        root.addWidget(audit_box, stretch=1)

        self.setCentralWidget(central)

    def _build_menu(self) -> None:
        bar = self.menuBar()

        file_menu = bar.addMenu("&File")
        export_csv = QAction("Export CSV…", self)
        export_csv.setShortcut(QKeySequence("Ctrl+Shift+S"))
        export_csv.triggered.connect(lambda: self._export("csv"))
        export_json = QAction("Export JSON…", self)
        export_json.triggered.connect(lambda: self._export("json"))
        exit_action = QAction("Exit", self)
        exit_action.setShortcut(QKeySequence.StandardKey.Quit)
        exit_action.triggered.connect(self.close)
        file_menu.addAction(export_csv)
        file_menu.addAction(export_json)
        file_menu.addSeparator()
        file_menu.addAction(exit_action)

        scan_menu = bar.addMenu("&Scan")
        start_action = QAction("Start Scan", self)
        start_action.setShortcut(QKeySequence("Ctrl+R"))
        start_action.triggered.connect(self._on_start)
        stop_action = QAction("Stop", self)
        stop_action.triggered.connect(self._on_stop)
        scan_menu.addAction(start_action)
        scan_menu.addAction(stop_action)

        security_menu = bar.addMenu("&Security")
        notice_action = QAction("View authorized-use notice…", self)
        notice_action.triggered.connect(self._show_consent)
        open_audit = QAction("Open audit log file", self)
        open_audit.triggered.connect(self._open_audit_file)
        open_data = QAction("Open application data folder", self)
        open_data.triggered.connect(self._open_data_folder)
        security_menu.addAction(notice_action)
        security_menu.addSeparator()
        security_menu.addAction(open_audit)
        security_menu.addAction(open_data)

        help_menu = bar.addMenu("&Help")
        about_action = QAction("About", self)
        about_action.triggered.connect(self._show_about)
        help_menu.addAction(about_action)

    # ------------------------------------------------------------- helpers

    def log(self, message: str) -> None:
        guard.audit(message)
        self.audit_pane.appendPlainText(message)

    def _refresh_interfaces(self, autodetect: bool = False) -> None:
        current = self.iface_combo.currentText()
        try:
            names = list_interfaces()
        except Exception as exc:  # noqa: BLE001
            self.iface_combo.clear()
            self.iface_combo.addItem("auto")
            self.local_label.setText(f"Local: interface enumeration failed ({exc})")
            return
        self.iface_combo.clear()
        self.iface_combo.addItem("auto")
        self.iface_combo.addItems(names)
        if autodetect:
            try:
                detected = detect_interface()
                idx = self.iface_combo.findText(detected)
                if idx > 0:
                    self.iface_combo.setCurrentIndex(idx)
            except Exception:  # noqa: BLE001
                pass
        elif current:
            idx = self.iface_combo.findText(current)
            if idx > 0:
                self.iface_combo.setCurrentIndex(idx)
        self._update_local_label()

    def _update_local_label(self) -> None:
        name = self.iface_combo.currentText().strip()
        if not name or name == "auto":
            self.local_label.setText("Local: auto (selecting default interface)")
            return
        try:
            ip4, mac = get_local_address(name)
            self.local_label.setText(f"Local: {ip4}  ({mac})  on {name}")
        except Exception as exc:  # noqa: BLE001
            self.local_label.setText(f"Local: {exc}")

    def _selected_iface(self) -> str:
        return self.iface_combo.currentText().strip() or "auto"

    # ------------------------------------------------------------ actions

    def _on_start(self) -> None:
        if self._thread is not None and self._thread.isRunning():
            return
        target = self.target_edit.text().strip()
        try:
            addresses = expand_target(target)
        except TargetError as exc:
            QMessageBox.warning(self, "Invalid target", str(exc))
            return

        if len(addresses) > 65_534 and not self.large_chk.isChecked():
            answer = QMessageBox.question(
                self,
                "Large scan",
                f"Target expands to {len(addresses)} addresses. This may take a very long time. Continue?",
                QMessageBox.Yes | QMessageBox.No,
                QMessageBox.No,
            )
            if answer != QMessageBox.Yes:
                return

        config = ScannerConfig(
            target=target,
            interface=self._selected_iface(),
            timeout=self.timeout_spin.value(),
            retries=self.retries_spin.value(),
            workers=16,
            quiet=False,
            verbose=False,
            include_reserved=self.reserved_chk.isChecked(),
            allow_large=self.large_chk.isChecked(),
        )
        try:
            config.validate()
        except ValueError as exc:
            QMessageBox.warning(self, "Invalid configuration", str(exc))
            return

        self._reset_for_scan()
        self._update_local_label()
        self.log(f"starting scan: {len(addresses)} targets, interface={config.interface}")

        thread = QThread(self)
        worker = ScanWorker(config)
        worker.moveToThread(thread)
        thread.started.connect(worker.run)
        worker.progress.connect(self._on_progress)
        worker.scan_finished.connect(self._on_finished)
        worker.scan_error.connect(self._on_error)
        worker.audit.connect(self.audit_pane.appendPlainText)
        worker.scan_finished.connect(self._set_last_result)
        thread.finished.connect(self._on_scan_finished_reset)
        thread.finished.connect(worker.deleteLater)
        thread.finished.connect(thread.deleteLater)

        self._thread = thread
        self._worker = worker
        self.start_btn.setEnabled(False)
        self.stop_btn.setEnabled(True)
        thread.start()

    def _on_stop(self) -> None:
        if self._worker is not None:
            self.log("stop requested by operator")
            self._worker.request_cancel()
            self.stop_btn.setEnabled(False)

    def _on_progress(self, done: int, total: int) -> None:
        self.progress_bar.setRange(0, max(1, total))
        self.progress_bar.setValue(done)
        self.stats_label.setText(f"Probing… {done}/{total} addresses")
        self.statusBar().showMessage(f"Scanning… {done}/{total}")

    def _set_last_result(self, result) -> None:
        self._last_result = result

    def _on_finished(self, result) -> None:
        self.table.setRowCount(0)
        for host in result.hosts_sorted:
            row = self.table.rowCount()
            self.table.insertRow(row)
            values = (
                host.ip,
                host.mac,
                host.vendor or "unknown",
                f"{host.rtt_ms:.2f}",
                host.interface,
            )
            for col, text in enumerate(values):
                item = QTableWidgetItem(str(text))
                item.setFlags(item.flags() & ~Qt.ItemIsEditable)
                self.table.setItem(row, col, item)
        self.progress_bar.setValue(self.progress_bar.maximum())
        self.stats_label.setText(
            f"Completed: {len(result.hosts_sorted)} / {len(result.targets)} hosts live on "
            f"{result.interface} in {result.duration_s:.2f}s"
        )
        self.statusBar().showMessage("Scan complete — use File → Export to save results.")
        self.log(
            f"scan finished: {len(result.hosts_sorted)} host(s) live, "
            f"{result.duration_s:.2f}s, interface={result.interface}"
        )

    def _on_error(self, kind: str, message: str) -> None:
        self.audit_pane.appendPlainText(f"[error:{kind}] {message}")
        if kind == "privilege":
            box = QMessageBox(QMessageBox.Warning, "Privileges required", message, QMessageBox.Ok, self)
            box.exec()
        else:
            QMessageBox.warning(self, "Scan error", message)

    def _on_scan_finished_reset(self) -> None:
        self.start_btn.setEnabled(True)
        self.stop_btn.setEnabled(False)
        self._worker = None
        self._thread = None

    def _export(self, fmt: str) -> None:
        if self._last_result is None:
            QMessageBox.information(self, "Nothing to export", "Run a scan first.")
            return
        stamp = time.strftime("%Y%m%d-%H%M%S")
        fname, _ = QFileDialog.getSaveFileName(
            self,
            f"Export {fmt.upper()}",
            f"arpscan_{stamp}.{fmt}",
            f"{fmt.upper()} files (*.{fmt})",
        )
        if not fname:
            return
        try:
            path = guard.validate_export_path(fname)
            written = write_export(str(path), self._last_result, fmt)
            self.log(f"exported {fmt.upper()} to {written}")
            QMessageBox.information(
                self,
                "Export complete",
                f"{len(self._last_result.hosts_sorted)} host(s) written to:\n{written}",
            )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Export failed", str(exc))

    def _show_consent(self) -> None:
        QMessageBox.information(self, "Authorized-use notice", guard.CONSENT_NOTICE)

    def _open_audit_file(self) -> None:
        import os

        try:
            os.startfile(str(guard.app_data_dir() / "audit.log"))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Open failed", str(exc))

    def _open_data_folder(self) -> None:
        import os

        try:
            os.startfile(str(guard.app_data_dir()))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.warning(self, "Open failed", str(exc))

    def _show_about(self) -> None:
        QMessageBox.about(
            self,
            "About ARP Scanner",
            "ARP Scanner — Live-Host Discovery Tool v1.0.0\n\n"
            "PySide6 (Qt) GUI over a burst-send ARP engine.\n"
            "Security controls: OWASP Top 10, ISO 27001, NIST — see security.md.",
        )

    def _reset_for_scan(self) -> None:
        self.table.setRowCount(0)
        self.progress_bar.setRange(0, 1)
        self.progress_bar.setValue(0)
        self.stats_label.setText("Starting scan…")
        self._last_result = None

    def closeEvent(self, event) -> None:  # noqa: N802 - Qt naming
        if self._thread is not None and self._thread.isRunning():
            self._worker.request_cancel()
            self._thread.quit()
            self._thread.wait(3000)
        super().closeEvent(event)