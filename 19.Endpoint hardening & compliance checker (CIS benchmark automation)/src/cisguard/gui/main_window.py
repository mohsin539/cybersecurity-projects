"""CISGuard main window: dashboard, findings table, detail pane, exports.

GUI thread only paints; the scan runs on a QThread (gui.worker).
"""

from __future__ import annotations

from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtGui import QColor, QFont
from PySide6.QtWidgets import (
    QDialog, QFileDialog, QHBoxLayout, QLabel, QMainWindow, QMessageBox,
    QPlainTextEdit, QPushButton, QSplitter, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from cisguard import APP_NAME, __version__
from cisguard.domain.models import Status
from cisguard.gui.worker import ScanWorker

_STATUS_COLORS = {
    "PASS": QColor("#1a7f37"),
    "FAIL": QColor("#c62828"),
    "ERROR": QColor("#757575"),
    "N/A": QColor("#8d6e63"),
}


class MainWindow(QMainWindow):
    def __init__(self, ctx, demo: bool = False) -> None:
        super().__init__()
        self.ctx = ctx
        self._record = None
        self._worker = None
        self.setWindowTitle(f"{APP_NAME} {__version__}{' — DEMO (offline sample data)' if demo else ''}")
        self.resize(1250, 780)
        self._build_ui()

    # -- UI ------------------------------------------------------------------

    def _build_ui(self) -> None:
        central = QWidget()
        self.setCentralWidget(central)
        root = QVBoxLayout(central)

        bar = QHBoxLayout()
        self.btn_scan = QPushButton("Run assessment")
        self.btn_scan.clicked.connect(self.on_scan)
        self.btn_html = QPushButton("Export HTML…")
        self.btn_html.clicked.connect(self.on_export_html)
        self.btn_json = QPushButton("Export JSON…")
        self.btn_json.clicked.connect(self.on_export_json)
        self.btn_csv = QPushButton("Export CSV…")
        self.btn_csv.clicked.connect(self.on_export_csv)
        for b in (self.btn_scan, self.btn_html, self.btn_json, self.btn_csv):
            bar.addWidget(b)
        bar.addStretch(1)
        self.lbl_status = QLabel("Read-only assessment. No system changes are ever made.")
        f = QFont(); f.setItalic(True)
        self.lbl_status.setFont(f)
        bar.addWidget(self.lbl_status)
        root.addLayout(bar)

        # KPI row
        kpis = QHBoxLayout()
        self.kpi_score, self.kpi_pass, self.kpi_fail, self.kpi_err = QLabel("—"), QLabel("—"), QLabel("—"), QLabel("—")
        for label, text in ((self.kpi_score, "Score"), (self.kpi_pass, "Passed"),
                            (self.kpi_fail, "Failed"), (self.kpi_err, "Errors")):
            label.setText(f"<div style='border:1px solid #ddd;border-radius:8px;padding:6px 14px'>"
                          f"<small>{text}</small><br><b style='font-size:22px'>—</b></div>")
            kpis.addWidget(label)
        kpis.addStretch(1)
        root.addLayout(kpis)

        split = QSplitter(Qt.Horizontal)
        root.addWidget(split, 1)

        # left: findings table
        self.tbl = QTableWidget(0, 5)
        self.tbl.setHorizontalHeaderLabels(["ID", "Status", "Severity", "Control", "Observed"])
        self.tbl.horizontalHeader().setStretchLastSection(True)
        self.tbl.setColumnWidth(0, 70)
        self.tbl.setColumnWidth(1, 70)
        self.tbl.setColumnWidth(2, 90)
        self.tbl.setColumnWidth(3, 420)
        self.tbl.setEditTriggers(QTableWidget.NoEditTriggers)
        self.tbl.setSelectionBehavior(QTableWidget.SelectRows)
        self.tbl.currentCellChanged.connect(self._on_row)
        split.addWidget(self.tbl)

        # right: detail pane
        right = QWidget()
        rv = QVBoxLayout(right)
        rv.addWidget(QLabel("Control detail"))
        self.txt_detail = QPlainTextEdit()
        self.txt_detail.setReadOnly(True)
        rv.addWidget(self.txt_detail)
        split.addWidget(right)
        split.setSizes([780, 470])

    # -- actions ---------------------------------------------------------------

    def on_scan(self) -> None:
        self.btn_scan.setEnabled(False)
        self.lbl_status.setText("Scanning (read-only)…")
        self._worker = ScanWorker(self.ctx.scan_service)
        self._worker.progress.connect(self._on_progress)
        self._worker.finished.connect(self._on_scan_done)
        self._worker.failed.connect(self._on_scan_error)
        self._worker.start()

    def _on_progress(self, done: int, total: int, cid: str) -> None:
        self.lbl_status.setText(f"Scanning… {done}/{total} {cid}")

    def _on_scan_done(self, record) -> None:
        self._record = record
        s = record.summary
        self.btn_scan.setEnabled(True)
        self.lbl_status.setText(
            f"Scan {s.scan_id} complete — {s.hostname} — score {s.score} "
            f"({s.passed} passed, {s.failed} failed, {s.errors} errors, {s.not_applicable} n/a)"
        )
        self._set_kpis(s)
        self._fill_table()
        try:
            self.ctx.history.save(record)
        except Exception:
            pass  # history is best-effort; never blocks assessment results

    def _on_scan_error(self, message: str) -> None:
        self.btn_scan.setEnabled(True)
        self.lbl_status.setText("Scan failed.")
        QMessageBox.critical(self, APP_NAME, message)

    def _set_kpis(self, s) -> None:
        def kpi(label, value, color="#1c1c1c"):
            return (f"<div style='border:1px solid #ddd;border-radius:8px;padding:6px 14px'>"
                    f"<small>{label}</small><br><b style='font-size:22px;color:{color}'>{value}</b></div>")
        color = "#1a7f37" if s.score >= 85 else ("#f9a825" if s.score >= 60 else "#c62828")
        self.kpi_score.setText(kpi("Score", s.score, color))
        self.kpi_pass.setText(kpi("Passed", s.passed, "#1a7f37"))
        self.kpi_fail.setText(kpi("Failed", s.failed, "#c62828"))
        self.kpi_err.setText(kpi("Errors", s.errors, "#757575"))

    def _fill_table(self) -> None:
        self.tbl.setRowCount(0)
        if not self._record:
            return
        for r in self._record.results:
            c = self._record.controls_by_id[r.control_id]
            row = self.tbl.rowCount()
            self.tbl.insertRow(row)
            values = [c.control_id, r.status.value, c.severity.value, c.title, r.observed]
            for col, val in enumerate(values):
                item = QTableWidgetItem(val)
                if col == 1:
                    item.setForeground(_STATUS_COLORS.get(r.status.value, QColor("#1c1c1c")))
                    font = QFont(); font.setBold(True); item.setFont(font)
                if col == 4:
                    item.setText(r.observed[:80])
                self.tbl.setItem(row, col, item)

    def _on_row(self, cur: int, *_args) -> None:
        if not self._record or not (0 <= cur < len(self._record.results)):
            return
        r = self._record.results[cur]
        c = self._record.controls_by_id[r.control_id]
        self.txt_detail.setPlainText(
            f"[{c.control_id}] {c.title}\n"
            f"Category : {c.category.value}\n"
            f"CIS Level: {c.level}   Severity: {c.severity.value}\n"
            f"Status   : {r.status.value}\n\n"
            f"Why it matters:\n  {c.rationale}\n\n"
            f"Observed : {r.observed}\n"
            f"Expected : {r.expected}\n"
            f"Evidence : {r.evidence.source}\n"
            + (f"\nError detail: {r.detail}" if r.detail else "")
            + f"\n\nHow to remediate (advisory — use change management):\n  {c.recommendation}"
        )

    # -- exports ------------------------------------------------------------

    def on_export_html(self) -> None:
        if not self._require_record():
            return
        out, _ = QFileDialog.getSaveFileName(self, "Export HTML", "cisguard-report.html", "HTML (*.html)")
        if out:
            p = self.ctx.reports.export_html(self._record, Path(out))
            self.lbl_status.setText(f"Report written: {p}")

    def on_export_json(self) -> None:
        if not self._require_record():
            return
        out, _ = QFileDialog.getSaveFileName(self, "Export JSON", "cisguard-report.json", "JSON (*.json)")
        if out:
            p = self.ctx.reports.export_json(self._record, Path(out))
            self.lbl_status.setText(f"Report written: {p}")

    def on_export_csv(self) -> None:
        if not self._require_record():
            return
        out, _ = QFileDialog.getSaveFileName(self, "Export CSV", "cisguard-report.csv", "CSV (*.csv)")
        if out:
            p = self.ctx.reports.export_csv(self._record, Path(out))
            self.lbl_status.setText(f"Report written: {p}")

    def _require_record(self) -> bool:
        if not self._record:
            QMessageBox.information(self, APP_NAME, "Run an assessment first.")
            return False
        return True


def run_gui(data_dir: Path | None = None, demo: bool = False) -> int:
    import sys

    from PySide6.QtWidgets import QApplication

    from cisguard.composition import AppContext

    app = QApplication(sys.argv)
    ctx = AppContext.open(data_dir or (Path.home() / "CISGuard"), use_test_collectors=demo)
    win = MainWindow(ctx, demo=demo)
    win.show()
    code = app.exec()
    ctx.close()
    return code
