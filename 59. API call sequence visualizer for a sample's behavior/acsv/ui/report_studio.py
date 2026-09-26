"""Report Studio page (architecture §7.3 download flow)."""

from __future__ import annotations

from pathlib import Path

from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QPushButton,
    QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from ..version import APP_VERSION
from .widgets import kpi_card, section_title

FORMATS = [
    ("PDF (formal audit evidence)", "pdf"),
    ("HTML (self-contained interactive)", "html"),
    ("JSON (machine integration)", "json"),
    ("CSV (spreadsheet work)", "csv"),
    ("STIX 2.1 (threat intel sharing)", "stix"),
]


class ReportStudioPage(QWidget):
    def __init__(self, bus, win) -> None:
        super().__init__()
        self.bus = bus
        self.win = win
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(14)

        title = QLabel("Report Studio")
        title.setObjectName("PageTitle")
        lay.addWidget(title)

        row = QHBoxLayout()
        session = QLabel("Session:")
        row.addWidget(session)
        self.session_combo = QComboBox()
        self.session_combo.setMinimumWidth(220)
        row.addWidget(self.session_combo)
        fmt = QLabel("Format:")
        row.addWidget(fmt)
        self.fmt_combo = QComboBox()
        for label, val in FORMATS:
            self.fmt_combo.addItem(label, val)
        row.addWidget(self.fmt_combo)
        gen = QPushButton("▤  Generate report")
        gen.setObjectName("Primary")
        gen.clicked.connect(self._generate)
        dl = QPushButton("⬇  Download")
        dl.clicked.connect(self._download)
        for w in (gen, dl):
            row.addWidget(w)
        row.addStretch(1)
        lay.addLayout(row)

        kpis = QHBoxLayout()
        self.last_kpi = kpi_card("Last render", "none", "#22d3ee")
        self.sha_kpi = kpi_card("Report SHA-256", "—", "#a78bfa")
        kpis.addWidget(self.last_kpi)
        kpis.addWidget(self.sha_kpi)
        kpis.addStretch(1)
        lay.addLayout(kpis)

        lay.addWidget(section_title("Report history"))
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Report ID", "Session", "Format", "Filename", "Size", "SHA-256"]
        )
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        lay.addWidget(self.table, stretch=1)

    def on_shown(self) -> None:
        svc = self.win.services
        self.session_combo.clear()
        for s in svc.store.list_sessions():
            sample = svc.store.get_sample(s.get("sample_id") or 0)
            self.session_combo.addItem(
                f"{s['id']} · {(sample or {}).get('name', '-')} · {s['status']}", s["id"]
            )
        if self.bus.session_id:
            idx = self.session_combo.findData(self.bus.session_id)
            if idx >= 0:
                self.session_combo.setCurrentIndex(idx)
        self.table.setRowCount(0)
        for r in svc.store.list_reports():
            n = self.table.rowCount()
            self.table.insertRow(n)
            self.table.setItem(n, 0, QTableWidgetItem(r["id"]))
            self.table.setItem(n, 1, QTableWidgetItem(r["session_id"]))
            self.table.setItem(n, 2, QTableWidgetItem(r["format"]))
            self.table.setItem(n, 3, QTableWidgetItem(r["filename"]))
            self.table.setItem(n, 4, QTableWidgetItem(str(r["size"])))
            self.table.setItem(n, 5, QTableWidgetItem(r["report_sha256"][:24] + "…"))
        self.table.resizeColumnsToContents()

    # ------------------------------------------------------------- actions
    def _generate(self) -> None:
        sid = self.session_combo.currentData()
        if not sid:
            QMessageBox.information(self, "No session", "Run a capture first.")
            return
        fmt = self.fmt_combo.currentData()
        out_dir = self.win.services.config.data_dir / "reports"
        out_dir.mkdir(parents=True, exist_ok=True)
        try:
            res = self.win.services.report_engine.render_and_save(
                sid, fmt, out_dir, {"gui": True, "tool": f"ACSV {APP_VERSION}"}
            )
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Report failed", str(exc))
            return
        k = self.last_kpi.findChildren(QLabel)[0]
        k.setText(f"{res['format'].upper()} · {Path(res['path']).name}")
        k2 = self.sha_kpi.findChildren(QLabel)[0]
        k2.setText(res["sha256"][:28] + "…")
        self.on_shown()

    def _download(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            self._generate()
            return
        sid = self.table.item(row, 1).text()
        fmt = self.table.item(row, 2).text()
        fname = self.table.item(row, 3).text()
        src = self.win.services.config.data_dir / "reports" / fname
        if not src.exists():
            QMessageBox.warning(self, "Missing file", f"{src} not found")
            return
        dest, _ = QFileDialog.getSaveFileName(self, "Save report", str(Path.home() / fname),
                                              f"{fmt.upper()} (*.{fmt})")
        if not dest:
            return
        target = Path(dest)
        if not target.parent.exists():
            QMessageBox.warning(self, "Invalid path", "Directory does not exist")
            return
        import shutil
        shutil.copyfile(src, target)
        sha = self.win.services.integrity.sha256_file(target)
        report_id = self.table.item(row, 0).text()
        original_ok = all(
            r["id"] != report_id or r["report_sha256"] == sha
            for r in self.win.services.store.list_reports()
        )
        self.win.services.audit.record("REPORT_DOWNLOAD", {
            "report_id": report_id,
            "session_id": sid, "format": fmt, "dest": str(target), "sha256": sha,
        })
        integrity = "Y" if original_ok else "N"
        QMessageBox.information(
            self, "Download",
            f"Saved {target}\nSHA-256: {sha}\nMatches authoritative copy: {integrity}"
        )