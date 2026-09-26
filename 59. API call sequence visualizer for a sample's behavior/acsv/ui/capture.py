"""Capture & Intake page (architecture §5.4 screens 1-2, §6 data flow)."""

from __future__ import annotations

import time
from pathlib import Path

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QComboBox, QFileDialog, QHBoxLayout, QLabel, QMessageBox, QProgressBar,
    QPushButton, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from ..capture.generator import build_trace
from ..capture.runner import CaptureRunner
from .theme import CAT_COLORS
from .widgets import kpi_card, section_title


class CapturePage(QWidget):
    def __init__(self, bus, win) -> None:
        super().__init__()
        self.bus = bus
        self.win = win
        self.current_sample_id: int | None = None
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(14)

        title = QLabel("Capture & Sample Intake")
        title.setObjectName("PageTitle")
        lay.addWidget(title)

        controls = QHBoxLayout()
        pick = QPushButton("⬆  Add sample file (hash only)")
        pick.setObjectName("Primary")
        pick.clicked.connect(self._pick_sample)
        self.mode = QComboBox()
        self.mode.addItem("Offline replay (synthetic ETW-shaped trace)", "replay")
        self.mode.addItem("Import trace file (.json/.csv/.xml)", "import")
        self.mode.addItem("Live ETW capture (v1.1 - disabled)", "live")
        self.run_btn = QPushButton("▶  Run capture")
        self.run_btn.clicked.connect(self._run)
        self.demo_btn = QPushButton("✦  Quick demo session")
        self.demo_btn.clicked.connect(self._demo)
        for w in (pick, self.mode, self.run_btn, self.demo_btn):
            controls.addWidget(w)
        controls.addStretch(1)
        lay.addLayout(controls)

        kpis = QHBoxLayout()
        self.events_kpi = kpi_card("Events to generate", "600", CAT_COLORS["Crypto"])
        self.status_kpi = kpi_card("Last run", "idle", CAT_COLORS["Network"])
        kpis.addWidget(self.events_kpi)
        kpis.addWidget(self.status_kpi)
        kpis.addStretch(1)
        lay.addLayout(kpis)

        self.progress = QProgressBar()
        self.progress.setVisible(False)
        lay.addWidget(self.progress)

        lay.addWidget(section_title("Samples"))
        self.table = QTableWidget(0, 5)
        self.table.setHorizontalHeaderLabels(["id", "Name", "SHA-256", "Size", "PE"])
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.itemSelectionChanged.connect(self._select_row)
        lay.addWidget(self.table, stretch=1)

    # ---------------------------------------------------------------- intake
    def _pick_sample(self) -> None:
        path, _ = QFileDialog.getOpenFileName(
            self, "Select sample (hash-only intake)", "", "All files (*.*)"
        )
        if not path:
            return
        try:
            meta = self.win.services.intake.ingest(Path(path))
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Intake failed", str(exc))
            return
        self.current_sample_id = int(meta["id"])
        self._refresh_table()
        self.win.services.record("EVENT_IMPORT", {"kind": "sample_intake", "sha256": meta["sha256"]})

    def _demo(self) -> None:
        try:
            meta = self.win.services.intake.register_virtual()
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Demo failed", str(exc))
            return
        self.current_sample_id = int(meta["id"])
        self._refresh_table()

    # ------------------------------------------------------------------ run
    def _run(self) -> None:
        svc = self.win.services
        if self.mode.currentData() == "live":
            QMessageBox.information(self, "v1.1 feature",
                                    "Live ETW capture ships in v1.1. Use replay or import.")
            return
        if self.current_sample_id is None:
            self._demo()
        sid = None
        try:
            sample = svc.store.get_sample(self.current_sample_id)
            runner = CaptureRunner(svc.store, svc.audit, svc.policy, svc.redaction)
            sid = runner.create_session(self.current_sample_id)
            if self.mode.currentData() == "import":
                path, _ = QFileDialog.getOpenFileName(
                    self, "Open trace", "", "Trace files (*.json *.csv *.xml);;All (*.*)"
                )
                if not path:
                    runner.audit.record("SESSION_ABORT", {"session_id": sid,
                                                          "reason": "no trace chosen"})
                    svc.store.finish_session(sid, "aborted")
                    return
                from ..capture.importer import TraceImporter
                events = TraceImporter.import_file(Path(path))
                svc.audit.record("SESSION_START", {"session_id": sid, "trace_file": path})
            else:
                events = build_trace(sample["sha256"], count=self._count())
            self.progress.setVisible(True)
            self.progress.setRange(0, len(events))
            written = runner.run_trace(sid, events)
            self.progress.setValue(len(events))
            self.progress.setVisible(False)
            self._flash(f"done · {written} events")
            self.bus.select(sid, self.current_sample_id)
        except Exception as exc:  # noqa: BLE001
            QMessageBox.critical(self, "Capture failed", str(exc))
            if sid:
                svc.store.finish_session(sid, "failed")
            return
        self.win._goto(2)

    def _count(self) -> int:
        return 600

    def _flash(self, text: str) -> None:
        val = self.status_kpi.findChildren(QLabel)[0]
        val.setText(text)

    # ---------------------------------------------------------------- table
    def _refresh_table(self) -> None:
        svc = self.win.services
        self.table.setRowCount(0)
        for s in svc.store.list_samples():
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(str(s["id"])))
            self.table.setItem(r, 1, QTableWidgetItem(s["name"]))
            self.table.setItem(r, 2, QTableWidgetItem(s["sha256"][:16] + "…"))
            self.table.setItem(r, 3, QTableWidgetItem(str(s["size"])))
            self.table.setItem(r, 4, QTableWidgetItem(s.get("pe_machine", "")))
        self.table.resizeColumnsToContents()

    def on_shown(self) -> None:
        self._refresh_table()

    def _select_row(self) -> None:
        sel = self.table.selectionModel().selectedRows()
        if sel:
            self.current_sample_id = int(self.table.item(sel[0].row(), 0).text())