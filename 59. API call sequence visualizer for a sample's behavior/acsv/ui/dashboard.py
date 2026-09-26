"""Dashboard page (architecture §5.4 screen 1)."""

from __future__ import annotations

from PySide6.QtCore import Qt
from PySide6.QtWidgets import (
    QGridLayout, QHBoxLayout, QLabel, QPushButton, QScrollArea, QTableWidget,
    QTableWidgetItem, QVBoxLayout, QWidget,
)

from ..version import APP_VERSION
from .theme import CAT_COLORS
from .widgets import kpi_card, section_title


class DashboardPage(QWidget):
    def __init__(self, bus, win) -> None:
        super().__init__()
        self.bus = bus
        self.win = win
        self._build()

    def _build(self) -> None:
        outer = QVBoxLayout(self)
        outer.setContentsMargins(26, 22, 26, 22)
        outer.setSpacing(16)

        header = QHBoxLayout()
        title = QLabel("Dashboard")
        title.setObjectName("PageTitle")
        header.addWidget(title)
        header.addStretch(1)
        refresh = QPushButton("↻ Refresh")
        refresh.setObjectName("Primary")
        refresh.clicked.connect(self.on_shown)
        header.addWidget(refresh)
        outer.addLayout(header)

        self.kpis: dict[str, QWidget] = {}
        grid = QGridLayout()
        grid.addWidget(kpi_card("Samples catalogued", "0", CAT_COLORS["Network"]), 0, 0)
        grid.addWidget(kpi_card("Capture sessions", "0", CAT_COLORS["Process"]), 0, 1)
        grid.addWidget(kpi_card("Events captured", "0", CAT_COLORS["Crypto"]), 0, 2)
        grid.addWidget(kpi_card("Reports generated", "0", CAT_COLORS["Thread"]), 0, 3)
        grid.addWidget(kpi_card("Audit entries", "0", CAT_COLORS["Registry"]), 0, 4)
        outer.addLayout(grid)

        quick = QHBoxLayout()
        start = QPushButton("⚡ New capture (replay)")
        start.setObjectName("Primary")
        start.clicked.connect(lambda: self.win._goto(1))
        reports = QPushButton("▤ Generate report")
        reports.clicked.connect(lambda: self.win._goto(5))
        audit = QPushButton("∿ Verify audit chain")
        audit.clicked.connect(lambda: self.win._goto(7))
        for b in (start, reports, audit):
            quick.addWidget(b)
        quick.addStretch(1)
        outer.addLayout(quick)

        outer.addWidget(section_title("Recent sessions"))
        self.table = QTableWidget(0, 6)
        self.table.setHorizontalHeaderLabels(
            ["Session", "Sample", "Status", "Events", "Sandbox", "Started (local)"]
        )
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setSelectionBehavior(QTableWidget.SelectRows)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        self.table.doubleClicked.connect(self._open_session)
        outer.addWidget(self.table, stretch=1)

    # ------------------------------------------------------------- refresh
    def on_shown(self) -> None:
        svc = self.win.services
        samples = svc.store.list_samples()
        sessions = svc.store.list_sessions()
        event_total = sum(int(s.get("event_count", 0)) for s in sessions)
        reports = list(svc.store.list_reports())
        audit_n = svc.audit.count()
        self._set_kpi(0, str(len(samples)))
        self._set_kpi(1, str(len(sessions)))
        self._set_kpi(2, f"{event_total:,}")
        self._set_kpi(3, str(len(reports)))
        self._set_kpi(4, str(audit_n))

        self.table.setRowCount(0)
        for s in sessions[:40]:
            sample = svc.store.get_sample(s.get("sample_id") or 0)
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(s["id"]))
            self.table.setItem(r, 1, QTableWidgetItem(sample.get("name", "-") if sample else "-"))
            self.table.setItem(r, 2, QTableWidgetItem(s["status"]))
            self.table.setItem(r, 3, QTableWidgetItem(str(s["event_count"])))
            self.table.setItem(r, 4, QTableWidgetItem(s.get("sandbox", "")))
            import time
            st = time.strftime("%Y-%m-%d %H:%M", time.localtime(s["started_at"] / 1e9))
            self.table.setItem(r, 5, QTableWidgetItem(st))
        self.table.resizeColumnsToContents()

    def _set_kpi(self, idx: int, value: str) -> None:
        cell = self.layout().itemAt(1).layout().itemAt(idx).widget()
        cell.findChildren(QLabel)[0].setText(value)

    def _open_session(self) -> None:
        row = self.table.currentRow()
        if row < 0:
            return
        sid = self.table.item(row, 0).text()
        self.bus.select(sid)
        self.win._goto(2)