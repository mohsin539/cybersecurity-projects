"""Heatmap page: API-category × time-bucket heat grid (architecture §5.4)."""

from __future__ import annotations

import collections

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .widgets import section_title

BUCKETS = 64


def _tint(frac: float) -> QColor:
    frac = min(max(frac, 0.0), 1.0)
    r = int(11 + 200 * frac)
    g = int(30 + 120 * frac)
    b = int(238 - 60 * frac)
    return QColor(r, g, b)


class HeatmapPage(QWidget):
    def __init__(self, bus, win) -> None:
        super().__init__()
        self.bus = bus
        self.win = win
        self._build()
        self.bus.session_changed.connect(self.on_shown)

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(12)
        head = QHBoxLayout()
        title = QLabel("Behavior Heatmap")
        title.setObjectName("PageTitle")
        head.addWidget(title)
        head.addStretch(1)
        self.session_lab = QLabel("no session")
        self.session_lab.setObjectName("kpi_label")
        head.addWidget(self.session_lab)
        lay.addLayout(head)
        lay.addWidget(section_title("Category × time-bucket density (last 200k events)"))
        self.table = QTableWidget(0, BUCKETS + 3)
        headers = ["Category", "Total"] + [f"b{i}" for i in range(BUCKETS)]
        self.table.setHorizontalHeaderLabels(headers)
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.table, stretch=1)

    def on_shown(self) -> None:
        if not self.bus.session_id:
            return
        svc = self.win.services
        self.session_lab.setText(self.bus.session_id)
        events = svc.store.iter_events(self.bus.session_id, limit=200000)
        if not events:
            return
        t0 = events[0]["ts_ns"]
        t1 = events[-1]["ts_ns"]
        span = max(t1 - t0, 1)
        heat: dict[str, list[int]] = collections.defaultdict(lambda: [0] * BUCKETS)
        for e in events:
            bucket = min(BUCKETS - 1, int((e["ts_ns"] - t0) / span * BUCKETS))
            heat[e["category"]][bucket] += 1
        cats = sorted(heat, key=lambda c: -sum(heat[c]))
        peak = max((max(v) for v in heat.values()), default=1)
        self.table.setRowCount(0)
        for cat in cats:
            cells = heat[cat]
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(cat))
            self.table.setItem(r, 1, QTableWidgetItem(str(sum(cells))))
            for i, n in enumerate(cells):
                cell = QTableWidgetItem()
                if n:
                    cell.setText(str(n))
                    cell.setBackground(_tint(n / peak))
                else:
                    cell.setBackground(QColor("#0b1120"))
                self.table.setItem(r, i + 2, cell)
        self.table.resizeColumnsToContents()
        self.table.setColumnCount(self.table.columnCount())