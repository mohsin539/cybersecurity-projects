"""Compliance Console page (architecture §5.4 screen 8, §9).
Renders ISO 27001 / NIST / OWASP coverage matrices with status colors."""

from __future__ import annotations

from PySide6.QtGui import QColor
from PySide6.QtWidgets import (
    QComboBox, QHBoxLayout, QLabel, QPushButton, QTableWidget, QTableWidgetItem,
    QVBoxLayout, QWidget,
)

from .theme import SEVERITY_COLORS
from .widgets import kpi_card, section_title

_STATUS_COLOR = {
    "evidenced": "#34d399",
    "implemented": "#22d3ee",
    "planned": "#64748b",
}


class CompliancePage(QWidget):
    def __init__(self, win) -> None:
        super().__init__()
        self.win = win
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(14)

        title = QLabel("Compliance Console")
        title.setObjectName("PageTitle")
        lay.addWidget(title)

        row = QHBoxLayout()
        lab = QLabel("Framework:")
        row.addWidget(lab)
        self.fw = QComboBox()
        for f in ("ISO27001", "NIST", "OWASP"):
            self.fw.addItem(f)
        self.fw.currentIndexChanged.connect(self.on_shown)
        row.addWidget(self.fw)
        btn = QPushButton("↻ Recompute")
        btn.clicked.connect(self.on_shown)
        row.addWidget(btn)
        row.addStretch(1)
        lay.addLayout(row)

        kpis = QHBoxLayout()
        self.total_kpi = kpi_card("Controls", "0", "#22d3ee")
        self.ev_kpi = kpi_card("Evidenced", "0", "#34d399")
        self.imp_kpi = kpi_card("Implemented", "0", "#a78bfa")
        self.gap_kpi = kpi_card("Gaps (planned)", "0", "#fb7185")
        for w in (self.total_kpi, self.ev_kpi, self.imp_kpi, self.gap_kpi):
            kpis.addWidget(w)
        kpis.addStretch(1)
        lay.addLayout(kpis)

        lay.addWidget(section_title("Control coverage matrix"))
        self.table = QTableWidget(0, 4)
        self.table.setHorizontalHeaderLabels(["Control ID", "Name", "Domain", "Status"])
        self.table.setAlternatingRowColors(True)
        self.table.horizontalHeader().setStretchLastSection(True)
        self.table.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.table, stretch=1)

    def _evidence(self) -> list[str]:
        return [
            "A.5.28", "A.5.33", "A.8.15", "A.8.24", "A.5.34", "A.8.28",
            "OWASP-A08", "OWASP-A09", "OWASP-A02", "OWASP-A03",
            "CSF-DETECT", "CSF-PROTECT", "SP800-53-AU-2", "SP800-53-SI-4",
            "SP800-53-SC-28",
        ]

    def on_shown(self) -> None:
        fw = self.fw.currentText()
        matrix = self.win.services.compliance.coverage_matrix(self._evidence())
        entry = matrix.get(fw, {"rows": [], "summary": {"total": 0, "evidenced": 0}})
        rows = entry["rows"]
        summary = entry["summary"]
        self._set(self.total_kpi, str(summary["total"]))
        self._set(self.ev_kpi, str(summary["evidenced"]))
        self._set(self.imp_kpi, str(summary["implemented"]))
        self._set(self.gap_kpi, str(summary["total"] - summary["implemented"]))
        self.table.setRowCount(0)
        for c in rows:
            r = self.table.rowCount()
            self.table.insertRow(r)
            self.table.setItem(r, 0, QTableWidgetItem(c["id"]))
            self.table.setItem(r, 1, QTableWidgetItem(c["name"]))
            self.table.setItem(r, 2, QTableWidgetItem(c["domain"]))
            item = QTableWidgetItem(c["status"])
            color = _STATUS_COLOR.get(c["status"], "#64748b")
            item.setForeground(QColor("#04101a"))
            item.setBackground(QColor(color))
            self.table.setItem(r, 3, item)
        self.table.resizeColumnsToContents()

    def _set(self, card, value: str) -> None:
        card.findChildren(QLabel)[0].setText(value)