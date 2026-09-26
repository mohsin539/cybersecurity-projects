"""Results page: filterable table, preview panel and recovery controls."""

from __future__ import annotations

from typing import Dict, List, Optional

from PySide6.QtCore import Qt, QAbstractTableModel, QModelIndex, Signal
from PySide6.QtGui import QColor, QPixmap
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QTableView, QHeaderView, QPushButton,
    QLineEdit, QComboBox, QSplitter, QTextBrowser, QTabWidget, QLabel,
    QFileDialog, QMessageBox, QApplication, QAbstractItemView,
)

from .theme import PALETTE
from ..core.disk import human_size

COLUMNS = [
    ("name", "File Name"),
    ("size", "Size"),
    ("fs", "FS"),
    ("kind", "Kind"),
    ("status", "Status"),
    ("method", "Method"),
    ("confidence", "Confidence"),
    ("quality", "Quality"),
    ("detail", "Details"),
]

KIND_TONE = {"deleted": "amber", "active": "green", "carved": "violet"}
TONE_HEX = {
    "green": "#34d399", "amber": "#fbbf24", "red": "#f87171",
    "blue": "#60a5fa", "violet": "#a78bfa", "gray": "#94a3b8",
}


class ResultsModel(QAbstractTableModel):
    def __init__(self, parent=None):
        super().__init__(parent)
        self._rows: List[dict] = []

    def set_rows(self, rows: List[dict]):
        self.beginResetModel()
        self._rows = rows
        self.endResetModel()

    def rowCount(self, parent=QModelIndex()):
        return 0 if parent.isValid() else len(self._rows)

    def columnCount(self, parent=QModelIndex()):
        return len(COLUMNS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role != Qt.DisplayRole:
            return None
        if orientation == Qt.Horizontal:
            return COLUMNS[section][1]
        return section + 1

    def data(self, index, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        r = self._rows[index.row()]
        key = COLUMNS[index.column()][0]
        if role == Qt.DisplayRole:
            v = r.get(key, "")
            if key == "size" and isinstance(v, (int, float)):
                return human_size(int(v))
            if key == "quality":
                return f"{float(v or 0) * 100:.0f}%"
            if key == "status" and not v:
                return ""
            return v if v is not None else ""
        if role == Qt.ToolTipRole:
            return r.get("detail", "")
        if role == Qt.UserRole:
            return r
        if role == Qt.BackgroundRole:
            q = float(r.get("quality", 0))
            tone = "violet"
            chic = {"green": "#0f3d2c", "amber": "#4a3512", "red": "#4a1c1c",
                    "violet": "#37285a", "blue": "#13335e", "gray": "#232d40"}
            if r.get("status") == "overwritten":
                tone = "gray"
            else:
                kind = r.get("kind")
                tone = {"deleted": "amber", "active": "green", "carved": "violet"}.get(kind, "blue")
            c = chic.get(tone, "#232d40")
            if q < 0.3:
                c = "#2e2a33"
            return QColor(c)
        if role == Qt.ForegroundRole:
            return QColor(PALETTE["text"])
        return None


class PreviewPanel(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumWidth(300)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(0, 0, 0, 0)
        self.tabs = QTabWidget()
        self.image = QLabel("No preview")
        self.image.setAlignment(Qt.AlignCenter)
        self.image.setStyleSheet("background:#101a2e; color:#7c8aa8; border-radius:8px;")
        self.image.setMinimumHeight(200)
        self.text = QTextBrowser()
        self.text.setStyleSheet("background:#101a2e; color:#d5e0f5; border-radius:8px; font-family:Consolas;")
        self.hex = QTextBrowser()
        self.hex.setStyleSheet("background:#101a2e; color:#9fd0c8; border-radius:8px; font-family:Consolas;")
        self.tabs.addTab(self.image, "Image")
        self.tabs.addTab(self.text, "Text")
        self.tabs.addTab(self.hex, "Hex")
        self.meta = QLabel("")
        self.meta.setStyleSheet("color:#93a4c4; font-size:11px; padding:4px 2px;")
        lay.addWidget(self.tabs, 1)
        lay.addWidget(self.meta)

    def show_meta(self, row: dict):
        if not row:
            self.meta.setText("")
            return
        self.meta.setText(
            f"{row.get('name','')}  ·  {human_size(int(row.get('size',0)))}"
            f"  ·  {row.get('fs','')}  ·  quality {(float(row.get('quality',0))*100):.0f}%")

    def show_data(self, row: Optional[dict], data: bytes):
        self.show_meta(row)
        if not row or not data:
            self.image.setText("No preview")
            self.text.clear()
            self.hex.clear()
            return
        ext = str(row.get("ext", "")).lower()
        shown = False
        if ext in ("png", "jpg", "jpeg", "gif", "bmp", "webp", "ico"):
            pm = QPixmap()
            if pm.loadFromData(data):
                self.image.setPixmap(pm.scaled(
                    self.image.size(), Qt.KeepAspectRatio, Qt.SmoothTransformation))
                shown = True
                self.tabs.setCurrentWidget(self.image)
        if not shown:
            self.image.setText("No image preview (binary)")
        texty = ext in ("txt", "log", "csv", "xml", "html", "json", "ini", "cfg", "md", "py", "sql")
        if data[:64] and b"\x00" not in data[:256] and (texty or ext in ("doc", "pdf")):
            try:
                sample = data[:200_000].decode("utf-8", errors="replace")
                self.text.setPlainText(sample)
                self.tabs.setCurrentWidget(self.text)
            except Exception:
                pass
        self.hex.setPlainText(_hexdump(data[:2048]))
        if self.tabs.currentWidget() == self.hex and len(data) > 2048:
            self.hex.append(f"\n… truncated ({len(data)} bytes total)")


def _hexdump(b: bytes, width: int = 16) -> str:
    lines = []
    for i in range(0, len(b), width):
        chunk = b[i:i + width]
        hex_part = " ".join(f"{x:02x}" for x in chunk)
        ascii_part = "".join(chr(x) if 32 <= x < 127 else "." for x in chunk)
        lines.append(f"{i:08x}  {hex_part:<{width*3}}  {ascii_part}")
    return "\n".join(lines)


class ResultsPage(QWidget):
    recover_selected = Signal()
    recover_all = Signal()
    export_requested = Signal(str)
    verify_vault_requested = Signal()

    def __init__(self, parent=None):
        super().__init__(parent)
        root = QVBoxLayout(self)
        root.setContentsMargins(18, 18, 18, 18)
        root.setSpacing(12)

        # toolbar
        bar = QHBoxLayout()
        self.search = QLineEdit()
        self.search.setPlaceholderText("🔍  Filter by name…")
        self.search.setClearButtonEnabled(True)
        self.search.setMaximumWidth(320)
        self.filter_kind = QComboBox()
        self.filter_kind.addItems(["All kinds", "Deleted", "Active", "Carved"])
        self.filter_status = QComboBox()
        self.filter_status.addItems(["Any status", "Recoverable", "Overwritten"])
        self.btn_recover_sel = QPushButton("Recover Selected")
        self.btn_recover_sel.setProperty("primary", "true")
        self.btn_recover_all = QPushButton("Recover All")
        self.export_csv = QPushButton("Export CSV")
        self.export_html = QPushButton("Export HTML")
        self.export_json = QPushButton("Export JSON")
        self.btn_verify = QPushButton("Verify Vault")
        bar.addWidget(self.search, 1)
        bar.addWidget(self.filter_kind)
        bar.addWidget(self.filter_status)
        bar.addStretch(1)
        bar.addWidget(self.export_csv)
        bar.addWidget(self.export_html)
        bar.addWidget(self.export_json)
        bar.addWidget(self.btn_verify)
        bar.addWidget(self.btn_recover_sel)
        bar.addWidget(self.btn_recover_all)
        root.addLayout(bar)

        self.table = QTableView()
        self.model = ResultsModel(self)
        self.table.setModel(self.model)
        self.table.setAlternatingRowColors(True)
        self.table.setSelectionBehavior(QAbstractItemView.SelectRows)
        self.table.setSelectionMode(QAbstractItemView.ExtendedSelection)
        self.table.verticalHeader().setVisible(False)
        hh = self.table.horizontalHeader()
        hh.setSectionResizeMode(0, QHeaderView.Stretch)
        hh.setSectionResizeMode(3, QHeaderView.ResizeToContents)
        hh.setSectionResizeMode(8, QHeaderView.Stretch)
        for c in range(1, self.model.columnCount()):
            if c not in (0, 8):
                hh.setSectionResizeMode(c, QHeaderView.ResizeToContents)

        splitter = QSplitter(Qt.Horizontal)
        splitter.addWidget(self.table)
        self.preview = PreviewPanel()
        splitter.addWidget(self.preview)
        splitter.setStretchFactor(0, 3)
        splitter.setStretchFactor(1, 1)
        splitter.setSizes([720, 340])
        root.addWidget(splitter, 1)

        self._all_rows: List[dict] = []
        self._engine = None

        self.btn_recover_sel.clicked.connect(self.recover_selected.emit)
        self.btn_recover_all.clicked.connect(self.recover_all.emit)
        self.export_csv.clicked.connect(lambda: self.export_requested.emit("csv"))
        self.export_html.clicked.connect(lambda: self.export_requested.emit("html"))
        self.export_json.clicked.connect(lambda: self.export_requested.emit("json"))
        self.btn_verify.clicked.connect(self.verify_vault_requested.emit)
        self.search.textChanged.connect(self.refresh_filters)
        self.filter_kind.currentIndexChanged.connect(self.refresh_filters)
        self.filter_status.currentIndexChanged.connect(self.refresh_filters)
        self.table.selectionModel().selectionChanged.connect(self._on_select)

    def set_context(self, engine, rows: List[dict]):
        self._engine = engine
        self._all_rows = rows
        self.refresh_filters()

    def refresh_filters(self):
        needle = self.search.text().strip().lower()
        kind = self.filter_kind.currentText()
        status = self.filter_status.currentText()
        out = []
        for r in self._all_rows:
            if needle and needle not in str(r.get("name", "")).lower():
                continue
            if kind == "Deleted" and r.get("kind") != "deleted":
                continue
            if kind == "Active" and r.get("kind") != "active":
                continue
            if kind == "Carved" and r.get("kind") != "carved":
                continue
            if status == "Recoverable" and r.get("status") != "recoverable":
                continue
            if status == "Overwritten" and r.get("status") != "overwritten":
                continue
            out.append(r)
        self.model.set_rows(out)
        self.preview.show_data(None, b"")

    def _on_select(self):
        sel = self.table.selectionModel().selectedRows()
        if not sel:
            self.preview.show_data(None, b"")
            return
        row = self.model.data(sel[0], Qt.UserRole)
        data = self._preview_data(row)
        self.preview.show_data(row, data)

    def _preview_data(self, row: dict) -> bytes:
        if not self._engine:
            return b""
        try:
            if row.get("kind") == "carved":
                start, size = int(row.get("start", 0)), int(row.get("size", 0))
                if size > 4 * 1024 * 1024:
                    return b""
                return self._engine.src.read(start, size)
            from ..core.engine import RecoveredItem
            item = RecoveredItem(
                name=row.get("name", ""), size=int(row.get("size", 0)),
                fs=row.get("fs", ""), kind=row.get("kind", "deleted"),
                status=row.get("status", "recoverable"), method=row.get("method", "metadata"),
                record_id=row.get("record_id", ""), recovered_bytes=int(row.get("recovered_bytes", 0)),
            )
            item._blob = b""
            data = self._engine.recover_item(item)
            row["ext"] = row.get("ext") or (item.name.rsplit(".", 1)[-1] if "." in item.name else "")
            return data
        except Exception:
            return b""

    def selected_rows(self) -> List[dict]:
        out = []
        for idx in self.table.selectionModel().selectedRows():
            r = self.model.data(idx, Qt.UserRole)
            if r:
                out.append(r)
        return out

    def all_rows(self) -> List[dict]:
        return self._all_rows

    def prompt_vault_folder(self, default: str) -> Optional[str]:
        path = QFileDialog.getExistingDirectory(self, "Choose recovery vault folder", default)
        if not path:
            QMessageBox.information(self, "Recovery", "Please choose a Vault folder to save recovered files.")
            return None
        return path