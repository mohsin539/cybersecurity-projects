"""Timeline page: thread swimlanes with colorful event bars (architecture
§5.4 screen 3, analysis.graph.aggregate_sessions)."""

from __future__ import annotations

from PySide6.QtCore import Qt, QPointF, QRectF, Signal, QRect
from PySide6.QtGui import QColor, QFont, QPainter, QPen, QBrush, QWheelEvent, QMouseEvent
from PySide6.QtWidgets import (
    QHBoxLayout, QLabel, QTableWidget, QTableWidgetItem, QVBoxLayout, QWidget,
)

from .theme import cat_color
from .widgets import section_title


class SwimlaneCanvas(QWidget):
    event_selected = Signal(dict)
    ROW_H = 34
    LANE_W = 150
    HEADER_H = 46

    def __init__(self) -> None:
        super().__init__()
        self.rows: list[list] = []  # per-page rows
        self.entry_lut: dict[int, tuple] = {}
        self.scale = 1.6
        self.offset = 0.0
        self.hover: dict | None = None
        self._drag = None
        self.setMinimumHeight(320)
        self.setMouseTracking(True)

    # ----------------------------------------------------------------- data
    def set_session(self, svc, session_id: str) -> None:
        events = svc.store.iter_events(session_id)
        from ..analysis.graph import aggregate_sessions
        tid_map = aggregate_sessions(events)
        self.tids = sorted(tid_map)
        max_per_lane = max((len(v) for v in tid_map.values()), default=1)
        self.pages = []
        page = []
        for tid in self.tids:
            for e in tid_map[tid]:
                idx = len(page)
                page.append((tid, e))
                if len(page) >= 1200:
                    self.pages.append(page)
                    page = []
        if page or not self.pages:
            self.pages.append(page)
        self.page_idx = 0
        self._layout_page()
        self.event_selected.emit({})

    def _layout_page(self) -> None:
        self.rows = self.pages[self.page_idx] if self.pages else []
        if not self.rows:
            self.min_time = 0.0
            self.max_time = 1.0
        else:
            self.min_time = min(e[0] for _, e in self.rows)
            self.max_time = max(e[0] for _, e in self.rows) + 0.01
        self.update()

    # ---------------------------------------------------------------- paint
    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        p.fillRect(self.rect(), QColor("#0b1120"))
        if not self.rows:
            p.setPen(QColor("#8ea0bf"))
            p.drawText(self.rect(), Qt.AlignCenter, "No events for this session — run a capture first.")
            return

        self.lane_tid = self.tids
        lanes_h = self.HEADER_H
        for i, tid in enumerate(self.tids):
            lane_top = lanes_h + i * self.ROW_H
            if i % 2 == 0:
                p.fillRect(QRect(0, lane_top, self.width(), self.ROW_H), QColor("#0e1628"))
            # lane label
            p.setPen(QColor("#a78bfa"))
            p.setFont(QFont("Segoe UI", 9, QFont.Bold))
            p.drawText(QRect(6, lane_top, self.LANE_W - 10, self.ROW_H),
                       Qt.AlignVCenter | Qt.AlignLeft, f"TID {tid}")
            # separator
            p.setPen(QPen(QColor("#233454"), 1))
            p.drawLine(0, lane_top + self.ROW_H, self.width(), lane_top + self.ROW_H)

        span = max(self.max_time - self.min_time, 1e-6)
        lane_top_of = {tid: i for i, tid in enumerate(self.tids)}
        for tid, (ts, pid, api, cat, status, ret) in self.rows:
            x = self.LANE_W + (ts - self.min_time) / span * (self.width() - self.LANE_W) * self.scale - self.offset
            lane = lane_top_of[tid]
            top = self.HEADER_H + lane * self.ROW_H + 4
            w = max(3.0, 10.0 / self.scale)
            color = cat_color(cat)
            if status == "FAIL" or status == "TIMEOUT":
                color = QColor("#fb7185")
            p.setPen(QPen(color.darker(150), 1))
            p.setBrush(QBrush(color))
            p.drawRoundedRect(QRectF(x, top, w, self.ROW_H - 8), 2, 2)

        # time axis header
        p.setPen(QColor("#22d3ee"))
        p.setFont(QFont("Segoe UI", 8))
        p.drawText(QRect(self.LANE_W, 6, self.width() - self.LANE_W, 30),
                   Qt.AlignLeft | Qt.AlignVCenter,
                   f"page {self.page_idx + 1}/{len(self.pages)}  ·  +zoom  −shift  ·  "
                   f"span {span * 1e6:.1f} ms")
        p.setPen(QPen(QColor("#22d3ee"), 1))
        p.drawLine(0, self.HEADER_H, self.width(), self.HEADER_H)

        if self.hover:
            tid_h, (ts_h, pid_h, api_h, cat_h, status_h, ret_h) = self.hover
            lane = lane_top_of[tid_h]
            y = self.HEADER_H + lane * self.ROW_H + self.ROW_H // 2
            p.setPen(QPen(QColor("#fbbf24"), 1, Qt.DashLine))
            p.drawLine(0, y, self.width(), y)
        p.end()

    # ------------------------------------------------------------- events
    def mousePressEvent(self, e: QMouseEvent) -> None:
        if e.button() == Qt.MiddleButton:
            self._drag = (e.position().x(), self.offset)
        else:
            hit = self._hit(e.position().x(), e.position().y())
            if hit:
                self.event_selected.emit(hit)
            else:
                self.event_selected.emit({})
        super().mousePressEvent(e)

    def mouseMoveEvent(self, e: QMouseEvent) -> None:
        if self._drag is not None:
            x0, off0 = self._drag
            self.offset = off0 + (x0 - e.position().x())
            self.offset = max(self.offset, 0.0)
            self.update()
            return
        hit = self._hit(e.position().x(), e.position().y())
        self.hover = (hit["tid"], (hit["ts"], hit["pid"], hit["api"], hit["cat"],
                                   hit["status"], hit["ret"])) if hit else None
        self.update()
        super().mouseMoveEvent(e)

    def mouseReleaseEvent(self, e: QMouseEvent) -> None:
        self._drag = None
        super().mouseReleaseEvent(e)

    def wheelEvent(self, e: QWheelEvent) -> None:
        delta = e.angleDelta().y()
        self.scale *= 1.12 if delta > 0 else 1 / 1.12
        self.scale = min(max(self.scale, 0.2), 60.0)
        self.update()

    def _hit(self, x: float, y: float) -> dict | None:
        if not self.rows:
            return None
        if x < self.LANE_W or y < self.HEADER_H:
            return None
        lane = int((y - self.HEADER_H) // self.ROW_H)
        if lane < 0 or lane >= len(self.tids):
            return None
        tid = self.tids[lane]
        span = max(self.max_time - self.min_time, 1e-6)
        t = self.min_time + (x + self.offset - self.LANE_W) / self.scale / (self.width() - self.LANE_W) * span
        best = None
        bd = float("inf")
        for row_tid, rec in self.rows:
            if row_tid != tid:
                continue
            d = abs(rec[0] - t)
            if d < bd:
                bd = d
                best = rec
        if best is None:
            return None
        return {"tid": tid, "ts": best[0], "pid": best[1], "api": best[2],
                "cat": best[3], "status": best[4], "ret": best[5]}

    def next_page(self, by: int = 1) -> None:
        if not self.pages:
            return
        self.page_idx = (self.page_idx + by) % len(self.pages)
        self._layout_page()


class TimelinePage(QWidget):
    def __init__(self, bus, win) -> None:
        super().__init__()
        self.bus = bus
        self.win = win
        self._build()

    def _build(self) -> None:
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(12)

        head = QHBoxLayout()
        title = QLabel("Timeline (thread swimlanes)")
        title.setObjectName("PageTitle")
        head.addWidget(title)
        head.addStretch(1)
        self.session_lab = QLabel("no session selected")
        self.session_lab.setObjectName("kpi_label")
        head.addWidget(self.session_lab)
        lay.addLayout(head)

        self.canvas = SwimlaneCanvas()
        self.canvas.event_selected.connect(self._show_detail)
        lay.addWidget(self.canvas, stretch=3)

        nav = QHBoxLayout()
        prev = self._btn("◀ prev page", lambda: self.canvas.next_page(-1))
        nxt = self._btn("next page ▶", lambda: self.canvas.next_page(1))
        nav.addWidget(prev)
        nav.addWidget(nxt)
        nav.addStretch(1)
        lay.addLayout(nav)

        lay.addWidget(section_title("Event detail"))
        self.grid = QTableWidget(1, 5)
        self.grid.setHorizontalHeaderLabels(["API", "Category", "Status", "Return", "TID"])
        self.grid.setAlternatingRowColors(True)
        self.grid.horizontalHeader().setStretchLastSection(True)
        self.grid.setEditTriggers(QTableWidget.NoEditTriggers)
        lay.addWidget(self.grid, stretch=2)
        self.bus.session_changed.connect(self._reload)

    def _btn(self, text: str, fn):
        from PySide6.QtWidgets import QPushButton
        b = QPushButton(text)
        b.clicked.connect(fn)
        return b

    def on_shown(self) -> None:
        self._reload()

    def _reload(self) -> None:
        if not self.bus.session_id:
            return
        self.session_lab.setText(self.bus.session_id)
        self.canvas.set_session(self.win.services, self.bus.session_id)

    def _show_detail(self, rec: dict) -> None:
        if not rec:
            return
        self.grid.setItem(0, 0, QTableWidgetItem(rec["api"]))
        self.grid.setItem(0, 1, QTableWidgetItem(rec["cat"]))
        self.grid.setItem(0, 2, QTableWidgetItem(rec["status"]))
        self.grid.setItem(0, 3, QTableWidgetItem(rec["ret"]))
        self.grid.setItem(0, 4, QTableWidgetItem(str(rec["tid"])))
        self.grid.resizeColumnsToContents()