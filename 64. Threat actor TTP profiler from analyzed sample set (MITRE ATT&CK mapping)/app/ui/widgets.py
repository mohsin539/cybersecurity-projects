"""TTPProfiler :: custom QPainter widgets — heatmap, radar, kill-chain timeline."""
from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRectF, Qt, Signal
from PySide6.QtGui import QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import QSizePolicy, QWidget

from .. import data as D
from ..theme import PALETTE

TA = {t["short"]: t["name"].split(" and ")[0] for t in D.TACTICS}
TA_ORDER = [t["short"] for t in D.TACTICS]
TA_ID = {t["short"]: t["id"] for t in D.TACTICS}


def _heat_color(score: float, alpha: int = 255) -> QColor:
    score = max(0.0, min(1.0, score))
    if score >= 0.8:
        return QColor(PALETTE["magenta"] + f"{alpha:02x}")
    if score >= 0.6:
        return QColor(PALETTE["amber"] + f"{alpha:02x}")
    if score >= 0.35:
        return QColor(PALETTE["cyan"] + f"{alpha:02x}")
    return QColor(PALETTE["violet"] + f"{alpha:02x}")


class HeatmapMatrix(QWidget):
    """MITRE ATT&CK tactic:technique heatmap matrix (Navigator-style)."""

    hovered = Signal(str)

    def __init__(self, parent=None):
        super().__init__(parent)
        self._data: dict[str, list[tuple[str, float]]] = {}
        self._order: list[str] = []
        self.setMinimumHeight(300)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Expanding)
        self.setMouseTracking(True)

    def set_profile(self, tactic_scores: dict[str, float], techniques) -> None:
        by_tactic: dict[str, list[tuple[str, float]]] = {}
        for tm in techniques:
            for tshort in D.TECHNIQUE_TACTICS.get(tm.technique_id, []):
                by_tactic.setdefault(tshort, []).append((tm.technique_id, tm.score))
        for k in by_tactic:
            by_tactic[k] = sorted(by_tactic[k], key=lambda x: -x[1])
        self._data = {k: by_tactic[k] for k in TA_ORDER if by_tactic.get(k)}
        self._order = list(self._data.keys())
        self.update()

    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        if not self._order:
            p.setPen(QPen(QColor(PALETTE["muted"])))
            p.drawText(QRectF(0, 0, w, h), Qt.AlignCenter,
                       "No mappings yet — import a sample set and build a profile")
            return
        cols = len(self._order)
        rows = max((len(v) for v in self._data.values()), default=1)
        head = 36
        cell_w = max(30, (w - 20) / cols)
        cell_h = max(22, (h - head - 12) / rows)
        f_hdr = QFont("Inter", 8, QFont.DemiBold)
        f_cell = QFont("JetBrains Mono", 7)
        for ci, tshort in enumerate(self._order):
            x = 10 + ci * cell_w
            p.setFont(f_hdr)
            p.setPen(QPen(QColor(PALETTE["cyan"])))
            p.drawText(QRectF(x, 4, cell_w, head - 8), Qt.AlignCenter | Qt.TextWordWrap,
                       TA.get(tshort, tshort))
            for ri, (tid, score) in enumerate(self._data.get(tshort, [])[:rows]):
                y = head + 6 + ri * cell_h
                rect = QRectF(x + 2, y, cell_w - 4, cell_h - 4)
                p.setPen(QPen(QColor(0, 0, 0, 50)))
                p.setBrush(_heat_color(score))
                p.drawRoundedRect(rect, min(5, cell_h / 3), min(5, cell_h / 3))
                p.setFont(f_cell)
                p.setPen(QPen(QColor("#08121F")))
                p.drawText(rect, Qt.AlignCenter, tid)
        p.end()

    def mouseMoveEvent(self, ev) -> None:
        if not self._order:
            return
        w = self.width()
        head = 36
        cell_w = max(30, (w - 20) / len(self._order))
        ci = int((ev.position().x() - 10) / cell_w)
        if 0 <= ci < len(self._order):
            rows = max((len(v) for v in self._data.values()), default=1)
            cell_h = max(22, (self.height() - head - 12) / rows)
            ri = int((ev.position().y() - head - 6) / cell_h)
            items = self._data.get(self._order[ci], [])
            if 0 <= ri < len(items):
                self.hovered.emit(items[ri][0])


def _pt(cx: float, cy: float, r: float, ang: float) -> QPointF:
    return QPointF(cx + r * math.cos(ang), cy + r * math.sin(ang))


class TacticRadar(QWidget):
    """Coverage radar over engaged tactics."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scores: dict[str, float] = {}
        self.setMinimumSize(340, 300)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_profile(self, tactic_scores: dict[str, float]) -> None:
        self._scores = dict(tactic_scores)
        self.update()

    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        cx, cy = w * 0.52, h * 0.53
        R = min(w, h) * 0.33
        axes = [t["short"] for t in D.TACTICS if self._scores.get(t["short"], 0) > 0]
        if len(axes) < 3:
            p.setPen(QPen(QColor(PALETTE["muted"])))
            p.drawText(QRectF(0, 0, w, h), Qt.AlignCenter, "Tactic coverage radar")
            return
        maxv = max(self._scores.values()) or 1.0
        n = len(axes)

        def val(k: str) -> float:
            return 0.15 + 0.85 * min(1.0, self._scores[k] / maxv)

        for ring in (1, 2, 3):
            path = QPainterPath()
            r = R * ring / 3
            for i in range(n):
                pt = _pt(cx, cy, r, _ang(i, n))
                path.lineTo(pt) if i else path.moveTo(pt)
            path.closeSubpath()
            p.setPen(QPen(QColor("#243148"), 1))
            p.drawPath(path)
        for i in range(n):
            ang = _ang(i, n)
            p.setPen(QPen(QColor("#26334B"), 1))
            p.drawLine(QPointF(cx, cy), _pt(cx, cy, R, ang))

        poly = QPainterPath()
        for i, key in enumerate(axes):
            pt = _pt(cx, cy, R * val(key), _ang(i, n))
            poly.lineTo(pt) if i else poly.moveTo(pt)
        poly.closeSubpath()
        grad = QLinearGradient(cx - R, cy - R, cx + R, cy + R)
        grad.setColorAt(0, QColor(0, 229, 255, 90))
        grad.setColorAt(1, QColor(255, 46, 151, 110))
        p.fillPath(poly, grad)
        p.setPen(QPen(QColor("#00E5FF"), 1.6))
        p.drawPath(poly)

        p.setBrush(QColor("#00E5FF"))
        for i, key in enumerate(axes):
            ang = _ang(i, n)
            pt = _pt(cx, cy, R * val(key), ang)
            p.drawEllipse(pt, 3, 3)
            label = TA.get(key, key)
            lp = _pt(cx, cy, R + 16, ang)
            p.setFont(QFont("Inter", 7))
            p.setPen(QPen(QColor(PALETTE["muted"])))
            p.drawText(QRectF(lp.x() - 50, lp.y() - 9, 100, 18), Qt.AlignCenter, label)
        p.end()


def _ang(i: int, n: int) -> float:
    return 2 * math.pi * i / n - math.pi / 2


class KillChainTimeline(QWidget):
    """Horizontal attack-chain phase coverage."""

    def __init__(self, parent=None):
        super().__init__(parent)
        self._scores: dict[str, float] = {}
        self.setMinimumHeight(104)
        self.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)

    def set_profile(self, tactic_scores: dict[str, float]) -> None:
        self._scores = dict(tactic_scores)
        self.update()

    def paintEvent(self, _ev) -> None:
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        w, h = self.width(), self.height()
        axis = [k for k in TA_ORDER if self._scores.get(k, 0) > 0]
        if not axis:
            p.setPen(QPen(QColor(PALETTE["muted"])))
            p.drawText(QRectF(0, 0, w, h), Qt.AlignCenter, "Kill-chain coverage timeline")
            return
        maxv = max(self._scores.values()) or 1.0
        x0, x1 = 34, w - 16
        y = h * 0.48
        seg = (x1 - x0) / len(axis)
        for i, k in enumerate(axis):
            val = min(1.0, self._scores[k] / maxv)
            start = x0 + i * seg
            end = x0 + (i + 1) * seg - 6
            p.setPen(QPen(_heat_color(val), 11, Qt.SolidLine, Qt.RoundCap))
            p.drawLine(int(start + 2), int(y), int(end), int(y))
            p.setFont(QFont("Inter", 7))
            p.setPen(QPen(QColor("#E8F0FE")))
            p.drawText(QRectF(start, y + 16, seg, 14), Qt.AlignHCenter, TA_ID.get(k, k))
            p.setPen(QPen(QColor(PALETTE["muted"])))
            p.drawText(QRectF(start, y - 26, seg, 14), Qt.AlignHCenter, TA.get(k, k)[:10])
        p.end()