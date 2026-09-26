"""Call-graph page: force-layout style graph via QGraphicsView
(architecture §5.4 screen 4)."""

from __future__ import annotations

import math

from PySide6.QtCore import QPointF, QRect, Qt
from PySide6.QtGui import QBrush, QColor, QFont, QLinearGradient, QPainter, QPainterPath, QPen
from PySide6.QtWidgets import (
    QGraphicsItem, QGraphicsPathItem, QGraphicsScene, QGraphicsView,
    QHBoxLayout, QLabel, QVBoxLayout, QWidget,
)

from .theme import CAT_COLORS


class _EdgeItem(QGraphicsPathItem):
    def __init__(self, path, color, width) -> None:
        super().__init__(path)
        pen = QPen(color, width)
        pen.setCosmetic(True)
        self.setPen(pen)


class _NodeItem(QGraphicsItem):
    def __init__(self, label: str, count: int) -> None:
        super().__init__()
        self.label = label
        self.count = count
        self.setToolTip(f"{label} · calls:{count}")
        self.setFlag(QGraphicsItem.ItemIsMovable)

    def boundingRect(self):
        return QRect(-34, -22, 68, 44)

    def paint(self, painter: QPainter, _opt, _w) -> None:
        painter.setRenderHint(QPainter.Antialiasing)
        rect = self.boundingRect()
        grad = QLinearGradient(rect.topLeft(), rect.bottomLeft())
        grad.setColorAt(0, QColor("#123a4d"))
        grad.setColorAt(1, QColor("#0e1730"))
        painter.setBrush(QBrush(grad))
        painter.setPen(QPen(QColor("#22d3ee"), 1.6))
        painter.drawRoundedRect(rect, 10, 10)
        painter.setPen(QColor("#e2e8f0"))
        painter.setFont(QFont("Segoe UI", 8, QFont.Bold))
        painter.drawText(rect, Qt.AlignCenter, self.label[:24])
        painter.setPen(QColor("#fbbf24"))
        painter.setFont(QFont("Segoe UI", 7))
        painter.drawText(QRect(rect.left(), rect.top() - 14, rect.width(), 13),
                         Qt.AlignCenter, f"×{self.count}")


class CallGraphView(QGraphicsView):
    def __init__(self) -> None:
        super().__init__()
        self.setScene(QGraphicsScene(self))
        self.setRenderHint(QPainter.Antialiasing)
        self.setBackgroundBrush(QColor("#0b1120"))
        self.setDragMode(QGraphicsView.ScrollHandDrag)
        self.scale(1.05, 1.05)

    def set_graph(self, graph: dict) -> None:
        scene = self.scene()
        scene.clear()
        nodes, edges = graph.get("nodes", []), graph.get("edges", [])
        if not nodes:
            return
        node_map = {}
        width = max(self.viewport().width(), 900)
        height = max(self.viewport().height(), 600)
        rx = max(width / 2 - 80, 140)
        ry = max(height / 2 - 60, 100)
        for i, nd in enumerate(nodes):
            ang = i / len(nodes) * 2 * math.pi
            x = width / 2 + rx * math.cos(ang)
            y = height / 2 + ry * math.sin(ang) * 0.7
            node = _NodeItem(nd.get("label", ""), nd.get("count", 0))
            node.setPos(QPointF(x, y))
            scene.addItem(node)
            node_map[nd.get("label")] = node
        for e in edges:
            a = node_map.get(e.get("from"))
            b = node_map.get(e.get("to"))
            if a is None or b is None:
                continue
            col = QColor(CAT_COLORS["Process"])
            col.setAlpha(min(230, 120 + int(e.get("value", 1)) * 10))
            edge = _EdgeItem(_edge_path(a.pos(), b.pos()), col,
                             min(5.0, 1.2 + e.get("value", 1) * 0.4))
            scene.addItem(edge)
            edge.setZValue(-1)
        scene.setSceneRect(scene.itemsBoundingRect().adjusted(-80, -80, 80, 80))
        self.fitInView(scene.sceneRect(), Qt.KeepAspectRatio)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        if self.scene() and self.scene().items():
            self.fitInView(self.scene().sceneRect(), Qt.KeepAspectRatio)


def _edge_path(a: QPointF, b: QPointF) -> QPainterPath:
    r = 22.0
    dx, dy = b.x() - a.x(), b.y() - a.y()
    length = max(math.hypot(dx, dy), 1.0)
    ux, uy = dx / length, dy / length
    p1 = QPointF(a.x() + ux * r, a.y() + uy * r)
    p2 = QPointF(b.x() - ux * r, b.y() - uy * r)
    path = QPainterPath(p1)
    path.cubicTo(p1.x() + (p2.x() - p1.x()) * 0.4, p1.y(),
                 p1.x() + (p2.x() - p1.x()) * 0.6, p2.y(), p2.x(), p2.y())
    return path


class GraphPage(QWidget):
    def __init__(self, bus, win) -> None:
        super().__init__()
        self.bus = bus
        self.win = win
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 22, 26, 22)
        lay.setSpacing(12)
        head = QHBoxLayout()
        title = QLabel("Call Sequence Graph")
        title.setObjectName("PageTitle")
        head.addWidget(title)
        head.addStretch(1)
        self.session_lab = QLabel("no session")
        self.session_lab.setObjectName("kpi_label")
        head.addWidget(self.session_lab)
        lay.addLayout(head)
        self.view = CallGraphView()
        lay.addWidget(self.view, stretch=1)
        self.bus.session_changed.connect(self.on_shown)

    def on_shown(self) -> None:
        if not self.bus.session_id:
            return
        self.session_lab.setText(self.bus.session_id)
        analysis = self.win.services.analysis.analyze(self.bus.session_id)
        from ..report.exports import graph_payload
        self.view.set_graph(graph_payload(analysis))