"""Reusable branded widgets + background worker threads."""

from __future__ import annotations

from typing import Callable, List, Optional

from PySide6.QtCore import Qt, Signal, QThread, QObject
from PySide6.QtGui import QColor, QFont, QPainter, QBrush, QLinearGradient
from PySide6.QtWidgets import (
    QFrame, QLabel, QVBoxLayout, QHBoxLayout, QPushButton, QProgressBar,
    QGraphicsDropShadowEffect, QSizePolicy,
)

from .theme import PALETTE, BRAND_GRADIENT


def linear_brush(color_a: str, color_b: str):
    return QLinearGradient()


def make_label(text: str, size: int = 13, color: str = "", bold: bool = False) -> QLabel:
    lb = QLabel(text)
    f = lb.font()
    f.setPointSizeF(size)
    f.setBold(bold)
    lb.setFont(f)
    if color:
        lb.setStyleSheet(f"color: {color};")
    return lb


def shadow(widget, blur: int = 40, y: int = 8, alpha: int = 70):
    eff = QGraphicsDropShadowEffect(widget)
    eff.setBlurRadius(blur)
    eff.setOffset(0, y)
    eff.setColor(QColor(0, 0, 0, alpha))
    widget.setGraphicsEffect(eff)
    return widget


class GradientBanner(QFrame):
    """Full-width gradient header used at the top of pages."""

    def __init__(self, title: str, subtitle: str, parent=None):
        super().__init__(parent)
        self.setObjectName("GradientBanner")
        self.setFixedHeight(112)
        lay = QVBoxLayout(self)
        lay.setContentsMargins(26, 16, 26, 12)
        self._title = make_label(title, 24, "#ffffff", True)
        self._sub = make_label(subtitle, 12, "#dfe6ff")
        lay.addWidget(self._title)
        lay.addWidget(self._sub)

    def paintEvent(self, e):
        p = QPainter(self)
        p.setRenderHint(QPainter.Antialiasing)
        gr = QLinearGradient(0, 0, self.width(), self.height())
        gr.setColorAt(0.0, QColor("#7c3aed"))
        gr.setColorAt(0.45, QColor("#4f46e5"))
        gr.setColorAt(0.8, QColor("#0ea5e9"))
        gr.setColorAt(1.0, QColor("#34d399"))
        p.fillRect(self.rect(), QBrush(gr))
        super().paintEvent(e)


def badge(text: str, tone: str = "blue") -> QPushButton:
    b = QPushButton(text)
    b.setProperty("badge", "true")
    b.setProperty("tone", tone)
    b.setEnabled(False)
    b.setCursor(Qt.ArrowCursor)
    return b


class StatCard(QFrame):
    def __init__(self, value: str, label: str, accent: str, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        self.value = make_label(value, 22, "#ffffff", True)
        self.value.setObjectName("StatValue")
        self.label = make_label(label, 10.5, PALETTE["text_dim"], False)
        self.label.setObjectName("StatLabel")
        self.value.setStyleSheet("color:#fff; font-size:21px; font-weight:700;")
        lay.addWidget(self.value)
        lay.addWidget(self.label)
        # accent underline
        seg = QFrame()
        seg.setFixedHeight(4)
        seg.setStyleSheet(f"background: {accent}; border-radius: 2px;")
        lay.addWidget(seg)


class SourceCard(QFrame):
    """Clickable source tile with filesystem badge and capacity bar."""

    clicked = Signal()

    def __init__(self, title: str, subtitle: str, fs_tone: str,
                 fs_label: str, size_text: str, used_ratio: float, parent=None):
        super().__init__(parent)
        self.setObjectName("Card")
        self.setProperty("hover", True)
        self.setCursor(Qt.PointingHandCursor)
        self.setMinimumHeight(86)

        lay = QVBoxLayout(self)
        lay.setContentsMargins(16, 12, 16, 12)
        top = QHBoxLayout()
        self.title_lb = make_label(title, 14.5, "#ffffff", True)
        self.fs_badge = badge(fs_label, fs_tone)
        self.size_lb = make_label(size_text, 12, PALETTE["text_dim"])
        top.addWidget(self.title_lb, 1)
        top.addWidget(self.size_lb)
        top.addWidget(self.fs_badge)
        self.sub_lb = make_label(subtitle, 11.5, PALETTE["text_dim"])
        lay.addLayout(top)
        lay.addWidget(self.sub_lb)

        bar_container = QFrame()
        bar_container.setFixedHeight(8)
        bc_lay = QHBoxLayout(bar_container)
        bc_lay.setContentsMargins(0, 0, 0, 0)
        track = QProgressBar()
        track.setRange(0, 1000)
        track.setValue(int(used_ratio * 1000))
        track.setFixedHeight(8)
        track.setTextVisible(False)
        track.setStyleSheet(
            "QProgressBar{background:#101a2e;border:none;border-radius:4px;}"
            f"QProgressBar::chunk{{background:{fs_tone};border-radius:4px;}}")
        bc_lay.addWidget(track)
        lay.addWidget(bar_container)

    def mouseReleaseEvent(self, e):
        if e.button() == Qt.LeftButton:
            self.clicked.emit()
        super().mouseReleaseEvent(e)


SCAN_UNITS = [
    ("metadata", "Metadata scan (fast)", "Directory + $MFT walk; finds deleted files by name/records."),
    ("orphan", "Orphan cluster scan", "Sweep data clusters for deleted directory entries (FAT)."),
    ("carve", "Signature carving (deep)", "Carve JPEG/PNG/PDF/ZIP/OFFICE/… from unallocated space."),
]


class ScanWorker(QObject):
    """Runs the recovery engine scanner on a QThread."""

    progress = Signal(str, float)
    results_ready = Signal(list)
    carved_ready = Signal(list)
    done = Signal(dict)
    failed = Signal(str)

    def __init__(self, engine, want_active=True, want_deleted=True,
                 orphan=True, carve=False, group_filter=None, ext_filter=None):
        super().__init__()
        self.engine = engine
        self.want_active = want_active
        self.want_deleted = want_deleted
        self.orphan = orphan
        self.carve = carve
        self.group_filter = group_filter
        self.ext_filter = ext_filter
        self._stop = False

    def stop(self):
        self._stop = True

    def run(self):
        try:
            result = self.engine.metadata_scan(
                progress=self._on_progress,
                want_active=self.want_active,
                want_deleted=self.want_deleted,
                scan_orphans=self.orphan,
            )
            # Keep recovered blob caching bounded: only small files stay in RAM.
            items = [i for i in result.items]
            self.results_ready.emit(items)
            carved = []
            if self.carve and not self._stop:
                carved = self.engine.carve(
                    group_filter=self.group_filter, ext_filter=self.ext_filter,
                    progress=self._on_progress, stop_flag=self.is_stopped)
                self.carved_ready.emit(carved)
            stats = dict(result.stats)
            stats["carved"] = len(carved)
            stats["fs"] = result.fs
            stats["warnings"] = result.warnings
            self.done.emit(stats)
        except Exception as e:  # noqa: BLE001 — surfaced to UI
            self.failed.emit(f"{type(e).__name__}: {e}")

    def is_stopped(self):
        return self._stop

    def _on_progress(self, msg: str, frac: float):
        self.progress.emit(msg, min(1.0, max(0.0, frac)))


class RecoverWorker(QObject):
    """Recovers a batch of items into the vault off the UI thread."""

    progress = Signal(int, int, str)
    one_recovered = Signal(dict)
    done = Signal(int, int)
    failed = Signal(str)

    def __init__(self, engine, items, vault, audit):
        super().__init__()
        self.engine = engine
        self.items = items
        self.vault = vault
        self.audit = audit

    def run(self):
        ok_count = 0
        for i, item in enumerate(self.items):
            try:
                data = self.engine.recover_item(item)
                if not data:
                    self.progress.emit(i + 1, len(self.items), "no bytes recovered")
                    continue
                ext = item.name.rsplit(".", 1)[-1] if "." in item.name else ""
                entry = self.vault.store(data, item.name, kind="deleted" if item.kind != "carved" else "carved", ext=ext)
                self.audit.log("artifact_recovered", detail={"name": item.name, "sha": entry["sha256"], "size": len(data)})
                ok_count += 1
                self.one_recovered.emit(entry)
            except Exception as e:  # noqa: BLE001
                self.audit.log("artifact_recovery_failed", result="error", detail={"name": item.name, "error": str(e)[:200]})
            self.progress.emit(i + 1, len(self.items), f"{ok_count} recovered")
        self.done.emit(ok_count, len(self.items))