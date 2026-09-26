"""Main window: sidebar navigation + stacked pages (architecture §5.4)."""

from __future__ import annotations

from PySide6.QtCore import Qt, Signal
from PySide6.QtWidgets import (
    QButtonGroup, QFrame, QHBoxLayout, QLabel, QPushButton, QStackedWidget,
    QVBoxLayout, QWidget,
)

from ..version import APP_NAME, APP_VERSION
from .audit_viewer import AuditPage
from .compliance_console import CompliancePage
from .dashboard import DashboardPage
from .capture import CapturePage
from .graph_view import GraphPage
from .heatmap import HeatmapPage
from .report_studio import ReportStudioPage
from .settings_view import SettingsPage
from .theme import STYLE_SHEET
from .timeline import TimelinePage


class SessionBus(QWidget):
    """Shared active-session selection used by viewer/report pages."""

    session_changed = Signal()

    def __init__(self) -> None:
        super().__init__()
        self.session_id: str | None = None
        self.sample_id: int | None = None

    def select(self, session_id: str, sample_id: int | None = None) -> None:
        self.session_id = session_id
        self.sample_id = sample_id
        self.session_changed.emit()


class MainWindow(QWidget):
    def __init__(self, services) -> None:
        super().__init__()
        self.services = services
        self.bus = SessionBus()
        self.setWindowTitle(f"{APP_NAME}  ·  v{APP_VERSION}")
        self.resize(1440, 860)
        self.setMinimumSize(1180, 720)

        root = QVBoxLayout(self)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        body = QWidget()
        body_lay = QHBoxLayout(body)
        body_lay.setContentsMargins(0, 0, 0, 0)
        body_lay.setSpacing(0)

        body_lay.addWidget(self._build_sidebar())

        self.stack = QStackedWidget()
        body_lay.addWidget(self.stack, stretch=1)
        root.addWidget(body)

        self._install_pages()
        self.setStyleSheet(STYLE_SHEET)
        self._goto(0)

    # ------------------------------------------------------------- sidebar
    def _build_sidebar(self) -> QFrame:
        sidebar = QFrame()
        sidebar.setObjectName("Sidebar")
        sidebar.setFixedWidth(216)
        lay = QVBoxLayout(sidebar)
        lay.setContentsMargins(10, 18, 10, 18)
        lay.setSpacing(4)

        logo = QLabel("▦ ACSV")
        logo.setStyleSheet(
            "font-size:20px; font-weight:800; color:#22d3ee; padding:6px 12px;"
        )
        lay.addWidget(logo)
        sub = QLabel("API Call Sequence Visualizer")
        sub.setStyleSheet("color:#8ea0bf; font-size:11px; padding:0 12px 10px 12px;")
        lay.addWidget(sub)

        lay.addWidget(self._nav_label("NAVIGATION"))
        self.nav_buttons: list[tuple[str, int]] = []
        items = [
            ("◈  Dashboard", 0),
            ("⚡  Capture & Intake", 1),
            ("⏱  Timeline", 2),
            ("▦  Heatmap", 3),
            ("⧉  Call Graph", 4),
            ("▤  Report Studio", 5),
            ("🛡  Compliance Console", 6),
            ("∿  Audit Log", 7),
            ("⚙  Settings", 8),
        ]
        grp = QButtonGroup(self)
        grp.setExclusive(True)
        for text, idx in items:
            btn = QPushButton(text)
            btn.setCheckable(True)
            btn.setCursor(Qt.PointingHandCursor)
            grp.addButton(btn, idx)
            btn.clicked.connect(lambda _=False, i=idx: self._goto(i))
            lay.addWidget(btn)
        lay.addStretch(1)

        db = QLabel(f"DB: {self.services.config.data_dir.name} · policy {self.services.policy.snapshot_hash[:8]}")
        db.setStyleSheet("color:#3f5370; font-size:10px; padding:8px 12px;")
        db.setWordWrap(True)
        lay.addWidget(db)
        return sidebar

    def _nav_label(self, text: str) -> QLabel:
        lab = QLabel(text)
        lab.setStyleSheet(
            "color:#5b6d8f; font-size:11px; letter-spacing:1px; padding:6px 12px 0 12px;"
        )
        return lab

    # ---------------------------------------------------------------- pages
    def _install_pages(self) -> None:
        self.dashboard = DashboardPage(self.bus, self)
        self.capture = CapturePage(self.bus, self)
        self.timeline = TimelinePage(self.bus, self)
        self.heatmap = HeatmapPage(self.bus, self)
        self.graph = GraphPage(self.bus, self)
        self.report = ReportStudioPage(self.bus, self)
        self.compliance = CompliancePage(self)
        self.audit = AuditPage(self)
        self.settings = SettingsPage(self)
        for page in (self.dashboard, self.capture, self.timeline, self.heatmap,
                     self.graph, self.report, self.compliance, self.audit, self.settings):
            self.stack.addWidget(page)

    def _goto(self, idx: int) -> None:
        self.stack.setCurrentIndex(idx)
        page = self.stack.currentWidget()
        if hasattr(page, "on_shown"):
            page.on_shown()
        self.services.record("ACCESS_NAV", {"page": type(page).__name__})