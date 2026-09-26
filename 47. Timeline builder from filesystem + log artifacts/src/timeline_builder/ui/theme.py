from __future__ import annotations

SEVERITY_COLORS = {
    "info": "#60a5fa",
    "low": "#34d399",
    "medium": "#fbbf24",
    "high": "#fb923c",
    "critical": "#f43f5e",
}

DARK_QSS = """
* { font-family: "Segoe UI", "Inter", sans-serif; font-size: 13px; }
QMainWindow, QWidget#Root { background-color: #070b18; color: #e6ecff; }
QToolBar {
    background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #0f1730, stop:1 #141d3a);
    border: none; border-bottom: 1px solid #22305c; padding: 6px; spacing: 6px;
}
QToolButton {
    background: rgba(255,255,255,0.04); border: 1px solid #22305c; color: #e6ecff;
    padding: 7px 12px; border-radius: 9px; font-weight: 600;
}
QToolButton:hover { border-color: #22d3ee; background: rgba(34,211,238,0.12); }
QToolButton:pressed { background: rgba(34,211,238,0.22); }
QToolButton:disabled { color: #5b6b93; border-color: #1a2440; }
QDockWidget { color: #8ea0cc; titlebar-close-icon: none; titlebar-normal-icon: none; font-weight: 700; }
QDockWidget::title { background: #0f1730; padding: 8px; border-bottom: 1px solid #22305c; }
QGroupBox {
    border: 1px solid #22305c; border-radius: 12px; margin-top: 16px; padding: 12px 10px 10px; background: #0f1730;
}
QGroupBox::title { subcontrol-origin: margin; left: 12px; padding: 0 6px; color: #22d3ee; font-weight: 700; }
QLineEdit, QComboBox, QListWidget, QPlainTextEdit, QTextBrowser, QSpinBox, QDateEdit {
    background: #0b1226; border: 1px solid #22305c; border-radius: 9px; padding: 7px; color: #e6ecff;
    selection-background-color: #22d3ee; selection-color: #05070f;
}
QLineEdit:focus, QComboBox:focus, QSpinBox:focus, QDateEdit:focus { border-color: #22d3ee; }
QComboBox QAbstractItemView { background: #0b1226; border: 1px solid #22305c; selection-background-color: #22d3ee; selection-color: #05070f; }
QPushButton {
    background: qlineargradient(x1:0, y1:0, x2:0, y2:1, stop:0 #22d3ee, stop:1 #0891b2);
    color: #04121a; border: none; border-radius: 9px; padding: 8px 14px; font-weight: 700;
}
QPushButton:hover { background: #38dcf0; }
QPushButton:disabled { background: #1a2440; color: #5b6b93; }
QPushButton#Ghost { background: rgba(255,255,255,0.05); border: 1px solid #22305c; color: #e6ecff; }
QPushButton#Ghost:hover { border-color: #a855f7; }
QTableView {
    background: #0b1226; alternate-background-color: #0e1630; gridline-color: #1a2440;
    border: 1px solid #22305c; border-radius: 12px; selection-background-color: rgba(34,211,238,0.22);
    selection-color: #ffffff;
}
QHeaderView::section {
    background: #0f1730; color: #8ea0cc; padding: 8px; border: none; border-right: 1px solid #1a2440;
    border-bottom: 1px solid #22305c; font-weight: 700;
}
QTableView QTableCornerButton::section { background: #0f1730; border: none; }
QProgressBar {
    background: #0b1226; border: 1px solid #22305c; border-radius: 8px; text-align: center; color: #e6ecff;
    height: 16px;
}
QProgressBar::chunk { border-radius: 7px; background: qlineargradient(x1:0, y1:0, x2:1, y2:0, stop:0 #22d3ee, stop:1 #a855f7); }
QStatusBar { background: #0f1730; border-top: 1px solid #22305c; color: #8ea0cc; }
QStatusBar QLabel { color: #8ea0cc; padding: 0 8px; }
QLabel#Title { font-size: 18px; font-weight: 800; color: #22d3ee; }
QLabel#Sub { color: #8ea0cc; }
QLabel#ChainOk { color: #34d399; font-weight: 700; }
QLabel#ChainBad { color: #f43f5e; font-weight: 700; }
QMenuBar { background: #0f1730; color: #e6ecff; }
QMenuBar::item:selected { background: rgba(34,211,238,0.15); }
QMenu { background: #0b1226; border: 1px solid #22305c; color: #e6ecff; }
QMenu::item:selected { background: rgba(34,211,238,0.18); }
QScrollBar:vertical { background: #0b1226; width: 12px; margin: 0; }
QScrollBar::handle:vertical { background: #22305c; border-radius: 6px; min-height: 30px; }
QScrollBar::handle:vertical:hover { background: #2f4380; }
QScrollBar:horizontal { background: #0b1226; height: 12px; }
QScrollBar::handle:horizontal { background: #22305c; border-radius: 6px; min-width: 30px; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }
"""


def apply_theme(app, theme: str = "dark") -> None:
    from PySide6.QtGui import QColor, QPalette

    palette = QPalette()
    palette.setColor(QPalette.Window, QColor("#070b18"))
    palette.setColor(QPalette.Base, QColor("#0b1226"))
    palette.setColor(QPalette.AlternateBase, QColor("#0e1630"))
    palette.setColor(QPalette.Text, QColor("#e6ecff"))
    palette.setColor(QPalette.WindowText, QColor("#e6ecff"))
    palette.setColor(QPalette.ButtonText, QColor("#e6ecff"))
    palette.setColor(QPalette.Highlight, QColor("#22d3ee"))
    palette.setColor(QPalette.HighlightedText, QColor("#04121a"))
    app.setPalette(palette)
    if theme == "dark":
        app.setStyleSheet(DARK_QSS)
