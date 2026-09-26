"""Colorful dark cyber theme (architecture §5.4).

Palette: cyan/violet/amber/rose/emerald on deep navy. QSS targets PySide6
widgets; every color token is exported for custom painters.
"""

from PySide6.QtGui import QColor

ACCENTS = {
    "cyan": "#22d3ee",
    "violet": "#a78bfa",
    "amber": "#fbbf24",
    "rose": "#fb7185",
    "emerald": "#34d399",
    "slate": "#94a3b8",
}

CAT_COLORS = {
    "File": "#22d3ee",
    "Registry": "#a78bfa",
    "Network": "#34d399",
    "Process": "#fbbf24",
    "Thread": "#fb7185",
    "Crypto": "#f1fa8c",
    "Memory": "#ef4444",
    "IPC": "#ffb86b",
    "Exception": "#ff5555",
    "Other": "#64748b",
}

STATUS_COLORS = {
    "SUCCESS": "#34d399",
    "FAIL": "#fb7185",
    "TIMEOUT": "#fbbf24",
    "UNKNOWN": "#94a3b8",
}

SEVERITY_COLORS = {
    "info": "#38bdf8",
    "low": "#4ade80",
    "medium": "#fbbf24",
    "high": "#fb7185",
    "critical": "#f43f5e",
}

COLORS = {
    "bg": QColor("#0b1120"),
    "panel": QColor("#111a2c"),
    "panel_alt": QColor("#16233c"),
    "border": QColor("#2b3c56"),
    "text": QColor("#e2e8f0"),
    "text_dim": QColor("#8ea0bf"),
    "accent": QColor("#22d3ee"),
    "success": QColor("#34d399"),
    "warn": QColor("#fbbf24"),
    "danger": QColor("#fb7185"),
}

STYLE_SHEET = """
* {
    font-family: "Segoe UI", "Segoe UI Variable Text";
    font-size: 13px;
}
QWidget {
    background: #0b1120;
    color: #e2e8f0;
}
QMainWindow, QDialog {
    background: #0b1120;
}
#Sidebar {
    background: #0e1730;
    border-right: 1px solid #233454;
}
#Sidebar QPushButton {
    background: transparent;
    color: #94a3b8;
    border: none;
    text-align: left;
    padding: 12px 18px;
    border-radius: 8px;
    font-size: 13px;
}
#Sidebar QPushButton:hover {
    background: #182744;
    color: #dbeafe;
}
#Sidebar QPushButton:checked {
    background: #123a4d;
    color: #22d3ee;
    border-left: 3px solid #22d3ee;
}
#Sidebar QLabel {
    color: #64748b;
    font-size: 11px;
    padding: 10px 18px 2px 18px;
    letter-spacing: 1px;
}
QPushButton {
    background: #123a4d;
    color: #e0f2fe;
    border: 1px solid #185e7a;
    border-radius: 8px;
    padding: 8px 16px;
}
QPushButton:hover { background: #155a75; }
QPushButton:pressed { background: #0f3a4d; }
QPushButton:disabled { background: #1c2940; color: #64748b; border-color: #26344f; }
QPushButton#Primary {
    background: #0ea5e9;
    color: #04101a;
    font-weight: 600;
    border: none;
}
QPushButton#Primary:hover { background: #38bdf8; }
QPushButton#Danger {
    background: #7f1d1d;
    color: #fee2e2;
    border: 1px solid #b91c1c;
}
QPushButton#Danger:hover { background: #991b1b; }
QLineEdit, QTextEdit, QPlainTextEdit, QComboBox, QSpinBox, QDateEdit {
    background: #0f1830;
    color: #e2e8f0;
    border: 1px solid #2b3c56;
    border-radius: 8px;
    padding: 8px 10px;
    selection-background-color: #155e75;
}
QLineEdit:focus, QComboBox:focus { border-color: #22d3ee; }
QComboBox::drop-down { border: none; width: 22px; }
QComboBox QAbstractItemView {
    background: #111a2c;
    border: 1px solid #2b3c56;
    border-radius: 6px;
    selection-background-color: #0ea5e9;
    selection-color: #04101a;
}
QTableView, QTableWidget {
    background: #0e1628;
    alternate-background-color: #111c33;
    gridline-color: #24344f;
    selection-background-color: #155e75;
    selection-color: #ecfeff;
    border: 1px solid #233454;
    border-radius: 8px;
}
QHeaderView::section {
    background: #16233c;
    color: #22d3ee;
    padding: 8px;
    border: none;
    border-bottom: 2px solid #185e7a;
    font-weight: 600;
}
QTableWidget::item { padding: 4px 6px; }
QTabWidget::pane {
    border: 1px solid #233454;
    border-radius: 8px;
}
QTabBar::tab {
    background: #0e1730;
    color: #94a3b8;
    padding: 8px 16px;
    border: 1px solid #233454;
    border-bottom: none;
    border-top-left-radius: 8px;
    border-top-right-radius: 8px;
}
QTabBar::tab:selected {
    color: #22d3ee;
    background: #12304a;
}
QScrollBar:vertical {
    background: #0e1628;
    width: 10px;
    border-radius: 5px;
}
QScrollBar::handle:vertical {
    background: #2b3c56;
    border-radius: 5px;
    min-height: 30px;
}
QScrollBar::handle:vertical:hover { background: #3b506f; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; }
QStatusBar { background: #0e1730; color: #8ea0bf; }
QMenuBar { background: #0e1730; }
QMenuBar::item { padding: 6px 12px; }
QMenu {
    background: #111a2c;
    border: 1px solid #233454;
    border-radius: 8px;
    padding: 6px;
}
QMenu::item { padding: 6px 24px 6px 16px; border-radius: 6px; }
QMenu::item:selected { background: #155e75; }
QLabel#card {
    background: #111a2c;
    border: 1px solid #233454;
    border-radius: 12px;
    padding: 14px;
}
QLabel#kpi_value { font-size: 26px; font-weight: 700; color: #fbbf24; }
QLabel#kpi_label { color: #8ea0bf; font-size: 12px; }
QLabel#PageTitle { font-size: 22px; font-weight: 700; color: #22d3ee; }
QLabel#SectionTitle { font-size: 15px; font-weight: 600; color: #a78bfa; }
QProgressBar {
    background: #0f1830;
    border: 1px solid #233454;
    border-radius: 8px;
    height: 18px;
    text-align: center;
    color: #e2e8f0;
}
QProgressBar::chunk {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #22d3ee, stop:1 #a78bfa);
    border-radius: 8px;
}
QSplitter::handle { background: #233454; width: 2px; }
QToolTip {
    background: #111a2c;
    color: #e2e8f0;
    border: 1px solid #22d3ee;
    padding: 6px;
}
"""


def severity_color(sev: str) -> QColor:
    return QColor(SEVERITY_COLORS.get(sev, "#94a3b8"))


def cat_color(cat: str) -> QColor:
    return QColor(CAT_COLORS.get(cat, "#64748b"))