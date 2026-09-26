"""RecovPro Secure — colorful modern theme (dark + light).

A single source of truth for palette + QSS. All colors derive from
a brand system (ISO/NIST-brandable, high-contrast for accessibility).
"""

from __future__ import annotations

PALETTE = {
    "bg": "#0d1424",
    "bg_alt": "#131c30",
    "panel": "#16202f",
    "panel_2": "#1b2740",
    "border": "#26334d",
    "text": "#e8eefb",
    "text_dim": "#93a4c4",
    "brand": "#7c3aed",        # violet
    "cyan": "#22d3ee",
    "green": "#34d399",
    "amber": "#fbbf24",
    "red": "#f87171",
    "purple": "#a78bfa",
    "grad": "QLinearGradient(x1:0, y1:0, x2:1, y2:1)"
}


def _grad(colors: tuple) -> str:
    stops = "".join(f"stop:{i} {c}" for i, c in enumerate(colors))
    return f"qlineargradient(x1:0,y1:0,x2:1,y2:1,{stops})"


BRAND_GRADIENT = _grad(("#7c3aed", "#4f46e5", "#0ea5e9", "#10b981"))


def qss() -> str:
    P = PALETTE
    return f"""
* {{
    font-family: 'Segoe UI Variable', 'Segoe UI', sans-serif;
    font-size: 13px;
    color: {P['text']};
}}
QMainWindow, QDialog {{ background: {P['bg']}; }}
QWidget#Sidebar {{
    background: qlineargradient(x1:0,y1:0,x2:0,y2:1,
        stop:0 #12092a, stop:0.55 #171233, stop:1 {P['bg']});
    border-right: 1px solid #2b1e52;
}}
QLabel#BrandTitle {{ color: #fff; font-size: 17px; font-weight: 700; letter-spacing: .3px; }}
QLabel#BrandSub {{ color: #9aa3c7; font-size: 10.5px; letter-spacing: 1.4px; }}
QLabel#PageTitle {{ color: #fff; font-size: 19px; font-weight: 700; }}
QLabel#PageSub {{ color: {P['text_dim']}; font-size: 12px; }}
QLabel#StatValue {{ color: #fff; font-size: 22px; font-weight: 700; }}
QLabel#StatLabel {{ color: {P['text_dim']}; font-size: 10.5px; letter-spacing: 1px; }}

QFrame#Card {{
    background: {P['panel']};
    border: 1px solid {P['border']};
    border-radius: 14px;
}}
QFrame#CardHover:hover {{
    border: 1px solid #39496e;
    background: {P['panel_2']};
}}
QPushButton {{
    background: {P['panel_2']};
    border: 1px solid {P['border']};
    border-radius: 9px;
    padding: 8px 14px;
    color: {P['text']};
}}
QPushButton:hover {{ border-color: {P['brand']}; background: #22304a; }}
QPushButton:pressed {{ background: #2a3a58; }}
QPushButton:disabled {{ color: #5c6b8a; border-color: #1f2a42; }}
QPushButton[primary="true"] {{
    background: {_grad(("#7c3aed", "#2563eb"))};
    border: none;
    color: #fff;
    font-weight: 600;
    padding: 10px 18px;
}}
QPushButton[primary="true"]:hover {{ background: {_grad(("#8b5cf6", "#3b82f6"))}; }}
QPushButton[primary="true"]:disabled {{ background: #33415e; color: #7c8aab; }}
QPushButton[danger="true"] {{ background: #7f1d1d; border: 1px solid #b91c1c; color:#fecaca; }}
QPushButton[ghost="true"] {{ background: transparent; border: 1px solid {P['border']}; }}

QToolButton#NavBtn {{
    text-align: left; border: none; border-radius: 10px;
    padding: 10px 14px; color: #c7cfe2; font-size: 13px;
}}
QToolButton#NavBtn:hover {{ background: #221b3d; color: #fff; }}
QToolButton#NavBtn:checked {{
    background: {_grad(("#7c3aed", "#4f46e5"))};
    color: #fff; font-weight: 600;
}}

QLineEdit, QTextEdit {{
    background: {P['bg_alt']}; border: 1px solid {P['border']};
    border-radius: 9px; padding: 8px 10px; color: {P['text']};
    selection-background-color: {P['brand']};
}}
QLineEdit:focus, QTextEdit:focus {{ border: 1px solid {P['cyan']}; }}
QComboBox {{
    background: {P['bg_alt']}; border: 1px solid {P['border']};
    border-radius: 9px; padding: 8px 10px; color: {P['text']};
}}
QComboBox::drop-down {{ border: none; width: 26px; }}
QComboBox QAbstractItemView {{
    background: #1a2440; border: 1px solid {P['border']};
    selection-background-color: {P['brand']}; outline: none;
}}
QCheckBox {{ spacing: 8px; color: {P['text']}; }}
QCheckBox::indicator {{
    width: 16px; height: 16px; border-radius: 5px;
    border: 1px solid #3b4a70; background: {P['bg_alt']};
}}
QCheckBox::indicator:checked {{
    background: {_grad(("#7c3aed", "#2563eb"))}; border: none;
}}

QProgressBar {{
    background: #101a2e; border: none; border-radius: 7px;
    height: 14px; text-align: center; color: #fff; font-size: 10.5px;
}}
QProgressBar::chunk {{
    border-radius: 7px;
    background: {_grad(("#22d3ee", "#7c3aed", "#34d399"))};
}}

QHeaderView::section {{
    background: #141d33; color: #9fb0d4; padding: 8px;
    border: none; border-bottom: 1px solid {P['border']}; font-weight: 600;
}}
QTableView {{
    background: {P['panel']}; alternate-background-color: #15203a;
    border: 1px solid {P['border']}; border-radius: 12px;
    gridline-color: #1c2740; selection-background-color: #3b4f7a;
}}
QTableView::item {{ padding: 5px 6px; }}
QTableView::item:selected {{ background: #3b4f7a; color: #fff; }}

QTabWidget::pane {{ border: 1px solid {P['border']}; border-radius: 12px; background: {P['panel']}; }}
QTabBar::tab {{
    background: transparent; padding: 8px 16px; color: {P['text_dim']};
    border-bottom: 2px solid transparent; font-weight: 600;
}}
QTabBar::tab:selected {{ color: {P['cyan']}; border-bottom: 2px solid {P['cyan']}; }}
QScrollBar:vertical {{ background: #0f1830; width: 10px; }}
QScrollBar::handle:vertical {{ background: #2b3a63; border-radius: 5px; min-height: 30px; }}
QScrollBar::add-line, QScrollBar::sub-line {{ height: 0; }}

QToolTip {{
    background: #1c2740; color: {P['text']}; border: 1px solid {P['border']};
    padding: 6px 8px; border-radius: 6px;
}}
QPushButton[badge="true"] {{ border-radius: 17px; padding: 3px 10px; font-size: 11px; }}
QPushButton[badge="true"][tone="green"]   {{ background:#065f46; color:#d1fae5; border:none; }}
QPushButton[badge="true"][tone="amber"]   {{ background:#78350f; color:#fde68a; border:none; }}
QPushButton[badge="true"][tone="red"]     {{ background:#7f1d1d; color:#fecaca; border:none; }}
QPushButton[badge="true"][tone="blue"]    {{ background:#1e3a8a; color:#dbeafe; border:none; }}
QPushButton[badge="true"][tone="violet"]  {{ background:#4c1d95; color:#ede9fe; border:none; }}
QPushButton[badge="true"][tone="gray"]    {{ background:#334155; color:#e2e8f0; border:none; }}
"""


def light_qss() -> str:
    """Optional light variant (kept small on purpose)."""
    P = PALETTE
    return f"""
* {{ font-family:'Segoe UI Variable','Segoe UI',sans-serif; font-size:13px; color:#1e293b; }}
QMainWindow {{ background:#eef2f9; }}
QFrame#Card {{ background:#ffffff; border:1px solid #e2e8f0; border-radius:14px; }}
QPushButton {{ background:#f1f5f9; border:1px solid #cbd5e1; border-radius:9px; padding:8px 14px; }}
QPushButton[primary="true"] {{ background:{_grad(("#7c3aed","#2563eb"))}; color:#fff; border:none; font-weight:600; }}
QHeaderView::section {{ background:#f8fafc; color:#334155; padding:8px; border:none; border-bottom:1px solid #e2e8f0; }}
QTableView {{ background:#fff; alternate-background-color:#f8fafc; border:1px solid #e2e8f0; border-radius:12px; }}
QLineEdit {{ background:#fff; border:1px solid #cbd5e1; border-radius:9px; padding:8px; }}
QProgressBar {{ background:#e2e8f0; border:none; border-radius:7px; height:14px; }}
QProgressBar::chunk {{ border-radius:7px; background:{_grad(("#22d3ee","#7c3aed","#34d399"))}; }}
"""