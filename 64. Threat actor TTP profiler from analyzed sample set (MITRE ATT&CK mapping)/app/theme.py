"""TTPProfiler :: 'Neon Sentinel' design system (QSS stylesheet)."""
from __future__ import annotations

PALETTE = {
    "abyss": "#0B0F19",
    "panel": "#111827",
    "elevation": "#1B2436",
    "cyan": "#00E5FF",
    "magenta": "#FF2E97",
    "lime": "#A6FF00",
    "amber": "#FFB800",
    "crimson": "#FF4D4D",
    "violet": "#7C4DFF",
    "ghost": "#E8F0FE",
    "muted": "#8FA3C9",
    "line": "#1E2A3F",
}

QSS = """
* {
    font-family: "Inter", "Segoe UI Variable", "Segoe UI", sans-serif;
    font-size: 13px;
    color: #E8F0FE;
}
QMainWindow, QWidget#root { background-color: #0B0F19; }
QWidget#panel { background-color: #111827; border: 1px solid #1E2A3F; border-radius: 14px; }
QWidget#elev { background-color: #1B2436; border-radius: 12px; }

#appTitle { font-size: 22px; font-weight: 800; color: #00E5FF; letter-spacing: .5px; }
#appSub { font-size: 12px; color: #8FA3C9; }
QFrame#sidebar { background-color: #0D1220; border-right: 1px solid #1E2A3F; }
QPushButton#navBtn {
    text-align: left; padding: 12px 18px; border: none; border-radius: 10px;
    color: #8FA3C9; font-size: 14px; background: transparent;
}
QPushButton#navBtn:hover { background-color: rgba(0,229,255,.08); color: #E8F0FE; }
QPushButton#navBtn:checked { background-color: rgba(0,229,255,.16); color: #00E5FF; }

QPushButton#primary {
    background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #00E5FF, stop:1 #7C4DFF);
    color: #08121f; font-weight: 700; border: none; border-radius: 10px; padding: 10px 20px;
}
QPushButton#primary:hover { color: #000; }
QPushButton#danger { background-color: rgba(255,77,77,.18); color: #FF4D4D;
    border: 1px solid #FF4D4D; border-radius: 10px; padding: 10px 20px; font-weight: 600; }
QPushButton#ghost { background: #1B2436; color: #E8F0FE; border: 1px solid #26334B;
    border-radius: 10px; padding: 10px 20px; }
QPushButton#ghost:hover { background: #212E47; }

QLabel#metricTitle { color: #8FA3C9; font-size: 12px; letter-spacing: 1px; text-transform: uppercase; }
QLabel#metricValue { font-family: "JetBrains Mono", "Consolas", monospace; font-size: 26px; font-weight: 800; color: #00E5FF; }
QLabel#sectionTitle { font-size: 16px; font-weight: 700; color: #E8F0FE; }
QLabel#hint { color: #5B6B8C; font-size: 12px; }
QLabel#lime { color: #A6FF00; }
QLabel#amber { color: #FFB800; }
QLabel#magenta { color: #FF2E97; }

QTableWidget { background: #0F1725; alternate-background-color: #131C2E;
    border: 1px solid #1E2A3F; border-radius: 10px; gridline-color: #1E2A3F; }
QHeaderView::section { background: #131C2E; color: #00E5FF; border: none; padding: 8px; font-weight: 700; }
QTableWidget::item { padding: 6px; border-bottom: 1px solid #182338; }

QListWidget { background: #0F1725; border: 1px solid #1E2A3F; border-radius: 10px; outline: none; }
QListWidget::item { padding: 8px 12px; border-bottom: 1px solid #182338; }
QListWidget::item:selected { background: rgba(0,229,255,.15); color: #00E5FF; }

QComboBox, QLineEdit, QTextEdit, QSpinBox {
    background: #0F1725; border: 1px solid #26334B; border-radius: 10px; padding: 8px 10px; color: #E8F0FE;
}
QComboBox:focus, QLineEdit:focus, QTextEdit:focus { border: 1px solid #00E5FF; }
QComboBox::drop-down { border: none; }
QComboBox QAbstractItemView { background: #111827; border: 1px solid #1E2A3F; selection-background-color: rgba(0,229,255,.2); }

QProgressBar { background: #0F1725; border: none; border-radius: 6px; height: 10px; text-align: center; }
QProgressBar::chunk { background: qlineargradient(x1:0,y1:0,x2:1,y2:0, stop:0 #00E5FF, stop:1 #7C4DFF); border-radius: 6px; }

QTabWidget::pane { border: 1px solid #1E2A3F; border-radius: 10px; top: -1px; }
QTabBar::tab { background: #0F1725; color: #8FA3C9; padding: 9px 18px; border-top-left-radius: 8px; border-top-right-radius: 8px; margin-right: 2px; }
QTabBar::tab:selected { background: #1B2436; color: #00E5FF; border-top: 2px solid #00E5FF; }

QScrollBar:vertical, QScrollBar:horizontal { background: #0D1220; width: 10px; height: 10px; }
QScrollBar::handle { background: #2A3854; border-radius: 5px; }
QScrollBar::handle:hover { background: #00E5FF; }
QScrollBar::add-line, QScrollBar::sub-line { height: 0; width: 0; }

QToolTip { background-color: #111827; color: #E8F0FE; border: 1px solid #00E5FF; border-radius: 6px; padding: 6px; }
QMenu { background: #111827; border: 1px solid #1E2A3F; border-radius: 10px; }
QMenu::item { padding: 8px 22px; border-radius: 6px; }
QMenu::item:selected { background: rgba(0,229,255,.15); }

QSplitter::handle { background: #1E2A3F; }
QStatusBar { background: #0D1220; color: #8FA3C9; border-top: 1px solid #1E2A3F; }
QStatusBar QLabel { color: #8FA3C9; }
QSplitter:hover { color: #1E2A3F; }

QFrame#heatmapCard { background: #111827; border: 1px solid #1E2A3F; border-radius: 14px; }
"""


def style_text(html_txt: str) -> str:
    return f'<span style="color:{PALETTE["ghost"]}">{html_txt}</span>'