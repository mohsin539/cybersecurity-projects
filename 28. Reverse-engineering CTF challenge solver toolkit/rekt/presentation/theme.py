"""Dark theme QSS (NFR-7: WCAG 2.1 AA contrast targets: #e8e8e8 on #16181d ≈ 12.9:1)."""

QSS = """
QWidget { background-color: #16181d; color: #e8e8e8; font-size: 13px; }
QMainWindow::separator { background: #2a2e38; width: 3px; }
QMenuBar { background: #1b1e25; }
QMenuBar::item:selected { background: #2f3542; }
QMenu { background: #1f232c; border: 1px solid #2f3542; }
QMenu::item:selected { background: #2f3542; }
QToolBar { background: #1b1e25; border-bottom: 1px solid #2a2e38; spacing: 6px; }
QToolButton { padding: 5px 10px; border-radius: 4px; }
QToolButton:hover { background: #2f3542; }
QTabWidget::pane { border: 1px solid #2a2e38; }
QTabBar::tab { background: #1b1e25; padding: 7px 16px; border: 1px solid #2a2e38; }
QTabBar::tab:selected { background: #2f3542; color: #ffffff; }
QTreeView, QListView, QTableView, QPlainTextEdit, QTextEdit, QLineEdit, QComboBox {
    background: #101218; border: 1px solid #2a2e38; border-radius: 4px;
    selection-background-color: #31405c;
}
QHeaderView::section { background: #1b1e25; border: none; padding: 5px; }
QPushButton {
    background: #2f3542; border: 1px solid #3a4152; border-radius: 4px;
    padding: 6px 14px; color: #ffffff;
}
QPushButton:hover { background: #3a4152; }
QPushButton:disabled { color: #7a7f8a; }
QPushButton#primary { background: #2456a8; border-color: #2f6ecf; }
QLabel#banner { background: #4a3b12; color: #ffd479; padding: 8px;
    border: 1px solid #6b5618; border-radius: 4px; }
QLabel#statusOk { color: #7dd487; }
QLabel#statusBad { color: #ef7b7b; }
QStatusBar { background: #1b1e25; }
QSplitter::handle { background: #2a2e38; }
"""
