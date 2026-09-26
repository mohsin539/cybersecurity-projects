from __future__ import annotations

__all__ = ["apply_theme", "TimelineTableModel", "ScanWorker", "MainWindow"]


def __getattr__(name):
    if name == "apply_theme":
        from .theme import apply_theme

        return apply_theme
    if name == "TimelineTableModel":
        from .models import TimelineTableModel

        return TimelineTableModel
    if name == "ScanWorker":
        from .worker import ScanWorker

        return ScanWorker
    if name == "MainWindow":
        from .main_window import MainWindow

        return MainWindow
    raise AttributeError(name)
