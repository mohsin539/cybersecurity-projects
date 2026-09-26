from __future__ import annotations

from PySide6.QtCore import QAbstractTableModel, QModelIndex, Qt
from PySide6.QtGui import QBrush, QColor, QFont

from ..models import TimelineEvent
from .theme import SEVERITY_COLORS

HEADERS = ["Timestamp (UTC)", "Kind", "Severity", "Source", "Host", "User", "Path / Artifact", "Description"]


class TimelineTableModel(QAbstractTableModel):
    def __init__(self, events: list[TimelineEvent] | None = None, parent=None):
        super().__init__(parent)
        self._events: list[TimelineEvent] = list(events or [])
        self._bold = QFont()
        self._bold.setBold(True)

    def set_events(self, events: list[TimelineEvent]) -> None:
        self.beginResetModel()
        self._events = list(events)
        self.endResetModel()

    def event_at(self, row: int) -> TimelineEvent | None:
        if 0 <= row < len(self._events):
            return self._events[row]
        return None

    def events(self) -> list[TimelineEvent]:
        return self._events

    def rowCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(self._events)

    def columnCount(self, parent=QModelIndex()) -> int:
        return 0 if parent.isValid() else len(HEADERS)

    def headerData(self, section, orientation, role=Qt.DisplayRole):
        if role == Qt.DisplayRole and orientation == Qt.Horizontal:
            return HEADERS[section]
        return None

    def data(self, index: QModelIndex, role=Qt.DisplayRole):
        if not index.isValid():
            return None
        event = self._events[index.row()]
        column = index.column()

        if role in (Qt.DisplayRole, Qt.ToolTipRole):
            values = [
                event.normalized_timestamp().strftime("%Y-%m-%d %H:%M:%S"),
                event.time_kind.value,
                event.severity.value.upper(),
                event.source_type.value,
                event.host or "-",
                event.user or "-",
                event.source_path,
                event.description,
            ]
            value = values[column]
            if role == Qt.ToolTipRole:
                detail = f"{value}\nSHA256: {event.sha256 or 'n/a'}\nID: {event.event_id}"
                return detail
            return value

        if role == Qt.ForegroundRole and column == 2:
            return QBrush(QColor(SEVERITY_COLORS.get(event.severity.value, "#60a5fa")))
        if role == Qt.FontRole and column == 2:
            return self._bold
        if role == Qt.UserRole:
            return event
        return None

    def sort(self, column: int, order=Qt.AscendingOrder) -> None:
        reverse = order == Qt.DescendingOrder
        keys = {
            0: lambda e: e.normalized_timestamp(),
            1: lambda e: e.time_kind.value,
            2: lambda e: list(SEVERITY_COLORS).index(e.severity.value) if e.severity.value in SEVERITY_COLORS else 9,
            3: lambda e: e.source_type.value,
            4: lambda e: e.host.lower(),
            5: lambda e: e.user.lower(),
            6: lambda e: e.source_path.lower(),
            7: lambda e: e.description.lower(),
        }
        key = keys.get(column)
        if key is None:
            return
        self.layoutAboutToBeChanged.emit()
        self._events.sort(key=key, reverse=reverse)
        self.layoutChanged.emit()
