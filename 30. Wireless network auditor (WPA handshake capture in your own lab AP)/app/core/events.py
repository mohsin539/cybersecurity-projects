"""Minimal pub/sub event bus used to stream capture events to the GUI."""
import threading
import queue


class EventBus:
    def __init__(self):
        self._q: queue.Queue = queue.Queue()
        self._subs: list = []
        self._lock = threading.Lock()

    def emit(self, *args) -> None:
        event = tuple(args)
        self._q.put(event)
        with self._lock:
            for fn in list(self._subs):
                try:
                    fn(*event)
                except Exception:
                    pass

    def subscribe(self, fn) -> None:
        with self._lock:
            self._subs.append(fn)

    def drain(self) -> list:
        out = []
        while True:
            try:
                out.append(self._q.get_nowait())
            except queue.Empty:
                return out


BUS = EventBus()