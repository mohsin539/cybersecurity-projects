from __future__ import annotations

import threading
import traceback

from PySide6.QtCore import QObject, Signal

from ..collectors import FilesystemCollector, LogCollector
from ..config import ScanOptions
from ..correlation import Correlator
from ..normalizer import TimelineNormalizer
from ..storage import CaseStore


class ScanWorker(QObject):
    progress = Signal(int, int, str)
    message = Signal(str)
    finished = Signal(dict)
    failed = Signal(str)

    def __init__(self, sources, options: ScanOptions, store: CaseStore, correlator: Correlator | None = None):
        super().__init__()
        self.sources = list(sources)
        self.options = options
        self.store = store
        self.correlator = correlator
        self._cancel = threading.Event()

    def cancel(self) -> None:
        self._cancel.set()

    def _cancelled(self) -> bool:
        return self._cancel.is_set()

    def run(self) -> None:
        try:
            all_events = []
            errors: list[str] = []
            total = max(1, len(self.sources))
            for index, source in enumerate(self.sources, start=1):
                if self._cancelled():
                    break
                path = source["path"]
                kind = source.get("kind") or "auto"
                self.message.emit(f"Collecting {path}")
                audit = getattr(self.store, "audit", None)

                if kind == "filesystem":
                    collector = FilesystemCollector(path, options=self.options, audit=audit)
                elif kind == "log":
                    collector = LogCollector(path, options=self.options, format_hint=source.get("format"), audit=audit)
                else:
                    collector = LogCollector(path, options=self.options, format_hint=source.get("format"), audit=audit)

                def make_progress(base=index - 1):
                    def report(current, source_total):
                        if source_total:
                            fraction = (base + min(current / source_total, 1.0)) / total
                            self.progress.emit(int(fraction * 100), 100, f"{path}")
                        else:
                            self.progress.emit(-1, -1, f"{path} ({current})")

                    return report

                from ..collectors.base import CollectorContext

                ctx = CollectorContext(progress=make_progress(), cancel=self._cancelled, audit=audit)
                result = collector.collect(ctx)
                all_events.extend(result.events)
                errors.extend(result.errors)
                try:
                    self.store.add_source(str(path), collector.name, len(result.events))
                except Exception as exc:
                    errors.append(f"store.add_source({path}): {exc}")

            self.progress.emit(0, 0, "Normalizing")
            normalizer = TimelineNormalizer(self.options)
            normalized = normalizer.normalize(all_events)
            self.progress.emit(0, 0, "Persisting to case store")
            self.store.add_events(normalized)

            summary = normalizer.summarize(normalized)
            summary["errors"] = errors[:200]
            summary["error_count"] = len(errors)
            if self.correlator is not None:
                groups = self.correlator.correlate(normalized)
                summary["correlation_groups"] = len(groups)
            self.progress.emit(100, 100, "Done")
            self.finished.emit(summary)
        except Exception:
            self.failed.emit(traceback.format_exc())
