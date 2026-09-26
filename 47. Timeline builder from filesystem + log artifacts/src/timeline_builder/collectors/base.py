from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Callable

from ..models import CollectionResult

ProgressFn = Callable[[int, int | None], None]
CancelFn = Callable[[], bool]


@dataclass
class CollectorContext:
    progress: ProgressFn | None = None
    cancel: CancelFn | None = None
    audit: object | None = None
    extra: dict = field(default_factory=dict)

    def report(self, current: int, total: int | None = None) -> None:
        if self.progress is not None:
            self.progress(current, total)

    def cancelled(self) -> bool:
        return bool(self.cancel and self.cancel())


class BaseCollector(ABC):
    name = "base"
    source_type = None

    def __init__(self, root, audit=None):
        self.root = root
        self.audit = audit

    @abstractmethod
    def collect(self, context: CollectorContext | None = None) -> CollectionResult:
        raise NotImplementedError

    def _audit(self, action: str, target: str = "", **detail) -> None:
        if self.audit is not None:
            self.audit.log(action, target=target, **detail)
