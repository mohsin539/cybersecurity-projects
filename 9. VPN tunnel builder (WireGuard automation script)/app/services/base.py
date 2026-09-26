"""A shared runtime context handed to every use case.

Keeps cross-cutting wiring (store, audit, snapshots, backend, settings) in one
place so the web layer never touches persistence/platform directly.
"""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..persistence.audit import AuditLog
from ..persistence.snapshots import SnapshotManager
from ..persistence.store import StateStore
from ..platform.backend import BaseBackend


@dataclass
class ServiceContext:
    store: StateStore
    audit: AuditLog
    snapshots: SnapshotManager
    backend: BaseBackend
    data_dir: Path

    @staticmethod
    def from_parts(
        store: StateStore,
        audit: AuditLog,
        snapshots: SnapshotManager,
        backend: BaseBackend,
    ) -> ServiceContext:
        return ServiceContext(
            store=store,
            audit=audit,
            snapshots=snapshots,
            backend=backend,
            data_dir=store.root,
        )