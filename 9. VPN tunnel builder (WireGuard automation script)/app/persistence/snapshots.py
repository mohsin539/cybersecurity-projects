"""Snapshot / rollback (NIST CP-9, AU-9; ISO 27001 A.8.11).

A snapshot captures state.json + secrets.json so a tunnel can be fully
restored, including key material. Retention is bounded by settings.
"""

from __future__ import annotations

import hashlib
import json
import shutil
from datetime import datetime, timezone
from pathlib import Path

from ..core.models import Snapshot
from .store import StateStore, StoreError, _atomic_write, _read_json


def _sha256_file(path: Path) -> str:
    if not path.exists():
        return "0" * 64
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(64 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


class SnapshotManager:
    INDEX_FILE = "index.json"

    def __init__(self, store: StateStore):
        self.store = store
        self.dir = store.snapshot_dir
        self.index_path = self.dir / self.INDEX_FILE

    def _load_index(self) -> dict:
        return _read_json(self.index_path, {"items": []})

    def _save_index(self, index: dict) -> None:
        _atomic_write(self.index_path, json.dumps(index, indent=2, sort_keys=True))

    def create(self, note: str = "") -> Snapshot:
        ts = datetime.now(timezone.utc).isoformat(timespec="seconds").replace(":", "-")
        snapshot_dir = self.dir / f"snapshot_{ts}.d"
        snapshot_dir.mkdir(parents=True, exist_ok=True)

        state_copy = self.store.root / "state.json"
        secrets_copy = self.store.root / "secrets.json"

        for src in (state_copy, secrets_copy):
            if src.exists():
                shutil.copy2(src, snapshot_dir / src.name)

        merged = {"ts": ts, "state": str(snapshot_dir / "state.json"), "secrets": str(snapshot_dir / "secrets.json")}
        blob = json.dumps(merged, sort_keys=True).encode("utf-8")
        size = sum(p.stat().st_size for p in snapshot_dir.iterdir() if p.is_file())
        snap = Snapshot(
            id=hashlib.sha256(blob).hexdigest()[:16],
            ts=ts,
            path=str(snapshot_dir),
            sha256=_sha256_file(snapshot_dir / "state.json") + _sha256_file(snapshot_dir / "secrets.json"),
            size=size,
        )
        (snapshot_dir / "meta.json").write_text(
            json.dumps({"id": snap.id, "ts": snap.ts, "note": note}, indent=2),
            encoding="utf-8",
        )

        index = self._load_index()
        index["items"] = [i for i in index.get("items", []) if i.get("id") != snap.id]
        index["items"].append({
            "id": snap.id, "ts": snap.ts, "path": snap.path,
            "sha256": snap.sha256, "note": note,
        })
        self._save_index(index)
        self._prune()
        return snap

    def list(self) -> list[dict]:
        items = self._load_index().get("items", [])
        return sorted(items, key=lambda i: i.get("ts", ""), reverse=True)

    def get(self, snap_id: str) -> dict:
        for item in self.list():
            if item["id"] == snap_id:
                return item
        raise StoreError(f"snapshot not found: {snap_id}")

    def restore(self, snap_id: str) -> Snapshot:
        item = self.get(snap_id)
        src = Path(item["path"])
        if not (src / "state.json").exists():
            raise StoreError(f"snapshot {snap_id} is incomplete")
        if (src / "state.json").exists():
            shutil.copy2(src / "state.json", self.store.state_path)
            if (src / "secrets.json").exists():
                shutil.copy2(src / "secrets.json", self.store.secrets_path)
            elif self.store.secrets_path.exists():
                self.store.secrets_path.unlink()
        for path in (self.store.state_path, self.store.secrets_path):
            try:
                import os
                if os.name == "posix":
                    os.chmod(path, 0o600)
            except OSError:
                pass
        return Snapshot(id=item["id"], ts=item["ts"], path=str(src),
                        sha256=item.get("sha256", ""), size=0)

    def _prune(self) -> None:
        retention = 10  # overridden by caller via prune(retention)
        _retention = getattr(self, "_retention", retention)
        items = self.list()
        if len(items) <= _retention:
            return
        for item in items[_retention:]:
            shutil.rmtree(Path(item["path"]), ignore_errors=True)
            self._prune_index_id(item["id"])

    def _prune_index_id(self, snap_id: str) -> None:
        index = self._load_index()
        index["items"] = [i for i in index.get("items", []) if i.get("id") != snap_id]
        self._save_index(index)

    def set_retention(self, count: int) -> None:
        self._retention = max(1, int(count))
        self._prune()