"""In-memory beacon registry, task queue and results store.

Thread-safe, simple, and volatile by design (educational skeleton).
A production build would swap these for a database (ISO A.18 / A.8 DRP).
"""
import threading
from collections import defaultdict
from typing import Optional

from .util import new_id, now_iso


class BeaconRegistry:
    def __init__(self):
        self._lock = threading.RLock()
        self._beacons: dict[str, dict] = {}
        self._tasks: dict[str, list[dict]] = defaultdict(list)
        self._results: list[dict] = []

    # ---- beacons --------------------------------------------------------
    def register(self, beacon_id: str, meta: dict, ip: str) -> dict:
        with self._lock:
            entry = self._beacons.get(beacon_id, {})
            entry.update({"beacon_id": beacon_id, "ip": ip, "meta": meta})
            entry["first_seen"] = entry.get("first_seen", now_iso())
            entry["last_seen"] = now_iso()
            entry["online"] = True
            self._beacons[beacon_id] = entry
            return dict(entry)

    def snapshot(self) -> list[dict]:
        with self._lock:
            return [dict(b) for b in self._beacons.values()]

    def get(self, beacon_id: str) -> Optional[dict]:
        with self._lock:
            b = self._beacons.get(beacon_id)
            return dict(b) if b else None

    # ---- tasks ----------------------------------------------------------
    def enqueue(self, beacon_id: str, task: dict) -> dict:
        with self._lock:
            task.setdefault("task_id", new_id("task"))
            task.setdefault("status", "pending")
            task.setdefault("queued_at", now_iso())
            self._tasks[beacon_id].append(task)
            return dict(task)

    def dequeue_pending(self, beacon_id: str) -> list[dict]:
        with self._lock:
            queue = self._tasks.get(beacon_id, [])
            pending = [t for t in queue if t.get("status") == "pending"]
            for t in pending:
                t["status"] = "dispatched"
                t.setdefault("dispatched_at", now_iso())
            return [dict(t) for t in pending]

    def mark_complete(self, beacon_id: str, task_id: str, ok: bool, output: dict) -> bool:
        with self._lock:
            queue = self._tasks.get(beacon_id, [])
            for t in queue:
                if t.get("task_id") == task_id:
                    t["status"] = "ok" if ok else "failed"
                    t["completed_at"] = now_iso()
                    t["output"] = output
                    self._results.append(dict(t))
                    return True
        return False

    # ---- results / history ----------------------------------------------
    def all_tasks(self) -> list[dict]:
        with self._lock:
            out = []
            for queue in self._tasks.values():
                out.extend(dict(t) for t in queue)
            return out

    def results(self) -> list[dict]:
        with self._lock:
            return [dict(r) for r in self._results]

    def counts(self) -> dict:
        with self._lock:
            return {
                "beacons": len(self._beacons),
                "tasks": sum(len(q) for q in self._tasks.values()),
                "results": len(self._results),
            }