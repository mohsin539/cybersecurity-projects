"""SQLite implementation of ``SnapshotStore``.

Swaps the in-memory ring buffer for a durable store so charts survive
restarts (the ``SnapshotStore`` port makes this invisible to the rest of the
stack). Rows are keyed by timestamp; per-interface rates ride along as a JSON
column. Capacity is enforced with a periodic prune keeping the newest
``capacity`` rows.

If the database cannot be opened (read-only filesystem, corrupt file, …) the
adapter degrades to an internal in-memory ring buffer so monitoring keeps
working; the failure is logged once.
"""
from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections import deque
from typing import List, Optional

from domain.entities import InterfaceTraffic, RateSample, Snapshot
from domain.interfaces import SnapshotStore
from infrastructure.storage.ring_buffer import RingBufferSnapshotStore

logger = logging.getLogger(__name__)

_SCHEMA = """
CREATE TABLE IF NOT EXISTS snapshots (
    ts          REAL PRIMARY KEY,
    total_dl    REAL NOT NULL,
    total_ul    REAL NOT NULL,
    rx_bytes    INTEGER NOT NULL,
    tx_bytes    INTEGER NOT NULL,
    rx_packets  INTEGER NOT NULL,
    tx_packets  INTEGER NOT NULL,
    err_in      INTEGER NOT NULL,
    err_out     INTEGER NOT NULL,
    drop_in     INTEGER NOT NULL,
    drop_out    INTEGER NOT NULL,
    interfaces  TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_snapshots_ts ON snapshots(ts);
"""

# Default prune margin: DELETE runs only when the row count exceeds
# capacity by this many rows, amortising the cost instead of paying it on
# every push. Configurable so tests can pin the exact capacity contract.
_DEFAULT_PRUNE_MARGIN = 64


class SqliteSnapshotStore(SnapshotStore):
    """Durable snapshot store; falls back to memory when SQLite fails."""

    def __init__(
        self,
        path: str = "bwmon_history.db",
        capacity: int = 3600,
        prune_margin: int = _DEFAULT_PRUNE_MARGIN,
    ) -> None:
        self._capacity = max(1, int(capacity))
        self._prune_margin = max(0, int(prune_margin))
        # RLock: push() -> _maybe_prune_locked() -> count() re-enters the lock.
        self._lock = threading.RLock()
        self._fallback: Optional[RingBufferSnapshotStore] = None
        self._pushes_since_count = 0

        try:
            # check_same_thread=False: pushes arrive on the telemetry thread,
            # reads on HTTP worker threads; all access is serialised above.
            self._conn = sqlite3.connect(
                path, check_same_thread=False, isolation_level=None
            )
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA synchronous=NORMAL")
            self._conn.executescript(_SCHEMA)
            logger.info("SQLite history store opened at %s (capacity=%d)", path, self._capacity)
        except sqlite3.Error as exc:
            logger.error(
                "SQLite store unavailable (%s); falling back to in-memory history", exc
            )
            self._fallback = RingBufferSnapshotStore(capacity=self._capacity)
            self._conn = None

    # ------------------------------------------------------------------ #
    # SnapshotStore port
    # ------------------------------------------------------------------ #
    def push(self, snapshot: Snapshot) -> None:
        if self._fallback is not None:
            self._fallback.push(snapshot)
            return
        try:
            with self._lock:
                self._conn.execute(
                    "INSERT OR REPLACE INTO snapshots VALUES (?,?,?,?,?,?,?,?,?,?,?,?)",
                    (
                        snapshot.timestamp,
                        snapshot.total_download,
                        snapshot.total_upload,
                        snapshot.total_counters.bytes_recv,
                        snapshot.total_counters.bytes_sent,
                        snapshot.total_counters.packets_recv,
                        snapshot.total_counters.packets_sent,
                        snapshot.total_counters.errors_in,
                        snapshot.total_counters.errors_out,
                        snapshot.total_counters.drops_in,
                        snapshot.total_counters.drops_out,
                        json.dumps(self._interfaces_json(snapshot)),
                    ),
                )
                self._maybe_prune_locked()
        except sqlite3.Error as exc:
            logger.error("Snapshot write failed (%s); degrading to memory", exc)
            self._degrade_to_memory(snapshot)

    def latest(self) -> Optional[Snapshot]:
        if self._fallback is not None:
            return self._fallback.latest()
        try:
            with self._lock:
                row = self._conn.execute(
                    "SELECT * FROM snapshots ORDER BY ts DESC LIMIT 1"
                ).fetchone()
        except sqlite3.Error:
            return None
        return self._row_to_snapshot(row) if row else None

    def window(self, seconds: float) -> List[Snapshot]:
        if self._fallback is not None:
            return self._fallback.window(seconds)
        seconds = max(0.0, float(seconds))
        try:
            with self._lock:
                anchor = self._conn.execute(
                    "SELECT MAX(ts) FROM snapshots"
                ).fetchone()[0]
                if anchor is None:
                    return []
                rows = self._conn.execute(
                    "SELECT * FROM snapshots WHERE ts >= ? ORDER BY ts ASC",
                    (anchor - seconds,),
                ).fetchall()
        except sqlite3.Error:
            return []
        return [self._row_to_snapshot(row) for row in rows]

    # ------------------------------------------------------------------ #
    # Maintenance
    # ------------------------------------------------------------------ #
    def count(self) -> int:
        """Number of retained rows (0 when degraded to memory)."""
        if self._fallback is not None:
            return self._fallback.size
        try:
            with self._lock:
                return int(self._conn.execute("SELECT COUNT(*) FROM snapshots").fetchone()[0])
        except sqlite3.Error:
            return 0

    def close(self) -> None:
        if self._conn is not None:
            try:
                self._conn.close()
            except sqlite3.Error:
                pass

    def _maybe_prune_locked(self) -> None:
        self._pushes_since_count += 1
        if self._pushes_since_count < 32:
            return
        self._pushes_since_count = 0
        excess = self.count() - self._capacity
        if excess > self._prune_margin:
            self._conn.execute(
                "DELETE FROM snapshots WHERE ts IN "
                "(SELECT ts FROM snapshots ORDER BY ts ASC LIMIT ?)",
                (excess,),
            )

    def _degrade_to_memory(self, snapshot: Snapshot) -> None:
        if self._fallback is None:
            self._fallback = RingBufferSnapshotStore(capacity=self._capacity)
        self._fallback.push(snapshot)
        try:
            self._conn.close()
        except sqlite3.Error:
            pass
        self._conn = None

    # ------------------------------------------------------------------ #
    # Row mapping
    # ------------------------------------------------------------------ #
    @staticmethod
    def _interfaces_json(snapshot: Snapshot) -> dict:
        return {
            name: {
                "download_rate": t.download_rate,
                "upload_rate": t.upload_rate,
                "counters": {
                    "timestamp": t.counters.timestamp,
                    "bytes_recv": t.counters.bytes_recv,
                    "bytes_sent": t.counters.bytes_sent,
                    "packets_recv": t.counters.packets_recv,
                    "packets_sent": t.counters.packets_sent,
                    "errors_in": t.counters.errors_in,
                    "errors_out": t.counters.errors_out,
                    "drops_in": t.counters.drops_in,
                    "drops_out": t.counters.drops_out,
                },
            }
            for name, t in snapshot.interfaces.items()
        }

    @staticmethod
    def _row_to_snapshot(row) -> Snapshot:
        (
            ts, total_dl, total_ul, rx, tx, rxp, txp,
            err_in, err_out, drop_in, drop_out, interfaces_json,
        ) = row
        interfaces: dict = {}
        try:
            raw = json.loads(interfaces_json)
        except (ValueError, TypeError):
            raw = {}
        for name, entry in raw.items():
            c = entry.get("counters", {})
            interfaces[name] = InterfaceTraffic(
                name=name,
                download_rate=entry.get("download_rate", 0.0),
                upload_rate=entry.get("upload_rate", 0.0),
                counters=RateSample(
                    timestamp=c.get("timestamp", ts),
                    bytes_recv=c.get("bytes_recv", 0),
                    bytes_sent=c.get("bytes_sent", 0),
                    packets_recv=c.get("packets_recv", 0),
                    packets_sent=c.get("packets_sent", 0),
                    errors_in=c.get("errors_in", 0),
                    errors_out=c.get("errors_out", 0),
                    drops_in=c.get("drops_in", 0),
                    drops_out=c.get("drops_out", 0),
                ),
            )
        return Snapshot(
            timestamp=ts,
            interfaces=interfaces,
            total_download=total_dl,
            total_upload=total_ul,
            total_counters=RateSample(
                timestamp=ts,
                bytes_recv=rx,
                bytes_sent=tx,
                packets_recv=rxp,
                packets_sent=txp,
                errors_in=err_in,
                errors_out=err_out,
                drops_in=drop_in,
                drops_out=drop_out,
            ),
        )
