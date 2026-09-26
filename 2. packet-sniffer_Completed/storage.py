"""SQLite persistence layer.

Thread model: exactly ONE writer thread owns the connection. sqlite3
connections created with check_same_thread=False are guarded by a lock
anyway (defense in depth).
"""
from __future__ import annotations

import queue
import sqlite3
import threading
import time
from typing import Optional

_SCHEMA = """
CREATE TABLE IF NOT EXISTS packets (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    src_ip TEXT, dst_ip TEXT,
    src_port INTEGER, dst_port INTEGER,
    protocol TEXT, length INTEGER,
    info TEXT, threat_score INTEGER DEFAULT 0,
    raw_hex TEXT
);
CREATE INDEX IF NOT EXISTS idx_packets_ts ON packets(ts);
CREATE INDEX IF NOT EXISTS idx_packets_src ON packets(src_ip);
CREATE TABLE IF NOT EXISTS events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    kind TEXT, src_ip TEXT,
    description TEXT, severity TEXT
);
CREATE TABLE IF NOT EXISTS consent (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    ts REAL NOT NULL,
    accepted INTEGER NOT NULL,
    host TEXT
);
"""


class Storage:
    """Batched writer: rows are queued, flushed every 200 packets or 5 s."""

    FLUSH_N = 200
    FLUSH_T = 5.0

    def __init__(self, path: str = "packets.db"):
        self.path = path
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._conn.executescript(_SCHEMA)
        self._conn.commit()
        self._q: "queue.Queue[tuple]" = queue.Queue()
        self._stop = threading.Event()
        self._lock = threading.Lock()
        self._t = threading.Thread(target=self._loop, name="DBWriter",
                                   daemon=True)
        self._t.start()

    # -- public API ---------------------------------------------------------
    def log_consent(self, accepted: bool):
        with self._lock:
            self._conn.execute(
                "INSERT INTO consent (ts, accepted, host) VALUES (?,?,?)",
                (time.time(), 1 if accepted else 0,
                 __import__("socket").gethostname()))
            self._conn.commit()

    def add_packet(self, row: tuple):
        """row = (ts, src_ip, dst_ip, sport, dport, proto, length, info,
                  threat_score, raw_hex)"""
        self._q.put(("pkt", row))

    def add_event(self, row: tuple):
        """row = (ts, kind, src_ip, description, severity)"""
        self._q.put(("evt", row))

    def stop(self):
        self._stop.set()
        self._t.join(timeout=3)
        try:
            self._conn.close()
        except sqlite3.Error:
            pass

    def query_recent(self, limit: int = 500) -> list:
        with self._lock:
            cur = self._conn.execute(
                "SELECT ts, src_ip, dst_ip, protocol, length, info "
                "FROM packets ORDER BY id DESC LIMIT ?", (limit,))
            return cur.fetchall()

    # -- internals ------------------------------------------------------------
    def _loop(self):
        buf: list[tuple] = []
        last = time.time()
        while True:
            try:
                kind, row = self._q.get(timeout=0.5)
                buf.append((kind, row))
            except queue.Empty:
                pass
            now = time.time()
            stop_drain = self._stop.is_set() and self._q.empty()
            if buf and (len(buf) >= self.FLUSH_N
                        or now - last >= self.FLUSH_T
                        or stop_drain):
                self._flush(buf)
                buf = []
                last = now
            if stop_drain and not buf:
                break

    def _flush(self, buf: list[tuple]):
        pkts = [r for k, r in buf if k == "pkt"]
        evts = [r for k, r in buf if k == "evt"]
        try:
            with self._lock:
                if pkts:
                    self._conn.executemany(
                        "INSERT INTO packets (ts, src_ip, dst_ip, src_port,"
                        " dst_port, protocol, length, info, threat_score,"
                        " raw_hex) VALUES (?,?,?,?,?,?,?,?,?,?)", pkts)
                if evts:
                    self._conn.executemany(
                        "INSERT INTO events (ts, kind, src_ip, description,"
                        " severity) VALUES (?,?,?,?,?)", evts)
                self._conn.commit()
        except sqlite3.Error:
            # Disk full / db locked — drop rather than crash capture
            pass


class Exporter:
    @staticmethod
    def to_csv(path: str, rows: list[tuple]):
        import csv
        with open(path, "w", newline="", encoding="utf-8") as f:
            w = csv.writer(f)
            w.writerow(["ts", "src_ip", "dst_ip", "src_port", "dst_port",
                        "protocol", "length", "info"])
            w.writerows(rows)

    @staticmethod
    def to_json(path: str, rows: list[tuple]):
        import json
        keys = ["ts", "src_ip", "dst_ip", "src_port", "dst_port",
                "protocol", "length", "info"]
        data = [dict(zip(keys, r)) for r in rows]
        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=1, default=str)
