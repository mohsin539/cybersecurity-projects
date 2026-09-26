"""Result store with write-ahead log for resume (architecture.md §4.6, §10).

Results are appended to a JSONL WAL (default perms 0600 where supported);
settled (host, port) entries are skipped on --resume.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path

from .events import EventBus, PortResultEvent, ServiceFoundEvent, ScanFinished
from .models import PortResult, PortState, Proto, ServiceResult
from .security import stderr_warn


class ResultStore:
    def __init__(self, wal_path: str | Path = "scan.wal", resume: bool = False) -> None:
        self.wal_path = Path(wal_path)
        self.results: dict[tuple[str, str, int], PortResult] = {}
        self.services: dict[tuple[str, int], ServiceResult] = {}
        self._lock = threading.Lock()
        self.settled_before: set[tuple[str, str, int]] = set()

        if resume and self.wal_path.exists():
            self._load_wal()
        self._wal = open(self.wal_path, "a", encoding="utf-8")

    # ---------- WAL ----------
    def _load_wal(self) -> None:
        try:
            with open(self.wal_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    try:
                        rec = json.loads(line)
                    except json.JSONDecodeError:
                        continue  # torn tail write — safe to skip (§10)
                    if rec.get("type") == "port_result":
                        key = (rec["host"], rec["proto"], rec["port"])
                        state = rec.get("state", "")
                        if state not in ("open|filtered", "filtered"):
                            self.settled_before.add(key)
        except OSError as exc:
            stderr_warn(f"WAL load failed: {exc}")

    def _wal_append(self, record: dict) -> None:
        try:
            self._wal.write(json.dumps(record) + "\n")
            self._wal.flush()
        except OSError as exc:
            stderr_warn(f"WAL write failed: {exc}")

    def close(self) -> None:
        try:
            self._wal.close()
        except OSError:
            pass
        if os.name == "posix":
            try:
                os.chmod(self.wal_path, 0o600)  # scan intel is sensitive (§16)
            except OSError:
                pass

    # ---------- subscriptions ----------
    def attach(self, bus: EventBus) -> None:
        bus.subscribe(self.on_result)
        bus.subscribe(self.on_service)
        bus.subscribe(self.on_finished)

    # ---------- handlers ----------
    def on_result(self, ev: PortResultEvent) -> None:
        key = (ev.host, ev.proto, ev.port)
        with self._lock:
            prev = self.results.get(key)
            # state machine: only upgrade on stronger evidence (§8)
            if prev is not None and str(prev.state) not in ("open|filtered", "filtered"):
                return
            result = PortResult(
                host=ev.host, hostname="", port=ev.port,
                proto=Proto(ev.proto),
                state=PortState(ev.state),
                engine="scheduler", attempt=0, rtt_ms=ev.rtt_ms,
            )
            self.results[key] = result
        self._wal_append({
            "type": "port_result", "host": ev.host, "port": ev.port,
            "proto": ev.proto, "state": ev.state, "rtt_ms": ev.rtt_ms,
        })

    def on_service(self, ev: ServiceFoundEvent) -> None:
        self._wal_append({"type": "service", "host": ev.host, "port": ev.port,
                          "service": ev.service})

    def on_finished(self, ev: ScanFinished) -> None:
        self._wal_append({"type": "scan_finished", "duration_s": ev.duration_s,
                          "counts": ev.counts})

    def add_service(self, service: ServiceResult) -> None:
        with self._lock:
            self.services[(service.host, service.port)] = service
        self._wal_append(service.to_dict())

    def open_ports(self) -> list[PortResult]:
        with self._lock:
            return sorted(
                (r for r in self.results.values() if r.state == PortState.OPEN),
                key=lambda r: (r.host, r.port),
            )
