"""Ingest layer: file tailer + syslog UDP listener + quarantine.

Design notes (memory.md #1): at-least-once delivery, idempotent reads via
(offset, seq) bookkeeping, backpressure via bounded queue.
"""
from __future__ import annotations

import json
import os
import re
import socketserver
import threading
from pathlib import Path
from queue import Empty, PriorityQueue, Queue
from typing import Iterable, Optional

from .model import RawEvent

_PORT_RE = re.compile(r"^(\d+)$")


class OffsetTracker:
    """Persist per-file read offset and next sequence number."""

    def __init__(self, state_dir: Path):
        self.state_dir = state_dir
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self._path = self.state_dir / "ingest_offsets.json"
        self._data: dict[str, dict] = {}
        if self._path.exists():
            try:
                self._data = json.loads(self._path.read_text(encoding="utf-8"))
            except (json.JSONDecodeError, OSError):
                self._data = {}

    def get(self, key: str) -> tuple[int, int]:
        entry = self._data.get(key, {})
        return int(entry.get("offset", 0)), int(entry.get("seq", 0))

    def put(self, key: str, offset: int, seq: int) -> None:
        self._data[key] = {"offset": offset, "seq": seq}
        tmp = self._path.with_suffix(".tmp")
        tmp.write_text(json.dumps(self._data, indent=2), encoding="utf-8")
        os.replace(tmp, self._path)


class FileTailer:
    """Poll-based file tailer (portable; no inotify dependency).

    Reads only appended bytes. Never overwrites. On each poll it advances
    by the bytes read, so restarts resume from the last offset (at-least-once).
    """

    def __init__(self, path: Path, offsets: OffsetTracker, chunk: int = 65536):
        self.path = path
        self.offsets = offsets
        self.chunk = chunk
        self.key = f"file:{path}"
        self._offset, self._seq = offsets.get(self.key)

    def __iter__(self) -> Iterable[RawEvent]:
        if not self.path.exists():
            return
        size = self.path.stat().st_size
        if size < self._offset:
            # File truncated (rotation) -> restart from 0.
            self._offset, self._seq = 0, 1
        with self.path.open("r", encoding="utf-8", errors="replace") as fh:
            fh.seek(self._offset)
            while True:
                line = fh.readline()
                if not line:
                    break
                b = len(line.encode("utf-8", errors="replace"))
                self._offset += b
                self._seq += 1
                self.offsets.put(self.key, self._offset, self._seq)
                yield RawEvent(source=self.key, seq=self._seq, raw=line.rstrip("\n"))


class SyslogPlayer:
    """Reads a syslog-format capture file and emits RawEvents (replay).

    Used for demos/tests and to replay canned attack logs cannot be faked
    over a live socket without privileged ports.
    """

    def __init__(self, path: Path):
        self.path = path

    def __iter__(self) -> Iterable[RawEvent]:
        seq = 0
        if not self.path.exists():
            return
        for line in self.path.read_text(encoding="utf-8", errors="replace").splitlines():
            seq += 1
            yield RawEvent(source=f"syslog:{self.path.name}", seq=seq, raw=line)


def _default_parse_count(x: str) -> int:
    try:
        return int(x)
    except ValueError:
        return 0


class IngestPipeline:
    """Feeds RawEvents into a bounded queue; parallel workers drain it.

    Bounded queue gives backpressure: producers block instead of dropping.
    """

    def __init__(self, maxsize: int = 10_000):
        self._q: "Queue[Optional[RawEvent]]" = Queue(maxsize=maxsize)
        self._stop = threading.Event()
        self._thread_count = 0

    def push(self, source, seq: int, raw: str) -> None:
        self._q.put(RawEvent(source=source, seq=seq, raw=raw))

    def start_worker(self, worker_fn) -> threading.Thread:
        """worker_fn receives one RawEvent and returns Optional[int] acked seq.

        Acking unused (no offsets to persist for raw capture), kept for API
        symmetry with future syslog socket ingest.
        """

        def _loop():
            while not self._stop.is_set():
                try:
                    ev = self._q.get(timeout=0.5)
                except Empty:
                    continue
                if ev is None:
                    break
                try:
                    worker_fn(ev)
                finally:
                    self._q.task_done()

        t = threading.Thread(target=_loop, daemon=True)
        t.start()
        self._thread_count += 1
        return t

    def stop(self) -> None:
        self._stop.set()
        for _ in range(self._thread_count):
            self._q.put(None)


class Quarantine:
    """Fail-open normalization dump: unparseable / invalid events land here."""

    def __init__(self, path: Path):
        self.path = path
        self.path.mkdir(parents=True, exist_ok=True)
        self._fh = (self.path / "quarantine.jsonl").open("a", encoding="utf-8")

    def write(self, raw: RawEvent, reason: str) -> None:
        rec = {"reason": reason, "source": raw.source, "seq": raw.seq, "raw": raw.raw}
        self._fh.write(json.dumps(rec) + "\n")
        self._fh.flush()

    def close(self) -> None:
        self._fh.close()