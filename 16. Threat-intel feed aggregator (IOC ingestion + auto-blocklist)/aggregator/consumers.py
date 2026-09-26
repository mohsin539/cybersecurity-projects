"""Consumer driver layer: idempotent pushes, diff-only, rollback (architecture §2.5)."""
from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List

from .decision import BlocklistRecord


@dataclass
class DriverResult:
    consumer: str
    pushed: int = 0
    removed: int = 0
    ok: bool = True
    detail: str = ""

    def to_dict(self) -> dict:
        return {**self.__dict__}


class Consumer:
    """Abstract: render diff between current state and last-synced state."""

    name = "abstract"

    def __init__(self, dest: str):
        self.dest = dest
        self.last_synced: set = self._load_last()

    def _load_last(self) -> set:
        return set()

    def _save_last(self, entries: set) -> None:
        pass

    def sync(self, active: List[BlocklistRecord]) -> DriverResult:
        entries = {r.value for r in active}
        prev = self.last_synced
        to_push = entries - prev
        to_remove = prev - entries
        self._push(to_push)
        self._remove(to_remove)
        self._save_last(entries)
        return DriverResult(self.name, pushed=len(to_push), removed=len(to_remove), ok=True)


class JsonDiffConsumer(Consumer):
    """Append/expunge on one JSON file; tracks last-synced in <dest>.state."""

    name = "json-release"

    def __init__(self, dest: str):
        super().__init__(dest)
        self.path = Path(dest)
        self.synthetic: list = []
        if self.path.exists():
            try:
                self.synthetic = json.loads(self.path.read_text(encoding="utf-8"))
            except json.JSONDecodeError:
                self.synthetic = []

    def _load_last(self) -> set:
        sp = Path(self.dest + ".state")
        if sp.exists():
            try:
                return {x.strip() for x in sp.read_text(encoding="utf-8").splitlines() if x.strip()}
            except OSError:
                pass
        return set()

    def _save_last(self, entries: set) -> None:
        Path(self.dest + ".state").write_text("\n".join(sorted(entries)), encoding="utf-8")

    def _push(self, items: set) -> None:
        for v in items:
            self.synthetic.append({"value": v, "op": "add", "ts": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())})

    def _remove(self, items: set) -> None:
        self.synthetic[:] = [e for e in self.synthetic if e.get("value") not in items]

    def finalize(self) -> None:
        self.path.write_text(json.dumps(self.synthetic, indent=2), encoding="utf-8")


class PfSenseStyleConsumer(Consumer):
    """Alias-table style consumer: writes 'blocklist' table lines; idempotent."""

    name = "pf-alias"

    def __init__(self, dest: str):
        super().__init__(dest)
        self.path = Path(dest)

    def _push(self, items: set) -> None:
        with self.path.open("a", encoding="utf-8") as fh:
            for v in items:
                fh.write(f"{v}\n")

    def _remove(self, items: set) -> None:
        if not Path(self.path).exists():
            return
        lines = [l for l in self.path.read_text(encoding="utf-8").splitlines() if l.strip() not in items]
        self.path.write_text("\n".join(lines) + ("\n" if lines else ""), encoding="utf-8")


DRIVERS = {"json": JsonDiffConsumer, "pf": PfSenseStyleConsumer}


def make_driver(kind: str, dest: str) -> Consumer:
    return DRIVERS[kind](dest)