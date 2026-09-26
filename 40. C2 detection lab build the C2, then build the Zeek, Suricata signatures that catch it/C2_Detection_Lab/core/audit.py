"""Audit trail - ISO A.8.16/A.8.17 + NIST AU-6 evidence chain.

Every artifact produced by a lab run is hashed (SHA-256) and written to
`audit.json`. This gives an immutable, replayable evidence record that is
exported into the report formats (.XLSX / .CSV / .HTML).
"""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path

_EVENTS_TAG = "ISO.27001.A8.17 / NIST.800-53.AU-6"


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


class Auditor:
    def __init__(self, outdir: str | Path):
        self.outdir = Path(outdir)
        self.outdir.mkdir(parents=True, exist_ok=True)
        self.entries: list[dict] = []

    def log(self, event: str, detail: str = "", artifact: str | None = None) -> dict:
        entry = {
            "ts": time.time(),
            "ts_iso": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "event": event,
            "detail": detail,
            "artifact": artifact,
            "control": _EVENTS_TAG,
        }
        if artifact and Path(artifact).exists():
            entry["sha256"] = sha256_file(artifact)
        self.entries.append(entry)
        return entry

    def write(self) -> Path:
        target = self.outdir / "audit.json"
        target.write_text(
            json.dumps({"generated": time.time(), "entries": self.entries}, indent=2),
            encoding="utf-8",
        )
        self.log("evidence_written", str(target), str(target))
        # rewrite to include the evidence hash of audit.json itself (self-chain)
        payload = json.dumps(
            {"generated": time.time(), "entries": self.log_entries_snapshot()}, indent=2
        )
        target.write_text(payload, encoding="utf-8")
        return target

    def log_entries_snapshot(self) -> list[dict]:
        out: list[dict] = []
        for e in self.entries:
            if e["event"] == "evidence_written":
                continue
            out.append(e)
        return out