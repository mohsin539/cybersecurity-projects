"""Trace importers (ETW/procmon/API-Monitor/file drag&drop).

Imports validated external trace files into TraceEvent streams. Parser
inputs are schema-validated; only structured reads (no shell/exec).
"""

from __future__ import annotations

import csv
import json
import xml.etree.ElementTree as ET
from pathlib import Path

from ..registry import SchemaRegistry
from .runner import TraceEvent

_CAT_MAP = {
    "file": "File", "disk": "File", "registry": "Registry", "reg": "Registry",
    "network": "Network", "net": "Network", "tcp": "Network", "udp": "Network",
    "process": "Process", "proc": "Process", "thread": "Thread",
    "crypto": "Crypto", "memory": "Memory", "map": "Memory",
    "ipc": "IPC", "mail": "IPC", "exception": "Exception", "excp": "Exception",
}


def _norm_cat(raw: str) -> str:
    key = (raw or "Other").lower()
    return _CAT_MAP.get(key, "Other")


class TraceImporter:
    @staticmethod
    def from_acsx_json(path: Path) -> list[TraceEvent]:
        data = json.loads(path.read_text(encoding="utf-8"))
        traces = data.get("events", data) if isinstance(data, dict) else data
        out = []
        for e in traces:
            probs = SchemaRegistry.validate_event(e)
            if probs:
                raise ValueError(f"trace event invalid: {'; '.join(probs)}")
            out.append(TraceEvent(
                api=e["api"], category=_norm_cat(e.get("category")), args=e.get("args", {}),
                ret=str(e.get("ret", "")), tid=int(e.get("tid", 1)), pid=int(e.get("pid", 1)),
                ts_ns=int(e.get("ts_ns", 0)), status=e.get("status", "SUCCESS"),
                parent_seq=e.get("parent_seq"), tags=e.get("tags", []),
                module=e.get("module", ""),
            ))
        return out

    @staticmethod
    def from_csv(path: Path) -> list[TraceEvent]:
        out = []
        with open(path, newline="", encoding="utf-8") as fh:
            for row in csv.DictReader(fh):
                if not row.get("api"):
                    continue
                out.append(TraceEvent(
                    api=row["api"], category=_norm_cat(row.get("category")),
                    args=json.loads(row.get("args", "{}")), ret=row.get("ret", ""),
                    tid=int(row.get("tid", 1)), pid=int(row.get("pid", 1)),
                    ts_ns=int(row.get("ts_ns", 0)), status=row.get("status", "SUCCESS"),
                    tags=row.get("tags", "").split(",") if row.get("tags") else [],
                    module=row.get("module", ""),
                ))
        return out

    @staticmethod
    def from_api_monitor_xml(path: Path) -> list[TraceEvent]:
        """API-Monitor export.xml -> TraceEvents (best effort)."""
        root = ET.parse(path).getroot()
        out = []
        for call in root.iter("Call") if root.tag.lower() == "calls" else root.iter():
            name = (call.findtext("Name") or call.get("name") or "").strip()
            if not name:
                continue
            args = {
                (a.get("name") or f"arg{i}"): (a.text or "").strip()
                for i, a in enumerate(list(call) )
            }
            out.append(TraceEvent(
                api=name, category="Other", args=args, ret=call.get("ret", ""),
                tid=int(call.get("Thread", 1) or 1), pid=int(call.get("Process", 1) or 1),
                status=call.get("status", "SUCCESS"),
            ))
        return out

    @staticmethod
    def detect(path: Path) -> str:
        suffix = path.suffix.lower()
        if suffix == ".json":
            return "json"
        if suffix == ".csv":
            return "csv"
        if suffix == ".xml":
            return "xml"
        return "json"

    @classmethod
    def import_file(cls, path: Path) -> list[TraceEvent]:
        kind = cls.detect(path)
        if kind == "csv":
            return cls.from_csv(path)
        if kind == "xml":
            return cls.from_api_monitor_xml(path)
        return cls.from_acsx_json(path)