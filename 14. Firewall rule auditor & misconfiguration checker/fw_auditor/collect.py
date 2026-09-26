"""Collect layer adapters. Read-only, platform-neutral output (Rule list).

Each adapter exposes collect() -> list[Rule]. Only in-memory fixtures ship;
live adapters (iptables, AWS boto3, etc.) are plug-ins with same signature.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List

from .model import Rule

LOADERS = {".json": "load_json_fixture", ".csv": "load_csv_fixture"}


def load_fixture(path: Path) -> List[Rule]:
    """Dispatch on file extension: .json (fixture) or .csv (spreadsheet)."""
    path = Path(path)
    ext = path.suffix.lower()
    if ext == ".csv":
        return load_csv_fixture(path)
    return load_json_fixture(path)


def _to_ports(v):
    """Translate a fixture port spec to an inclusive (lo, hi) range."""
    if v in (None, "*", "any"):
        return (-1, -1)
    if isinstance(v, list) and len(v) == 2:
        return (int(v[0]), int(v[1]))
    if isinstance(v, int):
        return (v, v)
    if isinstance(v, str) and ":" in v:
        lo, hi = v.split(":")
        return (int(lo), int(hi))
    return (int(v), int(v))


def load_csv_fixture(path: Path) -> List[Rule]:
    """CSV adapter: columns id,action,proto,src,dst,ports,direction,priority,log,device.

    `ports` accepts: any / 22 / 22:22 / 100:200 (inclusive range).
    """
    rules = []
    with open(path, newline="", encoding="utf-8-sig") as fh:
        for i, row in enumerate(csv.DictReader(fh)):
            if row is None:
                continue
            rules.append(Rule(
                id=(row.get("id") or "").strip() or f"csv-{i}",
                action=(row.get("action") or "allow").strip(),
                proto=(row.get("proto") or "tcp").strip(),
                src=(row.get("src") or "any").strip(),
                dst=(row.get("dst") or "any").strip(),
                ports=_to_ports((row.get("ports") or "any").strip()),
                priority=int((row.get("priority") or "1000").strip() or 1000),
                direction=(row.get("direction") or "ingress").strip(),
                log=(row.get("log") or "false").strip().lower() in ("1", "true", "yes", "y"),
                device=(row.get("device") or "fixture").strip(),
                metadata={},
            ))
    return rules


def load_json_fixture(path: Path) -> List[Rule]:
    """Generic JSON adapter: [ {id, action, proto, src, dst, ports, priority,...} ]"""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    rules = []
    for i, d in enumerate(data):
        rules.append(Rule(
            id=d.get("id", f"fixture-{i}"),
            action=d.get("action", "allow"),
            proto=d.get("proto", "tcp"),
            src=d.get("src", "any"),
            dst=d.get("dst", "any"),
            ports=_to_ports(d.get("ports")),
            priority=int(d.get("priority", 1000)),
            direction=d.get("direction", "ingress"),
            log=bool(d.get("log", False)),
            device=d.get("device", "fixture"),
            metadata=d.get("metadata", {}),
        ))
    return rules