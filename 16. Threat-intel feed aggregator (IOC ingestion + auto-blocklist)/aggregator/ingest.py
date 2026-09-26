"""Ingest adapters: JSON fixture, CSV, and honeypot-style payload (Project 15).

Each adapter stores structured IOC objects in `aggregator.normalize.IOC`.
"""
from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import List

from .normalize import IOC


def ingest_fixture_json(path: Path) -> List[IOC]:
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    out = []
    for d in data:
        if isinstance(d, dict):
            out.append(IOC(
                value=d.get("value", ""),
                ioc_type=d.get("ioc_type", "ipv4"),
                confidence=float(d.get("confidence", 0.5)),
                tlp=d.get("tlp", "white"),
                expires_at=d.get("expires_at", "2099-12-31T23:59:59Z"),
                tags=d.get("tags", []),
                feed_id=d.get("feed_id", "fixture"),
                first_seen=d.get("first_seen", ""),
                sources=d.get("sources", []),
            ))
    return [i for i in out if i.value]


def ingest_csv(path: Path) -> List[IOC]:
    out = []
    with Path(path).open(newline="", encoding="utf-8") as fh:
        for row in csv.DictReader(fh):
            out.append(IOC(
                value=row.get("value", ""),
                ioc_type=row.get("ioc_type", "ipv4"),
                confidence=float(row.get("confidence", 0.5)),
                tlp=row.get("tlp", "white"),
                expires_at=row.get("expires_at", "2099-12-31T23:59:59Z"),
                feed_id=row.get("feed_id", "csv"),
            ))
    return [i for i in out if i.value]


def ingest_honeypot_event(event: dict) -> List[IOC]:
    """Consumes Project 15 blocklist payload: {ioc_type, value, confidence, feed_id}."""
    if event.get("source") != "honeypot":
        return []
    return [IOC(
        value=str(event["value"]),
        ioc_type=event.get("ioc_type", "ipv4"),
        confidence=float(event.get("confidence", 1.0)),
        tlp=event.get("tlp", "white"),
        feed_id=event.get("feed_id", "honeypot-internal"),
        tags=event.get("tags", []),
    )]