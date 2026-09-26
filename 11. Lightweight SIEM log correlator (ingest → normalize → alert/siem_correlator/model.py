"""Common Event Schema (CES) models + validation.

Canonical fields follow the CES defined in architecture.md section 2.2.
"""
from __future__ import annotations

import datetime as _dt
import json
import uuid
from dataclasses import dataclass, field, asdict
from typing import Any, Optional


def utcnow() -> str:
    return _dt.datetime.now(_dt.timezone.utc).isoformat()


@dataclass
class RawEvent:
    """Event exactly as captured by an ingest source, before normalization."""
    source: str              # e.g. 'file:auth.log'
    seq: int                 # per-source sequence number
    raw: str                 # original line/payload
    ts: str = field(default_factory=utcnow)

    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass
class Event:
    """Normalized event in the Common Event Schema."""
    ts: str
    source_ip: str = ""
    dest_ip: str = ""
    dest_port: int = 0
    user: str = ""
    action: str = ""         # allow|deny|auth_success|auth_failure|exec|create|...
    category: str = ""       # authentication|network|file|process|...
    severity: str = "info"   # info|low|medium|high|critical
    message: str = ""
    source: str = ""
    extra: dict = field(default_factory=dict)

    def to_json(self) -> str:
        return json.dumps(asdict(self))


@dataclass
class Alert:
    rule_id: str
    rule_name: str
    severity: str
    evidence: list
    incident_id: str
    ts: str = field(default_factory=utcnow)
    count: int = 1

    def to_json(self) -> str:
        return json.dumps(asdict(self))


SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def validate_event(e: Event) -> list[str]:
    """Return a list of schema violations (empty == valid).

    CES validation only *requires* ts; all other fields are optional.
    """
    errors = []
    if not e.ts:
        errors.append("ts missing")
    if e.dest_port and not (0 <= e.dest_port <= 65535):
        errors.append(f"dest_port out of range: {e.dest_port}")
    if e.severity not in SEVERITY_ORDER:
        errors.append(f"severity not canonical: {e.severity}")
    if e.category not in {"", "authentication", "network", "file", "process"}:
        errors.append(f"category not in allowed set: {e.category}")
    return errors


def new_incident_id() -> str:
    return f"inc-{uuid.uuid4().hex[:12]}"