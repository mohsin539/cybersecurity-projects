"""Schema registry (ISO 27001 A.8.9 configuration management).

Bundles JSON Schemas for events, reports, audit entries and policy so
validators are self-contained inside the portable .exe.
"""

from __future__ import annotations

import json
from importlib import resources
from pathlib import Path

_EVENT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ACSV normalized API event",
    "type": "object",
    "required": ["seq", "ts_ns", "tid", "pid", "category", "api", "ret"],
    "additionalProperties": True,
    "properties": {
        "seq": {"type": "integer", "minimum": 0},
        "ts_ns": {"type": "integer", "minimum": 0},
        "tid": {"type": "integer"},
        "pid": {"type": "integer"},
        "category": {"type": "string", "enum": [
            "File", "Registry", "Network", "Process", "Thread", "Crypto",
            "Memory", "IPC", "Exception", "Other",
        ]},
        "api": {"type": "string", "minLength": 1},
        "module": {"type": "string"},
        "args": {"type": "object"},
        "ret": {"type": "string"},
        "status": {"type": "string", "enum": ["SUCCESS", "FAIL", "TIMEOUT", "UNKNOWN"]},
        "caller_stack_hash": {"type": "string"},
        "tags": {"type": "array", "items": {"type": "string"}},
        "parent_seq": {"type": ["integer", "null"]},
    },
}

_REPORT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ACSV report document",
    "type": "object",
    "required": ["report_id", "generated_at", "report_sha256", "session_id", "sections"],
    "properties": {
        "report_id": {"type": "string"},
        "generated_at": {"type": "string"},
        "report_sha256": {"type": "string"},
        "session_id": {"type": "string"},
        "policy_snapshot": {"type": "string"},
        "sections": {"type": "object"},
        "integrity": {"type": "object"},
    },
}

_AUDIT_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ACSV audit entry",
    "type": "object",
    "required": ["seq", "ts_ns", "actor", "action", "payload", "prev_hash", "entry_hash"],
    "properties": {
        "seq": {"type": "integer"},
        "ts_ns": {"type": "integer"},
        "actor": {"type": "string"},
        "action": {"type": "string"},
        "payload": {"type": "object"},
        "prev_hash": {"type": "string"},
        "entry_hash": {"type": "string"},
    },
}

_POLICY_SCHEMA = {
    "$schema": "https://json-schema.org/draft/2020-12/schema",
    "title": "ACSV policy",
    "type": "object",
    "required": ["config_version", "capture", "security", "reporting"],
    "properties": {
        "config_version": {"type": "string"},
        "capture": {"type": "object"},
        "security": {"type": "object"},
        "reporting": {"type": "object"},
        "retention_days": {"type": "integer"},
    },
}

_SCHEMAS = {
    "event": _EVENT_SCHEMA,
    "report": _REPORT_SCHEMA,
    "audit": _AUDIT_SCHEMA,
    "policy": _POLICY_SCHEMA,
}


class SchemaRegistry:
    """Versioned JSON Schema lookup with minimal structural validation."""

    SCHEMA_VERSION = "event@1.0"

    @classmethod
    def get(cls, name: str) -> dict:
        if name not in _SCHEMAS:
            raise KeyError(f"unknown schema '{name}'")
        return _SCHEMAS[name]

    @classmethod
    def validate_event(cls, ev: dict) -> list[str]:
        """Cheap structural validation; returns list of problems (empty = ok)."""
        probs: list[str] = []
        for req in ("seq", "ts_ns", "tid", "pid", "category", "api", "ret"):
            if req not in ev:
                probs.append(f"missing required field: {req}")
        if "seq" in ev and (not isinstance(ev["seq"], int) or ev["seq"] < 0):
            probs.append("seq must be a non-negative integer")
        if "ts_ns" in ev and not isinstance(ev["ts_ns"], int):
            probs.append("ts_ns must be an integer")
        if "args" in ev and not isinstance(ev["args"], dict):
            probs.append("args must be an object")
        return probs

    @classmethod
    def version(cls) -> str:
        return cls.SCHEMA_VERSION

    @classmethod
    def export_dir(cls, target: Path) -> None:
        """Write embedded schemas to disk (air-gap / audit convenience)."""
        target.mkdir(parents=True, exist_ok=True)
        for name, schema in _SCHEMAS.items():
            (target / f"{name}.schema.json").write_text(
                json.dumps(schema, indent=2), encoding="utf-8"
            )