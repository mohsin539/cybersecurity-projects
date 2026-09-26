"""Normalization layer: parsers -> CES map -> validate -> quarantine.

Each source type registers a parser (pluggable). Parser output is a plain
dict of CES fields; the NORMALIZER factory fills defaults and validates.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any, Callable, Optional

from .model import Event, RawEvent, validate_event

# ---------------------------------------------------------------------------
# Registry: name -> parser callable returning dict | None (None => quarantine)
# ---------------------------------------------------------------------------

ParseResult = Optional[dict]


@dataclass
class Parser:
    name: str
    fn: Callable[[RawEvent], ParseResult]


_PARSERS: dict[str, Callable[[RawEvent], ParseResult]] = {}


def register(name: str):
    """Decorator to plug in a new parser (extensibility point)."""
    def deco(fn):
        _PARSERS[name] = fn
        return fn
    return deco


@register("json")
def _parse_json(raw: RawEvent) -> ParseResult:
    try:
        obj = json.loads(raw.raw)
    except json.JSONDecodeError:
        return None
    if not isinstance(obj, dict):
        return None
    return {
        "ts": obj.get("ts", ""),
        "source_ip": obj.get("src_ip", obj.get("source_ip", "")),
        "dest_ip": obj.get("dst_ip", obj.get("dest_ip", "")),
        "dest_port": int(obj.get("dst_port", obj.get("dest_port", 0)) or 0),
        "user": obj.get("user", ""),
        "action": obj.get("action", ""),
        "category": obj.get("category", ""),
        "severity": obj.get("severity", "info"),
        "message": obj.get("message", ""),
        "extra": obj.get("extra", {}),
    }


_SYSLOG_LINE = re.compile(r"^(?P<ts>\S+)\s+(?P<msg>.*)$")


@register("auth_syslog")
def _parse_auth_syslog(raw: RawEvent) -> ParseResult:
    m = _SYSLOG_LINE.match(raw.raw.strip())
    if not m:
        return None
    msg = m.group("msg") or ""
    fields: dict[str, Any] = {}
    # SSH auth fail success patterns
    f = re.search(r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>[\d.]+) port", msg)
    if f:
        fields.update(
            action="auth_failure", category="authentication", severity="low",
            source_ip=f.group("ip"), user=f.group("user"), dest_port=22,
            message=msg,
        )
    s = re.search(r"Accepted password for (?P<user>\S+) from (?P<ip>[\d.]+) port", msg)
    if s:
        fields.update(
            action="auth_success", category="authentication", severity="info",
            source_ip=s.group("ip"), user=s.group("user"), dest_port=22,
            message=msg,
        )
    return fields


@register("apache")
def _parse_apache(raw: RawEvent) -> ParseResult:
    m = re.search(r'^(\S+) \S+ \S+ \[(\S+ [^\]]+)\] "(\S+) (\S+ \S+ [^"]*)" (\d+) (\d+|-)', raw.raw)
    if not m:
        return None
    ip, ts, method, url, status = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5)
    sev = "info"
    if status.startswith("4"):
        sev, action = "medium", "deny"
    elif status.startswith("5"):
        sev, action = "high", "error"
    else:
        action = "allow"
    return {
        "ts": ts, "source_ip": ip, "action": action, "category": "network",
        "severity": sev, "message": f"{method} {url} -> {status}",
        "extra": {"http_method": method, "http_url": url, "http_status": int(status)},
    }


def build_normalizer(quarantine_io=None):
    """Return a callable RawEvent -> Optional[Event].

    quarantine_io: object with .write(RawEvent, reason) if present.
    """

    def normalize(raw: RawEvent) -> Optional[Event]:
        for name, fn in _PARSERS.items():
            parsed = fn(raw)
            if parsed is not None:
                ev = Event(
                    ts=parsed.get("ts", raw.ts) or raw.ts,
                    source_ip=parsed.get("source_ip", ""),
                    dest_ip=parsed.get("dest_ip", ""),
                    dest_port=int(parsed.get("dest_port", 0) or 0),
                    user=parsed.get("user", ""),
                    action=parsed.get("action", ""),
                    category=parsed.get("category", ""),
                    severity=parsed.get("severity", "info"),
                    message=parsed.get("message", raw.raw),
                    source=raw.source,
                    extra=parsed.get("extra", {}),
                )
                errors = validate_event(ev)
                if errors:
                    if quarantine_io:
                        quarantine_io.write(raw, f"schema:{','.join(errors)}")
                    return None
                return ev
        # No parser matched: fail-open -> quarantine, never crash the pipeline.
        if quarantine_io:
            quarantine_io.write(raw, "no_parser_matched")
        return None

    return normalize