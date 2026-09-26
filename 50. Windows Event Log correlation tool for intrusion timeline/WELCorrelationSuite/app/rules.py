"""Rules engine: load, compile and evaluate correlation rules against events."""
import json
import os
import re

from .rules_registry import RULES as BUILTIN_RULES


def load_rules(source=None):
    """Load rules from an explicit JSON/registry file, or use built-ins."""
    if not source:
        return [Rule(r) for r in BUILTIN_RULES]
    with open(source, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    items = data if isinstance(data, list) else data.get("rules", [])
    return [Rule(r) for r in items]


def match_op(value, condition):
    """Evaluate a single field condition against an event value string."""
    if value is None:
        value = ""
    value = str(value)
    condition = str(condition)
    low, clow = value.lower(), condition.lower()
    if clow.startswith("~"):
        pattern = condition[1:]
        try:
            return re.search(pattern, value, re.IGNORECASE) is not None
        except re.error:
            return pattern.lower() in low
    if clow.startswith("!"):
        return not match_op(value, condition[1:]) if condition[1:] else value == ""
    if clow.startswith(">"):
        try:
            num = float(condition[1:])
            fval = float(value)
        except ValueError:
            return False
        return fval > num
    if clow.startswith("<"):
        try:
            num = float(condition[1:])
            fval = float(value)
        except ValueError:
            return False
        return fval < num
    return low == clow


class Rule:
    """A single correlation rule with one or more event matchers."""

    def __init__(self, spec):
        self.spec = spec
        self.id = spec.get("id", "R-?")
        self.name = spec.get("name", self.id)
        self.severity = int(spec.get("severity", 0))
        self.stage = spec.get("stage", "execution")
        self.mitre = spec.get("mitre") or {}
        self.iso = spec.get("iso") or []
        self.nist = spec.get("nist") or []
        self.note = spec.get("note", "")
        self.matches = spec.get("matches") or []

    def _value(self, event, key):
        if key in event:
            return event[key]
        d = event.get("data") or {}
        if key in d:
            return d[key]
        for ek, ev in (d or {}).items():
            if str(ek).strip().lower() == str(key).strip().lower():
                return ev
        return None

    def _match_one(self, event, matcher):
        ch = str(matcher.get("channel", "")).strip().lower()
        if ch and event.get("channel", "").strip().lower() != ch:
            return False
        want_id = matcher.get("event_id")
        if want_id is not None and int(event.get("event_id", 0)) != int(want_id):
            return False
        for key, cond in (matcher.get("opts") or {}).items():
            val = self._value(event, key)
            if not match_op(val, cond):
                return False
        return True

    def match(self, event):
        """True when any matcher fires for the event."""
        return any(self._match_one(event, m) for m in self.matches)

    def fire(self, event):
        """Return an incident record for a matching event."""
        return {
            "rule_id": self.id,
            "rule_name": self.name,
            "severity": self.severity,
            "stage": self.stage,
            "mitre": self.mitre,
            "iso": self.iso,
            "nist": self.nist,
            "note": self.note,
            "event_id": event.get("id"),
            "ts": event.get("ts"),
            "ts_epoch": event.get("ts_epoch", 0),
            "channel": event.get("channel"),
            "computer": event.get("computer", ""),
            "source_ip": event.get("source_ip", ""),
            "target_user": event.get("target_user", ""),
            "subject_user": event.get("subject_user", ""),
            "message": event.get("message", ""),
        }

    def as_dict(self):
        return dict(self.spec)


def severity_label(score):
    if score >= 85:
        return "critical"
    if score >= 65:
        return "high"
    if score >= 40:
        return "medium"
    if score >= 20:
        return "low"
    return "informational"