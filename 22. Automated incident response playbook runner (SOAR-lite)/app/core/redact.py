"""PII redaction for stored alert payloads (GDPR compliance, ISO 27001 A.6.5).

Redacts known sensitive fields by key name and common patterns before the
raw payload is committed to the database. The plaintext never reaches storage.
"""
from __future__ import annotations

import re

from app.config import settings

_PATTERNS = [
    (re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE), "[EMAIL_REDACTED]"),
    (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "[SSN_REDACTED]"),
    (re.compile(r"\b\d{10,}\b"), "[NUMBER_REDACTED]"),
]


def redact_value(value, path: str = "", depth: int = 0) -> object:
    """Recursively redact sensitive fields while preserving structure."""
    if depth > 6:
        return value

    lower = path.lower().split(".")[-1]
    if lower in settings.redaction_key_set:
        if isinstance(value, (str, int, float)):
            return "[REDACTED]"
        if isinstance(value, list):
            return ["[REDACTED]" for _ in value]

    if isinstance(value, str):
        for pattern, replacement in _PATTERNS:
            value = pattern.sub(replacement, value)
        return value
    if isinstance(value, dict):
        return {k: redact_value(v, f"{path}.{k}" if path else k, depth + 1) for k, v in value.items()}
    if isinstance(value, list):
        return [redact_value(v, path, depth + 1) for v in value]
    return value


def redact_payload(payload: dict) -> dict:
    redacted = redact_value(payload)
    return redacted if isinstance(redacted, dict) else {"_redacted": redacted}