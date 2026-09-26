"""Redaction service (ISO 27001 A.5.34 privacy; OWASP A03).

Two layers:
1. `redact_string` - masks secrets that appear inside plain string content.
2. `redact_json`  - re-serializes an object and runs value-preserving
   redaction over the canonical JSON text, then parses back. Key/value
   patterns define a named group `val` so only the value is masked, keeping
   the surrounding JSON structure intact.

Applied to API args before persist/visualize/export (fail-safe: if the JSON
round-trip ever breaks, the unredacted original is NOT returned - the caller
gets a conservative redacted copy built from per-node string redaction).
"""

from __future__ import annotations

import json
import re
from functools import lru_cache


@lru_cache(maxsize=1)
def default_patterns() -> tuple[str, ...]:
    return (
        r"(?i)(?P<key>(authorization|password|passwd|pwd|secret|token|bearer|api[_-]?key))"
        r"[\"']?\s*[:=]\s*(?P<val>(?:\"[^\"]*\")|(?:'[^']*')|\S+)",
        r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b",
        r"\b\d{3}[- ]?\d{2}[- ]?\d{4}\b",
    )


class RedactionService:
    def __init__(self, patterns: list[str], enabled: bool = True) -> None:
        self.enabled = enabled
        self._compiled = [re.compile(p) for p in patterns]

    # ------------------------------------------------------------------ text
    def redact_string(self, value: str) -> str:
        out = value
        for rx in self._compiled:
            out = rx.sub("[REDACTED]", out)
        return out

    @staticmethod
    def _repl(m: re.Match) -> str:
        gd = m.groupdict()
        val = gd.get("val")
        if "val" in gd and val is not None:
            prefix = m.group(0)[: m.start("val") - m.start()]
            lead = val[0] if val[:1] in ('"', "'") else ""
            trail = lead
            return f"{prefix}{lead}[REDACTED]{trail}"
        return "[REDACTED]"

    def _redact_text(self, text: str) -> str:
        out = text
        for rx in self._compiled:
            out = rx.sub(self._repl, out)
        return out

    # ------------------------------------------------------------------ json
    def redact_json(self, obj: object) -> object:
        if not self.enabled:
            return obj
        text = json.dumps(obj, ensure_ascii=True, sort_keys=True, separators=(",", ":"))
        text = self._redact_text(text)
        try:
            return json.loads(text)
        except (ValueError, TypeError):
            return self._fallback(obj)

    def _fallback(self, obj: object) -> object:
        """Per-node string redaction when JSON re-parse is impossible."""
        return self._walk(obj)

    def _walk(self, node: object) -> object:
        if isinstance(node, dict):
            return {k: self._walk(v) for k, v in node.items()}
        if isinstance(node, list):
            return [self._walk(v) for v in node]
        if isinstance(node, str):
            return self.redact_string(node)
        return node