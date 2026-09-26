"""First-party example plugin: CTF-hinted string heuristics.

Demonstrates the plugin API contract: class Plugin with operations() returning
{op_name: callable(bytes) -> bytes}. PURE risk class only — no I/O, no imports
beyond stdlib string work (plugins.py enforces nothing else yet; review before
extending, see docs in security.md).
"""
from __future__ import annotations

import re

_HINTS = [
    (rb"(?i)(password|passwd|secret|key)\s*[:=]\s*[^\s\x00]{4,64}"),
    (rb"(?i)wrong|correct|nice try|you got"),
    (rb"\b(?:md5|sha1|sha256)\b\s*[:=]?\s*[0-9a-f]{16,64}"),
]


class Plugin:
    name = "suspicious_strings"

    def operations(self) -> dict[str, object]:
        return {"mark_hints": self.mark_hints}

    @staticmethod
    def mark_hints(data: bytes) -> bytes:
        out = data
        for pat in _HINTS:
            out = re.sub(pat, lambda m: b"<<<" + m.group(0)[:120] + b">>>", out)
        return out
