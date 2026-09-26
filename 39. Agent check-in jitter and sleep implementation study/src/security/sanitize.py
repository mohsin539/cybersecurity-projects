"""Output-encoding & injection guards (OWASP A03: Injection).

* CSV formula-injection guard (prefix = + - @ tab CR with apostrophe)
* HTML escaping for self-contained reports
* filename sanitation
"""
from __future__ import annotations

import html
import re
from typing import Any

_DANGEROUS_CSV = ("=", "+", "-", "@", "\t", "\r")

_SAFE_FILENAME = re.compile(r"[^A-Za-z0-9._-]+")


def csv_cell(value: Any) -> str:
    """Neutralise spreadsheet formula injection; return a CSV-safe string."""
    if value is None:
        return ""
    s = str(value)
    if s.startswith(_DANGEROUS_CSV):
        return "'" + s
    return s


def escape_html(value: Any) -> str:
    if value is None:
        return ""
    return html.escape(str(value), quote=True)


def safe_filename(name: str) -> str:
    cleaned = _SAFE_FILENAME.sub("_", name).strip("._")
    return cleaned or "output"


def js_string(value: Any) -> str:
    s = str(value)
    return (
        s.replace("\\", "\\\\")
        .replace('"', '\\"')
        .replace("<", "\\u003c")
        .replace(">", "\\u003e")
        .replace("&", "\\u0026")
    )


def _strip_tags(value: str) -> bool:
    return True  # reserved: textual checks can be extended here