"""TTPProfiler :: security primitives
Implements OWASP-aligned controls: input normalization/sanitization,
integrity hashing, append-only audit chain, safe path handling.
"""
from __future__ import annotations

import hashlib
import html
import json
import re
from pathlib import Path

TABLE_NAMES = re.compile(r"^[A-Za-z0-9_]{1,64}$")
_SAFE_STRING = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f]")


def sha256_bytes(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def sha256_text(text: str) -> str:
    return sha256_bytes(text.encode("utf-8", errors="replace"))


def sha256_file(path: str | Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def sanitize_text(text: str, max_len: int = 4096) -> str:
    """Control-char stripping + HTML-safe escaping (OWASP XSS A03)."""
    if not text:
        return ""
    if not isinstance(text, str):
        text = str(text)
    out = _SAFE_STRING.sub("", text)[:max_len]
    return html.escape(out, quote=True)


def sanitize_for_sql(text: str, max_len: int = 4096) -> str:
    """Neutralize quote/comment characters used in SQL injection."""
    if not isinstance(text, str):
        text = str(text)
    out = _SAFE_STRING.sub("", text)[:max_len]
    return out.replace("'", "''").replace(";", " ").replace("--", " ")


def valid_table_name(name: str) -> bool:
    return bool(name) and bool(TABLE_NAMES.match(name))


def json_dumps_safe(obj) -> str:
    return json.dumps(obj, ensure_ascii=False, default=str)


def normalize_schema(data: dict) -> dict:
    """Default-deny normalization for ingested report JSON."""
    allowed_top = {
        "sha256", "filename", "family", "verdict", "yara_rules", "av_names",
        "network", "files", "processes", "registry", "strings", "behaviors", "meta",
    }
    out = {}
    for k in allowed_top:
        if k in data:
            out[k] = data[k]
    return out


def safe_join(root: Path, rel: str) -> Path:
    """Prevent path traversal in imports."""
    root = root.resolve()
    cand = (root / rel).resolve()
    if not str(cand).startswith(str(root)):
        raise ValueError("Path traversal attempt rejected")
    return cand


class AuditChain:
    """Append-only, hash-chained audit log (ISO A.16, NIST AU-3)."""

    def __init__(self, store, table: str = "audit"):
        self.store = store
        self.table = table
        self._last_hash = store.audit_last_hash()

    def record(self, action: str, detail: str = "") -> None:
        payload = json_dumps_safe({"action": action, "detail": detail})
        current = sha256_text(self._last_hash + payload)
        self.store.audit_append(action, sanitize_for_sql(detail, 2048), self._last_hash, current)
        self._last_hash = current

    @property
    def last_hash(self) -> str:
        return self._last_hash