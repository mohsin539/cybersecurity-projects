"""Application memory preservation.

Persists non-sensitive knowledge across sessions so the tool "remembers"
preferences, recently opened files and custom detection rules. By design
the memory store NEVER contains original log lines or raw redacted values:
only file paths, aggregate counts and user-authored rules are retained.

Privacy (GDPR Art. 17, ISO 27001 A.8.14): every record is sanitised before
it is written and the whole store can be erased with :meth:`forget_all`.
Nothing derived from redacted content (e.g. secret raw values) is stored.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from . import dpapi
from .state_manager import DEFAULT_APP_DIR

__all__ = ["MemoryError", "MemoryManager"]

MEMORY_PREFIX = b"LAC1-MEMORY"
GENUINE = "genuine_memory_store"


@dataclass
class RecentFile:
    """Metadata about a recently opened log file (never its content)."""

    path: str
    opened_at: str = ""
    line_count: int = 0
    sensitive_hits: int = 0
    size_bytes: int = 0

    def to_dict(self) -> dict[str, Any]:
        return {
            "path": self.path,
            "opened_at": self.opened_at,
            "line_count": self.line_count,
            "sensitive_hits": self.sensitive_hits,
            "size_bytes": self.size_bytes,
        }


@dataclass
class CustomRule:
    """A user-defined detection rule with an explicit classification."""

    entity_type: str
    pattern: str
    classification: str = "HIGH"
    strategy: str = "FULL_REDACT"
    note: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "entity_type": self.entity_type,
            "pattern": self.pattern,
            "classification": self.classification,
            "strategy": self.strategy,
            "note": self.note,
        }

    @classmethod
    def from_dict(cls, data: dict[str, Any]) -> CustomRule:
        return cls(
            entity_type=str(data.get("entity_type", "")),
            pattern=str(data.get("pattern", "")),
            classification=str(data.get("classification", "HIGH")),
            strategy=str(data.get("strategy", "FULL_REDACT")),
            note=str(data.get("note", "")),
        )


@dataclass
class Memory:
    """Sanitised cross-session memory."""

    version: int = 1
    theme: str = "dark"
    keep_last_chars: int = 4
    last_policy_id: str = "default"
    recent_files: list[RecentFile] = field(default_factory=list)
    custom_rules: list[CustomRule] = field(default_factory=list)
    entity_stats: dict[str, int] = field(default_factory=dict)
    updated_at: str = ""

    def to_dict(self) -> dict[str, Any]:
        return {
            "version": self.version,
            "theme": self.theme,
            "keep_last_chars": self.keep_last_chars,
            "last_policy_id": self.last_policy_id,
            "recent_files": [r.to_dict() for r in self.recent_files],
            "custom_rules": [r.to_dict() for r in self.custom_rules],
            "entity_stats": dict(self.entity_stats),
            "updated_at": self.updated_at,
        }


class MemoryError(RuntimeError):
    """Raised when the memory store is corrupt or tampered with."""


def _fingerprint(path: str) -> str:
    """Non-reversable marker for a file path (retained anonymised history)."""
    return hashlib.sha256(path.encode("utf-8", "replace")).hexdigest()[:16]


class MemoryManager:
    """Sanitised memory store with integrity verification and erasure."""

    MAX_RECENT = 20

    def __init__(
        self,
        directory: Path | str | None = None,
        *,
        entropy: bytes = b"",
        enable_dpapi: bool | None = None,
    ) -> None:
        self.directory = Path(directory) if directory else DEFAULT_APP_DIR
        self.file = self.directory / "memory.json"
        self.entropy = entropy
        self._enabled = dpapi.dpapi_available if enable_dpapi is None else enable_dpapi
        self.memory = Memory()

    def load(self) -> Memory:
        if not self.file.exists():
            self.memory = Memory()
            return self.memory
        try:
            raw = self.file.read_bytes()
        except OSError as exc:
            raise MemoryError(f"cannot read memory store: {exc}") from exc
        if not raw.startswith(MEMORY_PREFIX + b" "):
            raise MemoryError("memory store has an unknown format")
        first_line, _, rest = raw.partition(b"\n")
        try:
            expected_len = int(first_line.split(b" ", 1)[1])
        except (ValueError, IndexError) as exc:
            raise MemoryError("memory store has a corrupt length prefix") from exc
        hash_line, _, payload = rest.partition(b"\n")
        if len(payload) != expected_len + 1:
            raise MemoryError("memory store is truncated or has extra data")
        payload = payload[:-1]
        if hash_line != hashlib.sha256(MEMORY_PREFIX + payload).hexdigest().encode():
            raise MemoryError("memory store failed integrity verification")
        try:
            doc = json.loads(payload.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise MemoryError(f"memory store is not valid JSON: {exc}") from exc
        if doc.get("safer") != GENUINE:
            raise MemoryError("memory store is missing the marker")
        self.memory = self._from_doc(doc)
        return self.memory

    def save(self) -> Path:
        self.memory.updated_at = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        self.directory.mkdir(parents=True, exist_ok=True)
        doc = self.memory.to_dict()
        doc["safer"] = GENUINE
        payload = json.dumps(doc, indent=2, ensure_ascii=False).encode("utf-8")
        content = (
            MEMORY_PREFIX
            + b" "
            + str(len(payload)).encode()
            + b"\n"
            + hashlib.sha256(MEMORY_PREFIX + payload).hexdigest().encode()
            + b"\n"
            + payload
            + b"\n"
        )
        fd, tmp = tempfile.mkstemp(prefix=".memory-", dir=self.directory)
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(content)
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(tmp, self.file)
        except OSError:
            try:
                Path(tmp).unlink()
            except OSError:
                pass
            raise
        return self.file

    # -- memory mutations -------------------------------------------------

    def remember_file(self, path: str, *, line_count: int = 0, sensitive_hits: int = 0) -> None:
        """Record that a log file was opened (path and safe metadata only)."""
        now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        entry = RecentFile(
            path=str(Path(path).resolve()),
            opened_at=now,
            line_count=max(0, line_count),
            sensitive_hits=max(0, sensitive_hits),
            size_bytes=_size_of(path),
        )
        self.memory.recent_files = [e for e in self.memory.recent_files if e.path != entry.path]
        self.memory.recent_files.insert(0, entry)
        self.memory.recent_files = self.memory.recent_files[: self.MAX_RECENT]

    def record_stats(self, stats: dict[str, int]) -> None:
        """Aggregate sanitised detection statistics (entity types only)."""
        for entity, count in stats.items():
            key = _fingerprint(str(entity))
            self.memory.entity_stats[key] = self.memory.entity_stats.get(key, 0) + int(count)

    def set_preference(self, key: str, value: Any) -> None:
        allowed = {"theme", "keep_last_chars", "last_policy_id"}
        if key in allowed and isinstance(value, (str, int)):
            setattr(self.memory, key, value)

    def add_rule(self, rule: CustomRule) -> None:
        if not rule.entity_type or not rule.pattern:
            raise ValueError("custom rule requires entity_type and pattern")
        self.memory.custom_rules = [
            r for r in self.memory.custom_rules if r.entity_type != rule.entity_type
        ]
        self.memory.custom_rules.append(rule)

    def remove_rule(self, entity_type: str) -> None:
        self.memory.custom_rules = [
            r for r in self.memory.custom_rules if r.entity_type != entity_type
        ]

    def forget_all(self) -> None:
        """Erase all remembered data (right to erasure, GDPR Art. 17)."""
        self.memory = Memory()
        if self.file.exists():
            try:
                self.file.unlink()
            except OSError:
                pass

    # -- helpers ----------------------------------------------------------

    def _from_doc(self, doc: dict[str, Any]) -> Memory:
        mem = Memory()
        mem.version = int(doc.get("version", 1))
        mem.theme = str(doc.get("theme", "dark"))
        mem.keep_last_chars = int(doc.get("keep_last_chars", 4))
        mem.last_policy_id = str(doc.get("last_policy_id", "default"))
        mem.recent_files = [
            RecentFile(
                path=str(r.get("path", "")),
                opened_at=str(r.get("opened_at", "")),
                line_count=int(r.get("line_count", 0)),
                sensitive_hits=int(r.get("sensitive_hits", 0)),
                size_bytes=int(r.get("size_bytes", 0)),
            )
            for r in doc.get("recent_files", [])
            if r.get("path")
        ]
        mem.custom_rules = [CustomRule.from_dict(r) for r in doc.get("custom_rules", [])]
        mem.entity_stats = {str(k): int(v) for k, v in (doc.get("entity_stats") or {}).items()}
        mem.updated_at = str(doc.get("updated_at", ""))
        return mem


def _size_of(path: str) -> int:
    try:
        return Path(path).stat().st_size
    except OSError:
        return 0
