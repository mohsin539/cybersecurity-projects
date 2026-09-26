"""Data models shared across the extraction engine."""
from __future__ import annotations

import platform
import socket
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


@dataclass
class BrowserProfile:
    """A single browser profile discovered on the host."""

    browser: str                 # e.g. "Chrome"
    profile: str                 # e.g. "Default"
    root: str                    # profile directory holding the artifacts
    kind: str = "chromium"       # "chromium" | "firefox"
    user_data: str = ""          # parent "User Data" directory
    key_file: Optional[str] = None   # Local State (chromium) / key4.db (firefox)
    available: Dict[str, str] = field(default_factory=dict)  # artifact -> path
    installed: bool = True

    @property
    def label(self) -> str:
        return f"{self.browser} - {self.profile}"

    def to_dict(self) -> Dict[str, Any]:
        d = asdict(self)
        d["label"] = self.label
        return d


@dataclass
class EvidenceItem:
    """One collected artifact record plus chain-of-custody metadata."""

    category: str                # history / cookies / cache / downloads / ...
    source_path: str
    source_sha256: str
    collected_at: str = field(default_factory=_now_iso)
    record_count: int = 0
    notes: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    """Aggregate result of a collection run."""

    scan_id: str
    started_at: str
    finished_at: str = ""
    host: str = field(default_factory=lambda: socket.gethostname())
    platform: str = field(default_factory=lambda: platform.platform())
    operator: str = ""
    case_ref: str = ""
    authorize_reference: str = ""
    browsers: List[BrowserProfile] = field(default_factory=list)
    artifacts: Dict[str, List[Dict[str, Any]]] = field(default_factory=dict)
    evidence: List[EvidenceItem] = field(default_factory=list)
    errors: List[str] = field(default_factory=list)
    statistics: Dict[str, Any] = field(default_factory=dict)
    integrity: Dict[str, Any] = field(default_factory=dict)

    def finish(self) -> None:
        self.finished_at = _now_iso()

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scan_id": self.scan_id,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "host": self.host,
            "platform": self.platform,
            "operator": self.operator,
            "case_ref": self.case_ref,
            "authorize_reference": self.authorize_reference,
            "browsers": [b.to_dict() for b in self.browsers],
            "artifacts": self.artifacts,
            "evidence": [e.to_dict() for e in self.evidence],
            "errors": self.errors,
            "statistics": self.statistics,
            "integrity": self.integrity,
        }


@dataclass
class ScanOptions:
    """User-selected collection options."""

    categories: List[str] = field(default_factory=lambda: [
        "history", "downloads", "cookies", "bookmarks",
        "autofill", "logins", "search_terms", "cache",
    ])
    profile_filter: List[str] = field(default_factory=list)  # subset of profile labels
    decrypt_secrets: bool = False   # decrypt cookie values / passwords
    extract_cache_urls: bool = True
    max_records_per_category: int = 0   # 0 = unlimited

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
