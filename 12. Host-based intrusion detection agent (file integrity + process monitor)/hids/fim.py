"""FIM sensors: reactive (poll-diff) + periodic hasher, scopes, hash list.

Portable reactive watcher: snapshots directory listing at cadence and diffs.
Cross-platform hashing via hashlib with mmap for large files (bounded).
"""
from __future__ import annotations

import hashlib
import json
import os
import time
from pathlib import Path
from typing import Iterator, Optional


class Scope:
    """FIM scope definition (path + mode) per architecture.md 2.1-A."""

    CRITICAL = "critical"
    MONITORED = "monitored"

    def __init__(self, root: Path, mode: str, patterns: list[str]):
        self.root = Path(root)
        self.mode = mode
        self.patterns = patterns  # shell-like globs relative to root

    @classmethod
    def from_dict(cls, d: dict) -> "Scope":
        return cls(Path(d["root"]), d["mode"], d.get("patterns", ["*"]))

    def match(self, rel_path: str) -> bool:
        from fnmatch import fnmatch
        return any(fnmatch(rel_path, p) for p in self.patterns) and not any(
            fnmatch(rel_path, ig) for ig in self.ignores
        )

    @property
    def ignores(self):
        # statically defined ignore list: caches, journals, swap
        return ["*.swp", "*.tmp", "*.pyc", "__pycache__/*", "*.log"]


def load_scopes(path: Path) -> list[Scope]:
    data = json.loads(path.read_text(encoding="utf-8"))
    return [Scope.from_dict(d) for d in data.get("scopes", [])]


def file_sig(path: Path, chunk: int = 1 << 20) -> Optional[dict]:
    """sha256 + size + mtime + mode + owner. Bounded memory (streaming)."""
    try:
        st = path.stat()
        if not path.is_file():
            return None
        h = hashlib.sha256()
        with path.open("rb") as fh:
            while True:
                blk = fh.read(chunk)
                if not blk:
                    break
                h.update(blk)
        owner = ""
        try:
            owner = str(path.owner())
        except Exception:
            owner = "?"
        return {
            "hash": h.hexdigest(),
            "size": st.st_size,
            "mtime": st.st_mtime,
            "mode": f"{st.st_mode:o}",
            "owner": owner,
        }
    except (PermissionError, OSError):
        return None


def iter_scope_files(scope: Scope) -> Iterator[Path]:
    if not scope.root.exists():
        return
    for dirpath, dirnames, filenames in os.walk(scope.root):
        dirnames[:] = [d for d in dirnames if d not in {"__pycache__", ".git"}]
        rd = Path(dirpath)
        for name in filenames:
            p = rd / name
            rel = str(p.relative_to(scope.root))
            if scope.match(rel):
                yield p


class FimEngine:
    """Diffs current fs against BaselineDB; reports changes as findings."""

    def __init__(self, db, scopes: list[Scope], baseline: bool = False):
        self.db = db
        self.scopes = scopes
        self.baseline = baseline  # first-run mode: build baseline, no findings

    def snapshot(self) -> int:
        """One full scan cycle. Returns number of findings raised."""
        findings = 0
        seen: set[str] = set()
        for scope in self.scopes:
            for p in iter_scope_files(scope):
                full = str(p.resolve())
                sig = file_sig(p)
                if sig is None:
                    continue
                old = self.db.get(full)
                if old is None:
                    # New file in monitored scope -> finding
                    if not self.baseline:
                        findings += 1
                        self._emit({"type": "file_new", "path": full, "sig": sig, "mode": scope.mode})
                    self.db.upsert({**sig, "path": full, "snapshot_id": 0,
                                    "ts": str(time.time())})
                    seen.add(full)
                    continue
                if old["hash"] != sig["hash"] or old["size"] != sig["size"]:
                    findings += 1
                    self._emit({"type": "file_changed", "path": full,
                                "mode": scope.mode,
                                "old_hash": old["hash"], "new_hash": sig["hash"],
                                "old_mtime": old.get("mtime"), "new_mtime": sig.get("mtime")})
                self.db.upsert({**sig, "path": full, "snapshot_id": old.get("snapshot_id", 0) + 1,
                                "ts": str(time.time())})
                seen.add(full)
        findings += self._find_deletions(seen)
        return findings

    def _find_deletions(self, present: set[str]) -> int:
        """Emit `file_deleted` for baselined files that vanished from scopes."""
        findings = 0
        scoped_roots = []
        for scope in self.scopes:
            scoped_roots.append(str(scope.root.resolve()))

        for row in self.db.all():
            p = row["path"]
            dir_under_scope = any(
                p == r or p.startswith(r + os.sep) for r in scoped_roots
            )
            if not dir_under_scope:
                continue
            if p in present:
                continue
            if Path(p).exists():
                continue  # still there; probably skipped (ignored pattern)
            findings += 1
            self._emit({"type": "file_deleted", "path": p,
                        "old_hash": row.get("hash"), "mode": "critical"})
            self.db.upsert({**row, "path": p, "snapshot_id": row.get("snapshot_id", 0) + 1,
                            "ts": str(time.time())})
        return findings

    @staticmethod
    def _emit(finding: dict) -> None:
        # Hook point: wired to AlertEmitter in main.py via notify callback.
        import hids.alert as alert
        alert.emit(finding)