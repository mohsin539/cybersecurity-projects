from __future__ import annotations

import fnmatch
import os
import socket
from datetime import datetime, timezone
from pathlib import Path

from ..config import ScanOptions
from ..models import CollectionResult, Severity, SourceType, TimeKind, TimelineEvent
from ..security.hashing import sha256_file
from ..security.validation import validate_source_path
from .base import BaseCollector, CollectorContext

DEFAULT_EXCLUDES = (
    "$recycle.bin",
    "system volume information",
    "pagefile.sys",
    "hiberfil.sys",
    "swapfile.sys",
    "__pycache__",
)


def _host() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return ""


def _owner(path: str) -> str:
    try:
        import pwd

        return pwd.getpwuid(os.stat(path).st_uid).pw_name
    except Exception:
        return ""


class FilesystemCollector(BaseCollector):
    name = "filesystem"
    source_type = SourceType.FILESYSTEM

    def __init__(
        self,
        root,
        options: ScanOptions | None = None,
        host: str = "",
        exclude_dirs=DEFAULT_EXCLUDES,
        include_globs: tuple[str, ...] = (),
        audit=None,
    ):
        super().__init__(root, audit=audit)
        self.options = options or ScanOptions()
        self.host = host or _host()
        self.exclude_dirs = tuple(d.lower() for d in exclude_dirs)
        self.include_globs = tuple(include_globs)

    def _included(self, name: str) -> bool:
        if not self.include_globs:
            return True
        return any(fnmatch.fnmatch(name.lower(), pattern.lower()) for pattern in self.include_globs)

    def _stat_events(self, path: Path, stat_result) -> list[TimelineEvent]:
        opts = self.options
        events: list[TimelineEvent] = []
        is_windows = os.name == "nt"

        created_ts = getattr(stat_result, "st_birthtime", None)
        if created_ts is None and is_windows:
            created_ts = stat_result.st_ctime
        changed_ts = None if is_windows else stat_result.st_ctime

        common = {
            "size": stat_result.st_size,
            "host": self.host,
            "user": _owner(str(path)),
        }

        digest = ""
        if opts.compute_hashes and stat_result.st_size <= opts.hash_max_bytes:
            try:
                digest = sha256_file(path, max_bytes=opts.hash_max_bytes)
            except OSError:
                digest = ""

        def add(kind: TimeKind, timestamp: float | None, label: str) -> None:
            if timestamp is None:
                return
            events.append(
                TimelineEvent(
                    timestamp=datetime.fromtimestamp(timestamp, tz=timezone.utc),
                    source_type=SourceType.FILESYSTEM,
                    source_path=str(path),
                    description=f"{label}: {path.name}",
                    time_kind=kind,
                    severity=Severity.INFO,
                    sha256=digest,
                    tags=["filesystem", kind.value],
                    raw={"mode": stat_result.st_mode, "inode": stat_result.st_ino},
                    **common,
                )
            )

        if opts.collect_created:
            add(TimeKind.CREATED, created_ts, "Created")
        if opts.collect_modified:
            add(TimeKind.MODIFIED, stat_result.st_mtime, "Modified")
        if opts.collect_accessed:
            add(TimeKind.ACCESSED, stat_result.st_atime, "Accessed")
        if opts.collect_changed:
            add(TimeKind.CHANGED, changed_ts, "Changed")
        return events

    def collect(self, context: CollectorContext | None = None) -> CollectionResult:
        ctx = context or CollectorContext()
        result = CollectionResult()
        root = validate_source_path(self.root)
        result.sources.append(str(root))
        self._audit("collect.start", target=str(root), collector=self.name)

        options = self.options
        if root.is_file():
            targets = [(str(root), 0)]
        else:
            targets = list(self._walk(root, options.max_depth, ctx))

        for index, (path_str, _depth) in enumerate(targets, start=1):
            if ctx.cancelled():
                result.errors.append("cancelled by user")
                break
            ctx.report(index, len(targets))
            try:
                stat_result = os.stat(path_str, follow_symlinks=options.follow_symlinks)
            except OSError as exc:
                result.errors.append(f"{path_str}: {exc}")
                continue
            result.files_seen += 1
            result.bytes_seen += int(stat_result.st_size)
            if len(result.events) >= options.max_events:
                result.errors.append(f"max_events limit ({options.max_events}) reached")
                break
            result.events.extend(self._stat_events(Path(path_str), stat_result))

        self._audit(
            "collect.complete",
            target=str(root),
            collector=self.name,
            events=len(result.events),
            files=result.files_seen,
            errors=len(result.errors),
        )
        return result

    def _walk(self, root: Path, max_depth: int, ctx: CollectorContext):
        stack: list[tuple[Path, int]] = [(root, 0)]
        while stack:
            current, depth = stack.pop()
            if ctx.cancelled():
                return
            if depth > max_depth:
                continue
            try:
                with os.scandir(current) as entries:
                    for entry in entries:
                        try:
                            if entry.is_dir(follow_symlinks=self.options.follow_symlinks):
                                if entry.name.lower() in self.exclude_dirs:
                                    continue
                                if self.options.include_hidden or not entry.name.startswith("."):
                                    stack.append((Path(entry.path), depth + 1))
                            elif entry.is_file(follow_symlinks=self.options.follow_symlinks):
                                if self._included(entry.name):
                                    yield entry.path, depth
                        except OSError:
                            continue
            except OSError:
                continue
