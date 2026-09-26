from __future__ import annotations

import csv
import io
import json
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable, Iterator

from ..config import ScanOptions
from ..models import CollectionResult, Severity, SourceType, TimeKind, TimelineEvent
from ..security.validation import validate_source_path
from .base import BaseCollector, CollectorContext

LOG_EXTENSIONS = {
    ".log",
    ".txt",
    ".json",
    ".jsonl",
    ".ndjson",
    ".csv",
    ".tsv",
    ".evtx",
    ".evt",
    ".out",
    ".err",
    ".trace",
}

TS_KEYS = (
    "@timestamp",
    "timestamp",
    "time",
    "datetime",
    "date",
    "eventtime",
    "utc_time",
    "event_time",
    "timecreated",
    "occurred_at",
    "ts",
)

LEVEL_KEYS = ("level", "severity", "loglevel", "log_level", "priority", "eventlevel", "type")
MSG_KEYS = ("message", "msg", "description", "event", "text", "body", "summary", "raw", "data")
USER_KEYS = ("user", "username", "account", "accountname", "user_name", "subjectusername", "targetusername")
HOST_KEYS = ("host", "hostname", "computer", "computername", "machine", "source_host")

SEVERITY_WORDS = (
    (Severity.CRITICAL, ("critical", "fatal", "emergency", "panic", "severe")),
    (Severity.HIGH, ("error", "failed", "failure", "denied", "unauthorized", "attack", "malware", "exploit", "blocked")),
    (Severity.MEDIUM, ("warn", "warning", "deprecated", "retry", "timeout", "suspicious", "invalid")),
    (Severity.LOW, ("notice", "debug", "trace", "verbose")),
)

LEVEL_MAP = {
    "critical": Severity.CRITICAL,
    "fatal": Severity.CRITICAL,
    "emerg": Severity.CRITICAL,
    "alert": Severity.HIGH,
    "error": Severity.HIGH,
    "err": Severity.HIGH,
    "high": Severity.HIGH,
    "warning": Severity.MEDIUM,
    "warn": Severity.MEDIUM,
    "medium": Severity.MEDIUM,
    "notice": Severity.LOW,
    "info": Severity.INFO,
    "information": Severity.INFO,
    "low": Severity.LOW,
    "debug": Severity.LOW,
    "trace": Severity.LOW,
}

TS_PATTERNS = (
    re.compile(r"(?P<ts>\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d{1,7})?(?:Z|[+-]\d{2}:?\d{2})?)"),
    re.compile(r"(?P<ts>\d{2}/\d{2}/\d{4}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"),
    re.compile(r"(?P<ts>\d{4}/\d{2}/\d{2}[ T]\d{2}:\d{2}:\d{2}(?:[.,]\d+)?)"),
    re.compile(r"(?P<ts>[A-Z][a-z]{2}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2})"),
)

STRPTIME_FORMATS = (
    "%Y-%m-%dT%H:%M:%S.%f%z",
    "%Y-%m-%dT%H:%M:%S%z",
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S",
    "%Y-%m-%d %H:%M",
    "%Y/%m/%d %H:%M:%S",
    "%Y/%m/%d %H:%M",
    "%m/%d/%Y %H:%M:%S",
    "%m/%d/%Y %H:%M",
    "%d/%m/%Y %H:%M:%S",
    "%d-%m-%Y %H:%M:%S",
    "%Y%m%d%H%M%S",
)


def _host() -> str:
    try:
        return socket.gethostname()
    except OSError:
        return ""


def _clean_number(value: str) -> str:
    return value.replace(",", ".")


def parse_timestamp(value: Any) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, datetime):
        return value if value.tzinfo else value.replace(tzinfo=timezone.utc)
    if isinstance(value, (int, float)):
        seconds = float(value)
        if seconds > 1e12:
            seconds /= 1000.0
        try:
            return datetime.fromtimestamp(seconds, tz=timezone.utc)
        except (OverflowError, OSError, ValueError):
            return None
    text = str(value).strip()
    if not text:
        return None
    text = _clean_number(text)
    if text.endswith("Z"):
        text = text[:-1] + "+00:00"
    try:
        parsed = datetime.fromisoformat(text)
        return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
    except ValueError:
        pass
    match = re.match(r".*?([+-]\d{2})(\d{2})$", text)
    if match:
        candidate = text[: match.start(1)] + match.group(1) + ":" + match.group(2)
        try:
            parsed = datetime.fromisoformat(candidate)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            pass
    for fmt in STRPTIME_FORMATS:
        try:
            parsed = datetime.strptime(text, fmt)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            continue
    match = re.match(r"(?P<mon>[A-Z][a-z]{2})\s+(?P<day>\d{1,2})\s+(?P<time>\d{2}:\d{2}:\d{2})", text)
    if match:
        year = datetime.now(timezone.utc).year
        try:
            parsed = datetime.strptime(f"{year} {match.group('mon')} {match.group('day')} {match.group('time')}", "%Y %b %d %H:%M:%S")
            return parsed.replace(tzinfo=timezone.utc)
        except ValueError:
            return None
    return None


def infer_severity(text: str, default: Severity = Severity.INFO) -> Severity:
    lowered = (text or "").lower()
    for severity, words in SEVERITY_WORDS:
        if any(word in lowered for word in words):
            return severity
    return default


def severity_from_level(level: Any) -> Severity | None:
    if level is None:
        return None
    key = str(level).strip().lower()
    if key in LEVEL_MAP:
        return LEVEL_MAP[key]
    try:
        numeric = int(key)
    except ValueError:
        return None
    if numeric <= 1:
        return Severity.CRITICAL
    if numeric <= 3:
        return Severity.HIGH
    if numeric == 4:
        return Severity.MEDIUM
    if numeric <= 6:
        return Severity.INFO
    return Severity.LOW


def _flatten(mapping: dict[str, Any], prefix: str = "") -> dict[str, Any]:
    flat: dict[str, Any] = {}
    for key, value in mapping.items():
        name = f"{prefix}{key}".lower()
        if isinstance(value, dict):
            flat.update(_flatten(value, prefix=f"{name}"))
        else:
            flat[name] = value
    return flat


def _first(flat: dict[str, Any], keys: Iterable[str]) -> Any:
    for key in keys:
        if key in flat and flat[key] not in (None, ""):
            return flat[key]
    return None


def detect_format(path: str | Path) -> str:
    suffix = Path(path).suffix.lower()
    if suffix == ".evtx" or suffix == ".evt":
        return "evtx"
    if suffix == ".json":
        return "json"
    if suffix in (".jsonl", ".ndjson"):
        return "jsonl"
    if suffix == ".csv":
        return "csv"
    if suffix == ".tsv":
        return "tsv"
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            sample = handle.read(4096).lstrip()
    except OSError:
        return "text"
    if sample.startswith("{") and "\n{" in sample:
        return "jsonl"
    if sample.startswith("[") or sample.startswith("{"):
        return "json"
    first_line = sample.splitlines()[0] if sample.splitlines() else ""
    if first_line.count(",") >= 3 and re.search(r",\s*[A-Za-z_]", first_line):
        return "csv"
    if first_line.count("\t") >= 2:
        return "tsv"
    return "text"


class LogCollector(BaseCollector):
    name = "logs"
    source_type = SourceType.LOG

    def __init__(self, root, options: ScanOptions | None = None, host: str = "", format_hint: str | None = None, audit=None):
        super().__init__(root, audit=audit)
        self.options = options or ScanOptions()
        self.host = host or _host()
        self.format_hint = format_hint

    def _make_event(self, flat: dict[str, Any], path: Path, fmt: str, host: str) -> TimelineEvent | None:
        timestamp = parse_timestamp(_first(flat, TS_KEYS))
        if timestamp is None:
            return None
        message = _first(flat, MSG_KEYS)
        if isinstance(message, (dict, list)):
            message = json.dumps(message, ensure_ascii=False, default=str)
        description = str(message).strip() if message else json.dumps(flat, ensure_ascii=False, default=str)
        severity = severity_from_level(_first(flat, LEVEL_KEYS))
        if severity is None:
            severity = infer_severity(description) if self.options.infer_severity else Severity.INFO
        user = _first(flat, USER_KEYS)
        event_host = _first(flat, HOST_KEYS) or host
        return TimelineEvent(
            timestamp=timestamp,
            source_type=SourceType.LOG,
            source_path=str(path),
            description=description[:4000],
            time_kind=TimeKind.EVENT,
            host=str(event_host or ""),
            user=str(user or ""),
            severity=severity,
            tags=["log", fmt],
            raw={"fields": {k: str(v) for k, v in list(flat.items())[:80]}},
        )

    def _read_jsonl(self, path: Path, host: str) -> Iterator[TimelineEvent]:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                line = line.strip()
                if not line:
                    continue
                try:
                    payload = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if not isinstance(payload, dict):
                    continue
                event = self._make_event(_flatten(payload), path, "jsonl", host)
                if event is not None:
                    yield event

    def _read_json(self, path: Path, host: str) -> Iterator[TimelineEvent]:
        try:
            payload = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except (json.JSONDecodeError, OSError):
            for event in self._read_jsonl(path, host):
                yield event
            return
        records = payload if isinstance(payload, list) else payload.get("events", [payload]) if isinstance(payload, dict) else []
        for record in records:
            if not isinstance(record, dict):
                continue
            event = self._make_event(_flatten(record), path, "json", host)
            if event is not None:
                yield event

    def _read_delimited(self, path: Path, fmt: str, host: str) -> Iterator[TimelineEvent]:
        delimiter = "\t" if fmt == "tsv" else ","
        with open(path, "r", encoding="utf-8", errors="replace", newline="") as handle:
            sample = handle.read(8192)
            handle.seek(0)
            try:
                dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
                delimiter = dialect.delimiter
            except csv.Error:
                pass
            reader = csv.DictReader(handle, delimiter=delimiter)
            for record in reader:
                flat = {str(k).lower(): v for k, v in record.items() if k}
                event = self._make_event(flat, path, fmt, host)
                if event is not None:
                    yield event

    def _read_evtx(self, path: Path, host: str) -> Iterator[TimelineEvent]:
        try:
            from Evtx.Evtx import Evtx
        except Exception:
            raise RuntimeError("python-evtx is not installed (pip install python-evtx)")
        with Evtx(str(path)) as log:
            for record in log.records():
                try:
                    xml = record.xml()
                except Exception:
                    continue
                yield from self._events_from_evtx_xml(xml, path, host)

    def _events_from_evtx_xml(self, xml: str, path: Path, host: str) -> Iterator[TimelineEvent]:
        import xml.etree.ElementTree as ET

        try:
            root = ET.fromstring(xml)
        except ET.ParseError:
            return
        ns = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
        system = root.find("e:System", ns)
        event_data = root.find("e:EventData", ns)
        timestamp = None
        flat: dict[str, Any] = {"source": "evtx"}
        if system is not None:
            time_created = system.find("e:TimeCreated", ns)
            if time_created is not None:
                timestamp = time_created.get("SystemTime")
            for tag in ("EventID", "Computer", "Channel", "Level"):
                node = system.find(f"e:{tag}", ns)
                if node is not None and node.text:
                    flat[tag.lower()] = node.text
            provider = system.find("e:Provider", ns)
            if provider is not None:
                flat["provider"] = provider.get("Name")
            security = system.find("e:Security", ns)
            if security is not None:
                flat["user"] = security.get("UserID") or ""
        if event_data is not None:
            for data in event_data.findall("e:Data", ns):
                name = data.get("Name")
                if name:
                    flat[name.lower()] = data.text
        flat.setdefault("level", flat.get("level", "info"))
        if timestamp:
            flat["timestamp"] = timestamp
        event = self._make_event(flat, path, "evtx", host)
        if event is not None:
            yield event

    def _read_text(self, path: Path, host: str) -> Iterator[TimelineEvent]:
        with open(path, "r", encoding="utf-8", errors="replace") as handle:
            for line in handle:
                stripped = line.strip()
                if not stripped:
                    continue
                for pattern in TS_PATTERNS:
                    match = pattern.search(stripped)
                    if not match:
                        continue
                    timestamp = parse_timestamp(match.group("ts"))
                    if timestamp is None:
                        continue
                    remainder = stripped[match.end():].strip(" -|:\t")
                    severity = infer_severity(stripped) if self.options.infer_severity else Severity.INFO
                    yield TimelineEvent(
                        timestamp=timestamp,
                        source_type=SourceType.LOG,
                        source_path=str(path),
                        description=remainder[:4000] or stripped[:4000],
                        time_kind=TimeKind.EVENT,
                        host=host,
                        severity=severity,
                        tags=["log", "text"],
                        raw={"line": stripped[:4000]},
                    )
                    break

    def _collect_file(self, path: Path, ctx: CollectorContext) -> CollectionResult:
        result = CollectionResult()
        result.sources.append(str(path))
        fmt = self.format_hint or detect_format(path)
        try:
            size = path.stat().st_size
        except OSError as exc:
            result.errors.append(f"{path}: {exc}")
            return result
        if size > self.options.log_max_file_bytes:
            result.errors.append(f"{path}: exceeds max size ({size} bytes)")
            return result
        self._audit("collect.file", target=str(path), format=fmt, size=size)
        try:
            if fmt == "evtx":
                events = self._read_evtx(path, self.host)
            elif fmt == "jsonl":
                events = self._read_jsonl(path, self.host)
            elif fmt == "json":
                events = self._read_json(path, self.host)
            elif fmt in ("csv", "tsv"):
                events = self._read_delimited(path, fmt, self.host)
            else:
                events = self._read_text(path, self.host)
            count = 0
            for event in events:
                if ctx.cancelled():
                    break
                result.events.append(event)
                count += 1
                if count % 5000 == 0:
                    ctx.report(count, None)
            result.files_seen += 1
            result.bytes_seen += size
        except Exception as exc:
            result.errors.append(f"{path}: {exc}")
        return result

    def collect(self, context: CollectorContext | None = None) -> CollectionResult:
        ctx = context or CollectorContext()
        result = CollectionResult()
        root = validate_source_path(self.root)
        self._audit("collect.start", target=str(root), collector=self.name)

        if root.is_file():
            files = [root]
        else:
            files = [
                Path(path)
                for path in sorted(
                    str(p)
                    for p in root.rglob("*")
                    if p.is_file() and p.suffix.lower() in LOG_EXTENSIONS
                )
            ]

        for index, path in enumerate(files, start=1):
            if ctx.cancelled():
                result.errors.append("cancelled by user")
                break
            ctx.report(index, len(files))
            result.extend(self._collect_file(path, ctx))

        self._audit(
            "collect.complete",
            target=str(root),
            collector=self.name,
            events=len(result.events),
            files=len(files),
            errors=len(result.errors),
        )
        return result
