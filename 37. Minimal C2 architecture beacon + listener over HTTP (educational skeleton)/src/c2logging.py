"""Secure logging + append-only audit trail.

ISO 27001 A.12.4 (logging & monitoring), NIST SP 800-53 AU family,
OWASP A09 (security logging & monitoring).

Both console and tool surface a log queue so the GUI can render a live,
color-coded console without threading hazards.
"""
import json
import logging
import logging.handlers
import os
import threading
import queue
from datetime import datetime, timezone


class QueueLogHandler(logging.Handler):
    """Feed log records into a thread-safe queue for the GUI console."""

    def __init__(self, log_queue: "queue.Queue"):
        super().__init__()
        self.log_queue = log_queue

    def emit(self, record):
        try:
            entry = self.format(record)
            self.log_queue.put_nowait((record.levelno, entry))
        except Exception:
            pass


def setup_logging(log_dir: str) -> tuple[logging.Logger, "queue.Queue"]:
    os.makedirs(log_dir, exist_ok=True)
    logger = logging.getLogger("c2studylab")
    logger.setLevel(logging.DEBUG)
    logger.handlers.clear()

    fmt = logging.Formatter(
        "%(asctime)s.%(msecs)03d | %(levelname)-7s | %(name)s | %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    rotating = logging.handlers.TimedRotatingFileHandler(
        os.path.join(log_dir, "session.log"),
        when="midnight",
        backupCount=30,
        encoding="utf-8",
    )
    rotating.setFormatter(fmt)
    rotating.setLevel(logging.DEBUG)

    stream = logging.StreamHandler()
    stream.setFormatter(fmt)
    stream.setLevel(logging.INFO)

    log_queue: "queue.Queue" = queue.Queue(maxsize=2000)
    qhandler = QueueLogHandler(log_queue)
    qhandler.setFormatter(logging.Formatter("%(asctime)s | %(levelname)-7s | %(message)s"))

    logger.addHandler(rotating)
    logger.addHandler(stream)
    logger.addHandler(qhandler)
    logger.propagate = False
    return logger, log_queue


class AuditLog:
    """Append-only JSONL audit trail (append is the ONLY operation)."""

    def __init__(self, path: str):
        os.makedirs(os.path.dirname(path), exist_ok=True)
        self.path = path
        self._lock = threading.Lock()
        self._events: list[dict] = []  # in-memory mirror for live GUI

    def record(self, event, actor, subject, severity="info", detail=None) -> dict:
        rec = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "event": event,
            "actor": actor,
            "subject": subject,
            "severity": severity,
            "detail": detail or {},
        }
        with self._lock:
            with open(self.path, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(rec) + "\n")
            self._events.append(rec)
            if len(self._events) > 2000:
                self._events = self._events[-2000:]
        return rec

    def read_all(self) -> list[dict]:
        with self._lock:
            return list(self._events)

    def read_disk(self) -> list[dict]:
        rows = []
        try:
            with open(self.path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            rows.append(json.loads(line))
                        except json.JSONDecodeError:
                            continue
        except FileNotFoundError:
            pass
        return rows