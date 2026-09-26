"""Capture session runner (architecture §5.1 / §6).

Creates a session in the store, feeds it events from a driver (trace
replay or synthetic generator), enforces timeout + event caps from policy,
and finalizes the session. The ETW/hook engine will attach here in v1.1.
"""

from __future__ import annotations

import threading
import time
import uuid
from dataclasses import dataclass, field

from ..registry import SchemaRegistry

CATEGORIES = {"File", "Registry", "Network", "Process", "Thread", "Crypto",
              "Memory", "IPC", "Exception", "Other"}
STATUSES = {"SUCCESS", "FAIL", "TIMEOUT", "UNKNOWN"}


@dataclass
class TraceEvent:
    api: str
    category: str
    args: dict
    ret: str
    tid: int = 1
    pid: int = 1
    ts_ns: int | None = None
    status: str = "SUCCESS"
    parent_seq: int | None = None
    tags: list[str] = field(default_factory=list)
    module: str = ""

    def to_dict(self, seq: int) -> dict:
        problems = SchemaRegistry.validate_event({
            "seq": seq, "ts_ns": self.ts_ns or 0, "tid": self.tid, "pid": self.pid,
            "category": self.category, "api": self.api, "ret": self.ret,
        })
        if problems:
            raise ValueError(f"invalid event {self.api}: {'; '.join(problems)}")
        return {
            "seq": seq, "ts_ns": self.ts_ns or 0, "pid": self.pid, "tid": self.tid,
            "category": self.category, "api": self.api, "module": self.module,
            "args": self.args, "ret": self.ret, "status": self.status,
            "parent_seq": self.parent_seq, "tags": list(self.tags),
        }


class RunnerState:
    DISPOSED = "disposed"


class CaptureRunner:
    def __init__(self, store, audit, policy, redaction) -> None:
        self.store = store
        self.audit = audit
        self.policy = policy
        self.redaction = redaction
        self.pid_count = {1: 0}
        self._lock = threading.Lock()
        self._running_batches: dict[str, list[dict]] = {}

    # ------------------------------------------------------------------ run
    def run_trace(self, session_id: str, events: list[TraceEvent],
                  driver_meta: dict | None = None) -> int:
        session = self.store.get_session(session_id)
        max_events = int(self.policy.max_events_per_session)
        started = session["started_at"]
        t_start = time.monotonic()
        seq_acc = self.store.get_kv(f"seq:{session_id}").split(",") or []
        base_seq = int(seq_acc[0]) if seq_acc and seq_acc[0] else self.store.event_count(
            session_id)
        written = 0
        pending: list[dict] = []
        for raw in events:
            if written >= max_events:
                break
            if self.policy.capture_timeout_seconds and \
                    (time.monotonic() - t_start) > self.policy.capture_timeout_seconds:
                break
            base_seq += 1
            ev = raw.to_dict(base_seq)
            ev["ts_ns"] = started + written * 500_000  # 0.5 ms spacing
            ev["args"] = self.redaction.redact_json(ev.get("args", {}))
            pending.append(ev)
            written += 1
            if len(pending) >= 5000:
                self.store.insert_events(session_id, pending)
                pending = []
        if pending:
            self.store.insert_events(session_id, pending)
        if written >= max_events:
            self.store.set_kv(f"seq:{session_id}", "cap-reached")
        self.store.finish_session(session_id, "completed")
        self.audit.record("SESSION_STOP", {
            "session_id": session_id, "events": written,
            "driver": (driver_meta or {}).get("kind", "trace"),
        })
        return written

    @classmethod
    def new_session_id(cls) -> str:
        return uuid.uuid4().hex[:16]

    def create_session(self, sample_id: int, sandbox: str = "offline_replay") -> str:
        sid = self.new_session_id()
        self.store.create_session(sid, sample_id, self.policy.snapshot_hash, sandbox)
        self.audit.record("SESSION_START", {"session_id": sid, "sample_id": sample_id,
                                            "sandbox": sandbox})
        return sid