"""Session state machine + export/analysis data structures."""
from __future__ import annotations

import time
from dataclasses import dataclass, field


@dataclass
class Session:
    sid: str
    peer_ip: str
    peer_port: int
    protocol: str
    started: float = field(default_factory=time.time)
    ended: float = 0.0
    signals: list = field(default_factory=list)

    def add_signal(self, kind: str, value) -> None:
        self.signals.append({"kind": kind, "value": value, "ts": round(time.time(), 3)})

    def close(self) -> None:
        self.ended = time.time()

    def to_dict(self) -> dict:
        return {
            "sid": self.sid, "peer_ip": self.peer_ip, "peer_port": self.peer_port,
            "protocol": self.protocol,
            "started": self.started, "ended": self.ended,
            "duration": round(self.ended - self.started, 3),
            "signals": self.signals,
        }