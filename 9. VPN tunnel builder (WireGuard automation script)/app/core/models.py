"""Domain models (ISO 27001 A.8.12 — data classified; secrets never inline)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _obj(record: dict, fields: list[str]) -> dict:
    return {k: record[k] for k in fields if k in record}


@dataclass
class Peer:
    id: str
    tunnel: str
    name: str
    public_key: str
    allowed_ips: list[str]
    endpoint: str = ""
    persistent_keepalive: int = 0
    preshared: bool = False
    notes: str = ""
    enabled: bool = True
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    _SERIAL = [
        "id", "tunnel", "name", "public_key", "allowed_ips", "endpoint",
        "persistent_keepalive", "preshared", "notes", "enabled",
        "created_at", "updated_at",
    ]

    def to_dict(self) -> dict:
        return _obj(asdict(self), self._SERIAL)

    @classmethod
    def from_dict(cls, d: dict) -> Peer:
        return cls(**{k: d[k] for k in cls._SERIAL if k in d})


@dataclass
class Tunnel:
    name: str
    interface: str
    role: str = "server"              # server | client
    listen_port: int = 51820
    addresses: list[str] = field(default_factory=list)
    keypair_id: str = ""
    mtu: int | None = None
    fwmark: str = ""
    dns: list[str] = field(default_factory=list)
    enabled: bool = True
    created_at: str = field(default_factory=_now)
    updated_at: str = field(default_factory=_now)

    _SERIAL = [
        "name", "interface", "role", "listen_port", "addresses",
        "keypair_id", "mtu", "fwmark", "dns", "enabled",
        "created_at", "updated_at",
    ]

    def to_dict(self) -> dict:
        return _obj(asdict(self), self._SERIAL)

    @classmethod
    def from_dict(cls, d: dict) -> Tunnel:
        return cls(**{k: d[k] for k in cls._SERIAL if k in d})


@dataclass
class KeyPair:
    id: str
    kind: str                 # tunnel | peer
    public_key: str
    note: str = ""
    created_at: str = field(default_factory=_now)

    _SERIAL = ["id", "kind", "public_key", "note", "created_at"]

    def to_dict(self) -> dict:
        return _obj(asdict(self), self._SERIAL)

    @classmethod
    def from_dict(cls, d: dict) -> KeyPair:
        return cls(**{k: d[k] for k in cls._SERIAL if k in d})


@dataclass
class AuditEvent:
    action: str
    actor: str
    session: str
    target: str
    result: str
    detail: str
    prev_hash: str
    event_hash: str
    ts: str = field(default_factory=_now)

    _SERIAL = ["ts", "action", "actor", "session", "target", "result",
               "detail", "prev_hash", "event_hash"]

    def to_dict(self) -> dict:
        return _obj(asdict(self), self._SERIAL)

    @classmethod
    def from_dict(cls, d: dict) -> AuditEvent:
        return cls(**{k: d[k] for k in cls._SERIAL if k in d})


@dataclass
class Snapshot:
    id: str
    ts: str
    path: str
    sha256: str
    size: int

    _SERIAL = ["id", "ts", "path", "sha256", "size"]

    def to_dict(self) -> dict:
        return _obj(asdict(self), self._SERIAL)

    @classmethod
    def from_dict(cls, d: dict) -> Snapshot:
        return cls(**{k: d[k] for k in cls._SERIAL if k in d})