"""Core data models (architecture.md §7).

All results are immutable events; mutable aggregation lives in the store only.
"""
from __future__ import annotations

import enum
import time
from dataclasses import dataclass, field
from typing import Optional


class Proto(enum.StrEnum):
    TCP = "tcp"
    UDP = "udp"


class PortState(enum.StrEnum):
    OPEN = "open"
    CLOSED = "closed"
    FILTERED = "filtered"
    OPEN_FILTERED = "open|filtered"
    CLOSED_FILTERED = "closed|filtered"
    UNREACHABLE = "unreachable"

    @classmethod
    def inconclusive(cls) -> tuple["PortState", ...]:
        """States eligible for retry (architecture.md §8)."""
        return (cls.FILTERED, cls.OPEN_FILTERED, cls.CLOSED_FILTERED, cls.UNREACHABLE)


@dataclass(frozen=True)
class Target:
    ip: str
    hostname: str = ""


@dataclass
class ProbeJob:
    target: Target
    port: int
    proto: Proto = Proto.TCP
    attempt: int = 0


@dataclass
class Evidence:
    """What was actually observed — required for a state to be asserted."""
    errno: Optional[int] = None
    icmp_type: Optional[int] = None
    icmp_code: Optional[int] = None
    detail: str = ""

    def to_dict(self) -> dict:
        return {
            "errno": self.errno,
            "icmp_type": self.icmp_type,
            "icmp_code": self.icmp_code,
            "detail": self.detail[:512],  # bounded (security.md: input limits)
        }


@dataclass
class PortResult:
    host: str
    hostname: str
    port: int
    proto: Proto
    state: PortState
    engine: str
    attempt: int
    rtt_ms: float = 0.0
    evidence: Evidence = field(default_factory=Evidence)
    ts: float = field(default_factory=time.time)

    def key(self) -> tuple[str, str, int]:
        return (self.host, str(self.proto), self.port)

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "type": "port_result",
            "host": self.host,
            "hostname": self.hostname,
            "port": self.port,
            "proto": str(self.proto),
            "state": str(self.state),
            "engine": self.engine,
            "attempt": self.attempt,
            "rtt_ms": round(self.rtt_ms, 3),
            "evidence": self.evidence.to_dict(),
            "ts": self.ts,
        }


@dataclass
class TLSInfo:
    subject: str = ""
    issuer: str = ""
    sans: list[str] = field(default_factory=list)
    not_after: str = ""


@dataclass
class ServiceResult:
    host: str
    port: int
    proto: Proto
    service: str = "unknown"
    product: str = ""
    version: str = ""
    banner: str = ""          # sanitized before entering here (security.py)
    confidence: float = 0.0
    tls: Optional[TLSInfo] = None

    def to_dict(self) -> dict:
        return {
            "schema_version": SCHEMA_VERSION,
            "type": "service",
            "host": self.host,
            "port": self.port,
            "proto": str(self.proto),
            "service": self.service,
            "product": self.product,
            "version": self.version,
            "banner": self.banner,
            "confidence": round(self.confidence, 2),
            "tls": vars(self.tls) if self.tls else None,
        }


SCHEMA_VERSION = 1
