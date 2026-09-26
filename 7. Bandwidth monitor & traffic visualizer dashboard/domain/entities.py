"""Domain entities for network telemetry.

These classes are intentionally free of any framework / OS dependency so the
core business model can be reasoned about, versioned and unit tested in
isolation (Clean Architecture: inner layer).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional


@dataclass(frozen=True)
class RateSample:
    """A cumulative counter reading captured at a point in time."""

    timestamp: float  # epoch seconds
    bytes_sent: int
    bytes_recv: int
    packets_sent: int = 0
    packets_recv: int = 0
    errors_in: int = 0
    errors_out: int = 0
    drops_in: int = 0
    drops_out: int = 0


@dataclass(frozen=True)
class InterfaceTraffic:
    """Per-interface instantaneous throughput derived between two samples."""

    name: str
    download_rate: float  # bytes / second (ingress)
    upload_rate: float  # bytes / second (egress)
    counters: RateSample


@dataclass(frozen=True)
class Snapshot:
    """A complete picture of network activity at a given instant."""

    timestamp: float
    interfaces: Dict[str, InterfaceTraffic]
    total_download: float  # bytes / second
    total_upload: float  # bytes / second
    total_counters: RateSample


@dataclass(frozen=True)
class NetworkInterfaceInfo:
    """Fixed metadata describing a detected network interface."""

    name: str
    is_up: bool
    is_running: bool
    mac_address: Optional[str]
    addresses: List[str] = field(default_factory=list)
    speed_mbps: Optional[int] = None
    is_virtual: bool = False


@dataclass(frozen=True)
class ConnectionInfo:
    """One observed socket / connection."""

    process_name: Optional[str]
    pid: Optional[int]
    protocol: str  # "tcp" | "udp"
    family: str  # "ipv4" | "ipv6"
    state: Optional[str]
    local: str  # "ip:port" or ""
    remote: str  # "ip:port" or ""
    fd: Optional[int] = None


@dataclass(frozen=True)
class ConnectionSummary:
    """Aggregated view over the connections currently visible."""

    total: int
    by_state: Dict[str, int]
    by_protocol: Dict[str, int]
    by_process: Dict[str, int]
    samples: List[ConnectionInfo]


@dataclass(frozen=True)
class Alert:
    severity: str  # "warning" | "critical"
    source: str
    message: str
    timestamp: float
    value_bps: float = 0.0
    threshold_bps: float = 0.0