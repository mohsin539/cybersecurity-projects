"""Abstractions (ports) the framework layer must implement.

The application layer depends on these protocols only; swapping psutil for a
different capture provider, or the in-memory store for a time-series database,
never touches domain or application code.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Dict, List, Optional

from .entities import ConnectionInfo, NetworkInterfaceInfo, RateSample, Snapshot


class SystemNetworkSource(ABC):
    """Port for reading raw network telemetry from the host OS."""

    @abstractmethod
    def list_interfaces(self) -> List[NetworkInterfaceInfo]:
        """Return metadata for every network interface discovered."""

    @abstractmethod
    def read_counters(self) -> Dict[str, RateSample]:
        """Return cumulative counters per interface (keyed by interface name)."""

    @abstractmethod
    def read_total(self) -> RateSample:
        """Return cumulative counters aggregated across all interfaces."""

    @abstractmethod
    def read_connections(self, limit: int) -> List[ConnectionInfo]:
        """Return up to ``limit`` observed connections (best effort)."""


class SnapshotStore(ABC):
    """Port for persisting / querying telemetry snapshots."""

    @abstractmethod
    def push(self, snapshot: Snapshot) -> None:
        """Append a snapshot, evicting the oldest when at capacity."""

    @abstractmethod
    def latest(self) -> Optional[Snapshot]:
        """Return the most recent snapshot, or ``None`` if the store is empty."""

    @abstractmethod
    def window(self, seconds: float) -> List[Snapshot]:
        """Return snapshots newer than ``seconds`` (chronologically ordered)."""