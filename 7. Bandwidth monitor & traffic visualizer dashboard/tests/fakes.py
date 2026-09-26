"""Shared doubles used across the test suite (no real OS telemetry)."""
from __future__ import annotations

from typing import Dict, List, Optional

from domain.entities import ConnectionInfo, NetworkInterfaceInfo, RateSample
from domain.interfaces import SystemNetworkSource


def rate_sample(ts: float, rx: int, tx: int, rxp: int = 0, txp: int = 0) -> RateSample:
    return RateSample(
        timestamp=ts,
        bytes_recv=rx,
        bytes_sent=tx,
        packets_recv=rxp,
        packets_sent=txp,
    )


class ScriptedNetworkSource(SystemNetworkSource):
    """Cycles through a scripted sequence of (counters, total) reads."""

    def __init__(
        self,
        script: List[tuple],
        interfaces: Optional[List[NetworkInterfaceInfo]] = None,
        connections: Optional[List[ConnectionInfo]] = None,
    ) -> None:
        self._script = list(script)
        self._idx = 0
        self._last_entry: Optional[tuple] = None
        self.interfaces_meta = interfaces or []
        self.connections_data = connections or []

    def list_interfaces(self) -> List[NetworkInterfaceInfo]:
        return self.interfaces_meta

    def read_counters(self) -> Dict[str, RateSample]:
        entry = self._script[self._idx % len(self._script)]
        self._idx += 1
        self._last_entry = entry
        return entry[0]

    def read_total(self) -> RateSample:
        return self._last_entry[1] if self._last_entry else RateSample(0, 0, 0)

    def read_connections(self, limit: int) -> List[ConnectionInfo]:
        return self.connections_data[:limit]


class DummySnapshotListener:
    def __init__(self) -> None:
        self.received: List = []

    def __call__(self, snapshot) -> None:
        self.received.append(snapshot)