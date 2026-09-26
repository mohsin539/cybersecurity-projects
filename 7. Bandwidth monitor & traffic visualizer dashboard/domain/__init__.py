"""Package domain: pure business entities and ports (no framework imports)."""

from .entities import (
    Alert,
    ConnectionInfo,
    ConnectionSummary,
    InterfaceTraffic,
    NetworkInterfaceInfo,
    RateSample,
    Snapshot,
)
from .interfaces import SnapshotStore, SystemNetworkSource

__all__ = [
    "Alert",
    "ConnectionInfo",
    "ConnectionSummary",
    "InterfaceTraffic",
    "NetworkInterfaceInfo",
    "RateSample",
    "Snapshot",
    "SnapshotStore",
    "SystemNetworkSource",
]