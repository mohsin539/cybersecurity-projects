"""Scan engines (architecture.md §4.4).

Each engine implements Probe(job) -> PortResult. The scheduler is agnostic to
technique. Raw-socket engines are isolated here and privilege-checked.
"""
from __future__ import annotations

from .base import ScanEngine, ENGINE_REGISTRY, get_engine, available_engines
from .connect import ConnectEngine
from .udp import UdpEngine

__all__ = [
    "ScanEngine",
    "ENGINE_REGISTRY",
    "get_engine",
    "available_engines",
    "ConnectEngine",
    "UdpEngine",
]

ENGINE_REGISTRY["connect"] = ConnectEngine
ENGINE_REGISTRY["udp"] = UdpEngine

# Raw engines import scapy lazily so the unprivileged path has zero heavy deps.
try:  # pragma: no cover - environment dependent
    from .raw import SynEngine, FinEngine, NullEngine, XmasEngine

    ENGINE_REGISTRY["syn"] = SynEngine
    ENGINE_REGISTRY["fin"] = FinEngine
    ENGINE_REGISTRY["null"] = NullEngine
    ENGINE_REGISTRY["xmas"] = XmasEngine
except ImportError:
    pass  # scapy not installed: connect/udp remain fully functional


def engine_requires_raw(scan_type: str) -> bool:
    return scan_type in ("syn", "fin", "null", "xmas")
