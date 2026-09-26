"""psutil-based implementation of ``SystemNetworkSource``.

Deliberately the only module that imports psutil — swapping the platform
adapter (e.g. for a packet-capture backend or a remote agent) requires no
changes anywhere else.
"""
from __future__ import annotations

import logging
import socket
import time
from typing import Dict, List, Optional

import psutil

from domain.entities import (
    ConnectionInfo,
    NetworkInterfaceInfo,
    RateSample,
)
from domain.interfaces import SystemNetworkSource

logger = logging.getLogger(__name__)

# Long-standing names that are essentially never "real" hardware links.
_VIRTUAL_HINTS = (
    "virbr",
    "veth",
    "docker",
    "vmnet",
    "vboxnet",
    "wg",
    "tun",
    "tap",
    "bond",
    "br-",
    "bridge",
    "ppp",
    "nflog",
    "lo",
)

# AF_* constants differ across platforms; build the label map defensively.
_FAMILY_LABEL = {socket.AF_INET: "ipv4", socket.AF_INET6: "ipv6"}
for _af in (getattr(socket, "AF_LINK", None), getattr(socket, "AF_PACKET", None)):
    if _af is not None:
        _FAMILY_LABEL[_af] = "mac"
_PROTOCOL_LABEL = {
    socket.SOCK_STREAM: "tcp",
    socket.SOCK_DGRAM: "udp",
}


class PsutilNetworkSource(SystemNetworkSource):
    """Reads counters, interface metadata and sockets via ``psutil``."""

    def __init__(self) -> None:
        self._process_cache: Dict[int, Optional[str]] = {}

    # ------------------------------------------------------------------ #
    # Interfaces
    # ------------------------------------------------------------------ #
    def list_interfaces(self) -> List[NetworkInterfaceInfo]:
        stats = psutil.net_if_stats()
        addrs = psutil.net_if_addrs()
        interfaces: List[NetworkInterfaceInfo] = []

        for name in sorted(set(stats) | set(addrs)):
            addr_list = []
            mac: Optional[str] = None
            for addr in addrs.get(name, []):
                label = _FAMILY_LABEL.get(addr.family)
                if label == "mac":
                    mac = addr.address
                elif label == "ipv4" or label == "ipv6":
                    addr_list.append(f"{label} {addr.address}")

            nic_stats = stats.get(name)
            interfaces.append(
                NetworkInterfaceInfo(
                    name=name,
                    is_up=bool(nic_stats and nic_stats.isup),
                    is_running=bool(nic_stats and nic_stats.isup),
                    mac_address=mac,
                    addresses=addr_list,
                    speed_mbps=nic_stats.speed if nic_stats else None,
                    is_virtual=self._is_virtual(name),
                )
            )
        return interfaces

    # ------------------------------------------------------------------ #
    # Counters
    # ------------------------------------------------------------------ #
    def read_counters(self) -> Dict[str, RateSample]:
        raw = psutil.net_io_counters(pernic=True)
        now = time.time()
        counters: Dict[str, RateSample] = {}
        for name, counters_io in raw.items():
            counters[name] = RateSample(
                timestamp=now,
                bytes_sent=counters_io.bytes_sent,
                bytes_recv=counters_io.bytes_recv,
                packets_sent=counters_io.packets_sent,
                packets_recv=counters_io.packets_recv,
                errors_in=counters_io.errin,
                errors_out=counters_io.errout,
                drops_in=counters_io.dropin,
                drops_out=counters_io.dropout,
            )
        return counters

    def read_total(self) -> RateSample:
        total = psutil.net_io_counters(pernic=False)
        return RateSample(
            timestamp=time.time(),
            bytes_sent=total.bytes_sent,
            bytes_recv=total.bytes_recv,
            packets_sent=total.packets_sent,
            packets_recv=total.packets_recv,
            errors_in=total.errin,
            errors_out=total.errout,
            drops_in=total.dropin,
            drops_out=total.dropout,
        )

    # ------------------------------------------------------------------ #
    # Connections
    # ------------------------------------------------------------------ #
    def read_connections(self, limit: int) -> List[ConnectionInfo]:
        try:
            sockets = psutil.net_connections(kind="inet")
        except (psutil.AccessDenied, OSError) as exc:
            # Elevated privileges are required on some platforms.
            logger.warning("Connection enumeration unavailable: %s", exc)
            return []

        connections: List[ConnectionInfo] = []
        for conn in sockets:
            protocol = _PROTOCOL_LABEL.get(conn.type)
            if protocol is None:
                continue
            family = _FAMILY_LABEL.get(conn.family, "unknown")
            pid = conn.pid
            process_name = self._process_name(pid)
            connections.append(
                ConnectionInfo(
                    process_name=process_name,
                    pid=pid,
                    protocol=protocol,
                    family=family,
                    state=conn.status,
                    local=_format_addr(conn.laddr),
                    remote=_format_addr(conn.raddr),
                    fd=conn.fd if conn.fd and conn.fd >= 0 else None,
                )
            )
            if len(connections) >= limit:
                break
        return connections

    # ------------------------------------------------------------------ #
    # Helpers
    # ------------------------------------------------------------------ #
    def _process_name(self, pid: Optional[int]) -> Optional[str]:
        if pid is None:
            return None
        if pid in self._process_cache:
            return self._process_cache[pid]
        try:
            proc = psutil.Process(pid)
            name = proc.name() if proc.is_running() else None
        except (psutil.NoSuchProcess, psutil.AccessDenied, psutil.ZombieProcess):
            name = None
        self._process_cache[pid] = name
        if len(self._process_cache) > 512:
            self._process_cache.clear()
        return name

    @staticmethod
    def _is_virtual(name: str) -> bool:
        lower = name.lower()
        return any(hint in lower for hint in _VIRTUAL_HINTS)


def _format_addr(addr) -> str:
    if not addr:
        return ""
    port = getattr(addr, "port", "")
    ip = getattr(addr, "ip", "")
    if isinstance(port, int) and port > 0:
        return f"{ip}:{port}"
    return str(ip) if ip else ""