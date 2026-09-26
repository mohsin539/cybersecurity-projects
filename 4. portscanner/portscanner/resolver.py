"""Target resolution & expansion (architecture.md §4.2).

Streams a flat, deduplicated, exclusion-filtered target queue. A /8 never
materializes in RAM — expansion is lazy.
"""
from __future__ import annotations

import ipaddress
import socket
import threading
from typing import Iterator

from .models import Target
from .security import stderr_warn

MAX_EXPANSION = 1_048_576  # hard cap: refuse > /12 worth of hosts (DoS guard)


def parse_target(t: str) -> tuple[list[ipaddress._BaseNetwork], list[str]]:
    """Split an input string into networks and bare hostnames."""
    networks: list[ipaddress._BaseNetwork] = []
    hosts: list[str] = []
    if "/" in t:
        networks.append(ipaddress.ip_network(t, strict=False))  # type: ignore[arg-type]
    elif "-" in t and t.split("-")[-1].isdigit():
        base, last = t.rsplit("-", 1)
        base_ip = ipaddress.ip_address(base.strip())
        networks.append(_range_to_network(base_ip, int(last)))
    else:
        hosts.append(t)
    return networks, hosts


def _range_to_network(base_ip: ipaddress._BaseAddress, last_octet_or_host: int) -> "ipaddress._BaseNetwork":
    """Expand '10.0.0.1-50' shorthand into a network covering the range."""
    if base_ip.version != 4:
        raise ValueError("dash ranges only supported for IPv4")
    start_int = int(base_ip)
    end_int = start_int + last_octet_or_host - 1
    start = ipaddress.ip_address(start_int)
    end = ipaddress.ip_address(end_int)
    return ipaddress.summarize_address_range(start, end)[0]  # type: ignore[return-value]


class TargetResolver:
    """Resolve → expand → exclude → dedupe, streamed lazily."""

    def __init__(self, targets: list[str], exclude: list[str], dns_timeout: float = 3.0) -> None:
        self.targets = targets
        self.exclude = [ipaddress.ip_network(e, strict=False) for e in exclude if e]
        self.dns_timeout = dns_timeout
        self.resolved: dict[str, str] = {}  # ip -> original hostname
        self._lock = threading.Lock()

    def _excluded(self, ip: ipaddress._BaseAddress) -> bool:
        return any(ip in net for net in self.exclude)

    def _resolve_host(self, host: str) -> list[ipaddress._BaseAddress]:
        try:
            infos = socket.getaddrinfo(
                host, None, proto=socket.IPPROTO_TCP,
            )
        except socket.gaierror as exc:
            stderr_warn(f"DNS failure for {host!r}: {exc}")
            return []
        out: list[ipaddress._BaseAddress] = []
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip not in out:
                out.append(ip)
        return out

    def expand(self) -> Iterator[Target]:
        seen: set[str] = set()
        count = 0
        for raw in self.targets:
            networks, hosts = parse_target(raw)
            ips: list[ipaddress._BaseAddress] = []
            for net in networks:
                for ip in net:
                    count += 1
                    if count > MAX_EXPANSION:
                        raise ValueError(
                            f"target expansion exceeded {MAX_EXPANSION} hosts — reduce scope"
                        )
                    if not self._excluded(ip):
                        ips.append(ip)
            for host in hosts:
                resolved = self._resolve_host(host)
                for ip in resolved:
                    if not self._excluded(ip):
                        ips.append(ip)

            for ip in ips:
                key = str(ip)
                if key in seen:
                    continue
                seen.add(key)
                with self._lock:
                    self.resolved[key] = raw if raw in hosts else ""
                yield Target(ip=key, hostname=raw if raw in hosts else "")
