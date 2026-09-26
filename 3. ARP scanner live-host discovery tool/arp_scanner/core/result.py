"""Scan result data model and aggregation (archetecture.md §7.6, §8)."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone

from ipaddress import IPv4Address

from arp_scanner.util.net import sort_addresses


@dataclass(frozen=True, slots=True)
class HostInfo:
    ip: str
    mac: str
    vendor: str | None
    rtt_ms: float
    interface: str
    discovered_at_epoch: float

    def to_dict(self) -> dict:
        data = asdict(self)
        return {
            "ip": data["ip"],
            "mac": data["mac"],
            "vendor": data["vendor"] or "unknown",
            "rtt_ms": round(data["rtt_ms"], 2),
            "interface": data["interface"],
        }


@dataclass(frozen=True, slots=True)
class ScanResult:
    targets: list[str] = field(default_factory=list)
    hosts: list[HostInfo] = field(default_factory=list)
    scanned_at: str = ""  # ISO-8601 UTC
    duration_s: float = 0.0
    interface: str = ""
    schema_version: int = 1

    @property
    def hosts_sorted(self) -> list[HostInfo]:
        return sorted(self.hosts, key=lambda h: int(IPv4Address(h.ip)))

    @property
    def unresolved_targets(self) -> int:
        return max(0, len(self.targets) - len(self.hosts))

    def to_dict(self) -> dict:
        return {
            "schema_version": self.schema_version,
            "scanned_at": self.scanned_at,
            "duration_s": round(self.duration_s, 3),
            "interface": self.interface,
            "targets_total": len(self.targets),
            "hosts_found": len(self.hosts),
            "unresolved_targets": self.unresolved_targets,
            "hosts": [h.to_dict() for h in self.hosts_sorted],
        }


def build_result(
    *,
    targets: list[str],
    replies: dict[str, tuple[str, float]],
    interface: str,
    duration_s: float,
    vendor_lookup,
) -> ScanResult:
    """Assemble a ScanResult from raw sender replies (aggregation stage)."""
    hosts: list[HostInfo] = []
    now_epoch = datetime.now(timezone.utc).timestamp()
    for ip in sort_addresses([str(t) for t in targets]):
        entry = replies.get(ip)
        if not entry:
            continue
        mac, rtt = entry
        hosts.append(
            HostInfo(
                ip=str(ip),
                mac=mac,
                vendor=vendor_lookup(mac),
                rtt_ms=rtt,
                interface=interface,
                discovered_at_epoch=now_epoch,
            )
        )
    return ScanResult(
        targets=targets,
        hosts=hosts,
        scanned_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
        duration_s=duration_s,
        interface=interface,
    )