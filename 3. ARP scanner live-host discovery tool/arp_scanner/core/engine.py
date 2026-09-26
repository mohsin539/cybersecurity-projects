"""Scan orchestration (archetecture.md §7.3): interface resolution, target
expansion, privilege pre-check, sender invocation, aggregation."""

from __future__ import annotations

import threading
import time
from typing import Callable

from arp_scanner.core.config import ScannerConfig
from arp_scanner.core.result import ScanResult, build_result
from arp_scanner.core.sender import ArpSender, SenderError
from arp_scanner.security.guard import check_privileges
from arp_scanner.util.net import (
    expand_target,
    expand_target_info,
    is_reserved_host,
)

LARGE_SCAN_ADDRESS_LIMIT = 1_000_000
LARGE_SCAN_WARNING_LIMIT = 65_534


class ScanError(RuntimeError):
    """Raised for fatal scan failures."""


class NoInterfaceError(ScanError):
    pass


def _list_psutil_interfaces() -> list[tuple[str, str | None, str | None]]:
    """[(friendly_name, ipv4, mac)] for up interfaces with an IPv4 address."""
    import socket as _socket

    import psutil

    stats = psutil.net_if_stats()
    rows: list[tuple[str, str | None, str | None]] = []
    for name, addrs in psutil.net_if_addrs().items():
        if not stats.get(name) or not stats[name].isup:
            continue
        ip4 = mac = None
        for addr in addrs:
            if addr.family == _socket.AF_INET and ip4 is None and addr.address:
                ip4 = addr.address
            elif addr.family == psutil.AF_LINK and mac is None and addr.address:
                mac = addr.address
        if ip4:
            rows.append((name, ip4, mac))
    rows.sort(key=lambda r: str(r[0]).lower())
    return rows


def list_interfaces() -> list[str]:
    """Friendly interface names suitable for the GUI combo box."""
    return [name for name, _ip, _mac in _list_psutil_interfaces()]


def detect_interface() -> str:
    rows = _list_psutil_interfaces()
    if not rows:
        raise NoInterfaceError("no up interface with an IPv4 address was found")
    return rows[0][0]


def get_local_address(interface: str) -> tuple[str, str]:
    """Best-effort (ipv4, mac) for the given friendly interface name."""
    rows = _list_psutil_interfaces()
    for name, ip4, mac in rows:
        if name.lower() == interface.lower():
            return ip4 or "0.0.0.0", mac or "00:00:00:00:00:00"
    raise NoInterfaceError(f"interface '{interface}' is not up or has no IPv4 address")


def resolve_interface(interface: str) -> str:
    """Map a friendly interface name to the name scapy understands
    (Windows Npcap device names differ from psutil friendly names)."""
    requested = interface.strip()

    def all_names() -> list[str]:
        try:
            from scapy.all import conf

            ifaces = getattr(conf, "ifaces", None)
            if ifaces is None:
                return []
            seen: list[str] = []
            for nic in ifaces.values():
                values = [getattr(nic, "name", ""), getattr(nic, "description", "")]
                for v in values:
                    if v and v.lower() not in {s.lower() for s in seen}:
                        seen.append(v)
            return seen
        except Exception:  # noqa: BLE001
            return []

    scapy_names = all_names()
    if not scapy_names:
        raise NoInterfaceError("scapy could not enumerate interfaces; is Npcap installed?")

    lowered = requested.lower()
    if requested in scapy_names:
        return requested
    for candidate in scapy_names:
        if candidate.lower() == lowered:
            return candidate
    # Npcap device names look like: \Device\NPF_{guid} — match by anything after NPF_
    for candidate in scapy_names:
        if "npf_" in candidate.lower() and lowered in candidate.lower():
            return candidate
    raise NoInterfaceError(
        f"could not resolve interface '{requested}'. Available: {', '.join(scapy_names[:10])}"
    )


def run_scan(
    config: ScannerConfig,
    *,
    cancel: threading.Event | None = None,
    on_progress: Callable[[int, int], None] | None = None,
    on_host: Callable[[str, str, float], None] | None = None,
    audit: Callable[[str], None] | None = None,
    sender_factory: Callable[..., ArpSender] | None = None,
) -> ScanResult:
    """Execute a full scan lifecycle and return aggregated results."""
    start = time.monotonic()
    audit = audit or (lambda msg: None)

    addresses, net = expand_target_info(config.target)
    if not addresses:
        raise ScanError("target expands to zero addresses")

    if not config.include_reserved and net is not None:
        addresses = [a for a in addresses if not is_reserved_host(a, net)]

    if len(addresses) > LARGE_SCAN_ADDRESS_LIMIT and not config.allow_large:
        raise ScanError(
            f"target expands to {len(addresses)} addresses (limit "
            f"{LARGE_SCAN_ADDRESS_LIMIT}); enable the large-scan override to continue"
        )

    local_wants = interface = "auto" if config.interface in ("auto", "") else config.interface
    if interface == "auto":
        interface = detect_interface()
    resolved = resolve_interface(interface)
    src_ip, src_mac = get_local_address(local_wants if local_wants != "auto" else interface)
    if not src_mac or src_mac == "00:00:00:00:00:00":
        audit(f"warning: no MAC address exposed for '{interface}'; requests will still be sent")

    check_privileges(resolved)
    audit(f"scan started: {len(addresses)} targets on '{resolved}' ({src_ip})")

    factory = sender_factory or (
        lambda: ArpSender(
            interface=resolved,
            src_ip=src_ip,
            src_mac=src_mac,
            timeout=config.timeout,
            retries=config.retries,
        )
    )
    sender = factory()
    try:
        replies = sender.probe(addresses, cancel=cancel, on_progress=on_progress)
    except SenderError as exc:
        audit(f"scan failed: {exc}")
        raise ScanError(str(exc)) from exc

    if cancel is not None and cancel.is_set():
        audit("scan cancelled by user")
        raise ScanError("scan cancelled")

    from arp_scanner.core.devices import lookup_vendor

    duration = time.monotonic() - start
    result = build_result(
        targets=[str(a) for a in addresses],
        replies=replies,
        interface=resolved,
        duration_s=duration,
        vendor_lookup=lookup_vendor,
    )
    for host in result.hosts_sorted:
        if on_host:
            on_host(host.ip, host.mac, host.rtt_ms)
    audit(f"scan complete: {len(result.hosts)} host(s) live, {result.duration_s:.2f}s")
    return result


def _friendly(resolved: str) -> str:
    """Best-effort reverse: Npcap device name back to a psutil friendly name."""
    for name, _ip, _mac in _list_psutil_interfaces():
        if name.lower() == resolved.lower():
            return name
        if "npf_" in resolved.lower() and name.lower() in resolved.lower():
            return name
    return resolved