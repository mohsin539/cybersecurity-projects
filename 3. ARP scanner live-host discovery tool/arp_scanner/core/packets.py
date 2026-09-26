"""ARP packet building and parsing (archetecture.md §7.4)."""

from __future__ import annotations

from dataclasses import dataclass
from ipaddress import IPv4Address

from scapy.layers.l2 import ARP, Ether

from arp_scanner.util.net import normalize_mac

OP_REQUEST = 1
OP_REPLY = 2

BROADCAST_MAC = "ff:ff:ff:ff:ff:ff"


class PacketError(RuntimeError):
    """Raised when a frame cannot be built or parsed."""


def build_arp_request(src_mac: str, src_ip: str, target_ip: str | IPv4Address) -> Ether:
    """Build a broadcast ARP who-has frame for target_ip."""
    try:
        norm_src = normalize_mac(src_mac)
        assert norm_src, "invalid source MAC"
        return Ether(dst=BROADCAST_MAC, src=norm_src) / ARP(
            op=OP_REQUEST,
            hwsrc=norm_src,
            psrc=str(src_ip),
            pdst=str(target_ip),
        )
    except Exception as exc:  # noqa: BLE001 - normalize any build failure
        raise PacketError(f"failed to build ARP request: {exc}") from exc


def parse_arp_reply(pkt) -> tuple[IPv4Address, str] | None:
    """Extract (sender-ip, sender-mac) from an ARP is-at reply. None otherwise."""
    if pkt is None or not hasattr(pkt, "haslayer"):
        return None
    try:
        arp = pkt.getlayer(ARP) if pkt.haslayer(ARP) else None
        if arp is None or arp.op != OP_REPLY:
            return None
        mac = normalize_mac(arp.hwsrc)
        if mac is None:
            return None
        return IPv4Address(arp.psrc), mac
    except Exception:  # noqa: BLE001 - malformed frame is not our problem
        return None