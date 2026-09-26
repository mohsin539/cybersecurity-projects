"""Core IPv4 mathematics (architecture.md section 6.2).

All functions are pure; addresses are plain unsigned-32-bit Python ints
(masked with MASK32 everywhere so results stay in range).
"""
from __future__ import annotations

from dataclasses import dataclass

from . import formatter

MASK32 = 0xFFFFFFFF

# (network, prefix) pairs checked by is_private(): RFC 1918 + loopback + APIPA.
PRIVATE_RANGES: tuple[tuple[int, int], ...] = (
    (0x0A000000, 8),    # 10.0.0.0/8
    (0xAC100000, 12),   # 172.16.0.0/12
    (0xC0A80000, 16),   # 192.168.0.0/16
    (0x7F000000, 8),    # 127.0.0.0/8 loopback
    (0xA9FE0000, 16),   # 169.254.0.0/16 APIPA
)


# ---------------------------------------------------------------- conversions
def ip_from_octets(a: int, b: int, c: int, d: int) -> int:
    return ((a << 24) | (b << 16) | (c << 8) | d) & MASK32


def ip_to_string(ip: int) -> str:
    ip &= MASK32
    return ".".join(str((ip >> shift) & 0xFF) for shift in (24, 16, 8, 0))


def cidr_to_mask(cidr: int) -> int:
    return (MASK32 << (32 - cidr)) & MASK32


def cidr_to_wildcard(cidr: int) -> int:
    return MASK32 >> cidr


def mask_to_cidr(mask: int) -> int:
    """Count prefix bits of a mask. Assumes contiguity (parser validates it)."""
    return bin(mask & MASK32).count("1")


# ------------------------------------------------------------- subnet metrics
def network_of(ip: int, cidr: int) -> int:
    return ip & (MASK32 << (32 - cidr)) & MASK32


def broadcast_of(ip: int, cidr: int) -> int:
    return network_of(ip, cidr) | (MASK32 >> cidr)


def total_addresses(cidr: int) -> int:
    return 1 << (32 - cidr)


def usable_hosts(cidr: int) -> int:
    """Usable host count with RFC 3021 (/31) and host-route (/32) semantics."""
    if cidr >= 32:
        return 1
    if cidr == 31:
        return 2
    return total_addresses(cidr) - 2


def first_host(ip: int, cidr: int) -> int:
    net = network_of(ip, cidr)
    if cidr >= 31:          # /31: first address is usable; /32: the host itself
        return net
    return net + 1


def last_host(ip: int, cidr: int) -> int:
    bc = broadcast_of(ip, cidr)
    if cidr >= 32:          # /32: single host route
        return bc
    if cidr == 31:          # /31: second address is usable
        return bc
    return bc - 1


def cidr_for_hosts(hosts: int) -> int:
    """Smallest prefix that fits `hosts` usable hosts (network+broadcast reserved).

    cidr = 32 - ceil(log2(hosts + 2)), implemented exactly with bit_length.
    hosts <= 0 allocates a /32 (single-address route).
    """
    if hosts <= 0:
        return 32
    bits = (hosts + 1).bit_length()      # ceil(log2(hosts + 2)) for hosts >= 1
    return max(0, min(32, 32 - bits))


# ------------------------------------------------------------- classification
def classify(ip: int) -> str:
    first_octet = (ip & MASK32) >> 24
    if first_octet < 128:
        return "A"
    if first_octet < 192:
        return "B"
    if first_octet < 224:
        return "C"
    if first_octet < 240:
        return "D"
    return "E"


def _matches(ip: int, base: int, prefix: int) -> bool:
    return network_of(ip, prefix) == network_of(base, prefix)


def is_private(ip: int) -> bool:
    return any(_matches(ip, base, prefix) for base, prefix in PRIVATE_RANGES)


# -------------------------------------------------------------------- summary
@dataclass(frozen=True)
class SubnetInfo:
    """All calculated details for one input (mirrors architecture.md section 5)."""

    input_ip: str
    cidr: int
    network: str
    broadcast: str
    first_host: str
    last_host: str
    subnet_mask: str
    wildcard_mask: str
    total_addresses: int
    usable_hosts: int
    ip_class: str
    is_private: bool
    binary_mask: str
    hex_ip: str


def describe(ip: int, cidr: int) -> SubnetInfo:
    net = network_of(ip, cidr)
    bc = broadcast_of(ip, cidr)
    return SubnetInfo(
        input_ip=ip_to_string(ip),
        cidr=cidr,
        network=ip_to_string(net),
        broadcast=ip_to_string(bc),
        first_host=ip_to_string(first_host(ip, cidr)),
        last_host=ip_to_string(last_host(ip, cidr)),
        subnet_mask=ip_to_string(cidr_to_mask(cidr)),
        wildcard_mask=ip_to_string(cidr_to_wildcard(cidr)),
        total_addresses=total_addresses(cidr),
        usable_hosts=usable_hosts(cidr),
        ip_class=classify(ip),
        is_private=is_private(ip),
        binary_mask=formatter.format_binary_mask(cidr),
        hex_ip=formatter.format_hex_ip(ip),
    )
