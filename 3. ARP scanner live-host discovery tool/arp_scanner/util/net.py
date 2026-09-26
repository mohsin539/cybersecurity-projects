"""Network math helpers: target expansion, MAC normalization, reserved-host
detection. Hardened against malformed input (OWASP A03 injection, A04 design)."""

from __future__ import annotations

import re
from ipaddress import IPv4Address, IPv4Network, ip_network

_MAX_MASK = 32

_CIDR_RE = re.compile(
    r"^(?P<a>\d{1,3})\.(?P<b>\d{1,3})\.(?P<c>\d{1,3})\.(?P<d>\d{1,3})/"
    r"(?P<mask>3[0-2]|2[0-9]|1[0-9]|[0-9])$"
)
_RANGE_FULL_RE = re.compile(
    r"^(?P<a>\d{1,3})\.(?P<b>\d{1,3})\.(?P<c>\d{1,3})\.(?P<d>\d{1,3})"
    r"-(?P<ea>\d{1,3})\.(?P<eb>\d{1,3})\.(?P<ec>\d{1,3})\.(?P<ed>\d{1,3})$"
)
_RANGE_SHORT_RE = re.compile(
    r"^(?P<a>\d{1,3})\.(?P<b>\d{1,3})\.(?P<c>\d{1,3})\.(?P<d>\d{1,3})-(?P<ed>\d{1,3})$"
)
_SINGLE_RE = re.compile(r"^(?P<a>\d{1,3})\.(?P<b>\d{1,3})\.(?P<c>\d{1,3})\.(?P<d>\d{1,3})$")

_MAC_MAP = str.maketrans({"-": ":", "_": ":"})
_MAC_RE = re.compile(r"^([0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2}$")


class TargetError(ValueError):
    """Raised for malformed or unsafe scan targets."""


def _octet(part: str, reg: re.Match) -> int:
    value = int(reg.group(part))
    if value > 255:
        raise TargetError(f"octet {value} out of range 0-255")
    return value


def _hosts_in_range(start: IPv4Address, end: IPv4Address) -> list[IPv4Address]:
    if end < start:
        raise TargetError("range start is greater than range end")
    if int(end) - int(start) > 2_000_000:
        raise TargetError("target range exceeds 2,000,000 addresses")
    return [IPv4Address(addr) for addr in range(int(start), int(end) + 1)]


def expand_target(target: str) -> list[IPv4Address]:
    """Expand a CIDR, single IP, or dash-delimited range into a list of IPv4s."""
    if not target or not target.strip():
        raise TargetError("target is empty")
    raw = target.strip()

    if "/" in raw:
        match = _CIDR_RE.match(raw)
        if not match:
            raise TargetError(f"invalid CIDR notation: {raw!r}")
        for part in ("a", "b", "c", "d"):
            _octet(part, match)
        try:
            net = ip_network(raw, strict=False)
        except ValueError as exc:
            raise TargetError(f"invalid CIDR: {raw!r}") from exc
        if net.version != 4:
            raise TargetError("only IPv4 targets are supported")
        return list(net.hosts())

    match = _RANGE_FULL_RE.match(raw)
    if match:
        start = IPv4Address(
            f"{_octet('a', match)}.{_octet('b', match)}.{_octet('c', match)}.{_octet('d', match)}"
        )
        end = IPv4Address(
            f"{_octet('ea', match)}.{_octet('eb', match)}.{_octet('ec', match)}.{_octet('ed', match)}"
        )
        return _hosts_in_range(start, end)

    match = _RANGE_SHORT_RE.match(raw)
    if match:
        a, b, c, d = (_octet(p, match) for p in ("a", "b", "c", "d"))
        start = IPv4Address(f"{a}.{b}.{c}.{d}")
        end = IPv4Address(f"{a}.{b}.{c}.{_octet('ed', match)}")
        return _hosts_in_range(start, end)

    match = _SINGLE_RE.match(raw)
    if match:
        single = IPv4Address(
            f"{_octet('a', match)}.{_octet('b', match)}.{_octet('c', match)}.{_octet('d', match)}"
        )
        return [single]

    raise TargetError(f"invalid target: {raw!r} (expected CIDR, range, or single IP)")


def expand_target_info(target: str) -> tuple[list[IPv4Address], IPv4Network | None]:
    """Expanded address list plus the base network (for reserved filtering)."""
    addresses = expand_target(target)
    net = None
    if "/" in target.strip():
        try:
            net = ip_network(target.strip(), strict=False)
        except ValueError:
            net = None
    return addresses, net


def is_reserved_host(address: IPv4Address, net: IPv4Network | None) -> bool:
    """True when the address is the network or broadcast address of `net`."""
    if net is None:
        return False
    return address == net.network_address or address == net.broadcast_address


def normalize_mac(mac: str) -> str | None:
    """Normalize a MAC to lower-case colon form; None when unusable."""
    if not mac:
        return None
    cleaned = str(mac).strip().translate(_MAC_MAP)
    if not _MAC_RE.match(cleaned):
        return None
    return cleaned.lower()


def oui_prefix(mac: str) -> str:
    """First six hex digits of a normalized MAC (e.g. 'b827eb')."""
    normalized = normalize_mac(mac)
    if normalized is None:
        return ""
    return normalized.replace(":", "")[:6]


def sort_addresses(addresses: list[IPv4Address]) -> list[IPv4Address]:
    return sorted(addresses, key=int)