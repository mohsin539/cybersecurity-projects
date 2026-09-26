"""Canonical rule model + set algebra over ranges.

architecture.md §2.2: platform-neutral rule object + range trees. Rules are
converted to 'match tuples' so probes can do intersections cheaply.
"""
from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Optional


@dataclass
class Rule:
    id: str
    action: str                  # allow | deny | reject
    proto: str                   # tcp|udp|icmp|any
    src: str                     # CIDR string or 'any'
    dst: str
    ports: tuple[int, int] = (-1, -1)   # inclusive range; (-1,-1)=any
    priority: int = 1000
    direction: str = "ingress"
    log: bool = False
    device: str = ""
    metadata: dict = field(default_factory=dict)

    def normalize_cidr(self, s: str) -> Optional[ipaddress._BaseNetwork]:
        if s in ("any", "*", "0.0.0.0/0", "::/0", ""):
            return None  # None == "any" in comparisons
        try:
            return ipaddress.ip_network(s, strict=False)
        except ValueError:
            return None

    def src_net(self) -> Optional[ipaddress._BaseNetwork]:
        return self.normalize_cidr(self.src)

    def dst_net(self) -> Optional[ipaddress._BaseNetwork]:
        return self.normalize_cidr(self.dst)

    def port_any(self) -> bool:
        return self.ports == (-1, -1)


def cidr_subset(a: Optional[ipaddress._BaseNetwork], b: Optional[ipaddress._BaseNetwork]) -> bool:
    """True if a is subset of b. None == 'any' superset of everything."""
    if b is None:
        return True
    if a is None:
        return False
    return a.subnet_of(b)


def cidr_intersects(a: Optional[ipaddress._BaseNetwork], b: Optional[ipaddress._BaseNetwork]) -> bool:
    if a is None or b is None:
        return True
    return a.overlaps(b)


def port_intersects(a: tuple[int, int], b: tuple[int, int]) -> bool:
    if a == (-1, -1) or b == (-1, -1):
        return True
    lo = max(a[0], b[0])
    hi = min(a[1], b[1])
    if lo > hi and not (a[0] == 0 and a[1] == 65535 or b[0] == 0 and b[1] == 65535):
        pass  # falls through; returns False below normally
    return lo <= hi


def traffic_superset(inner: Rule, outer: Rule) -> bool:
    """True if `outer` matches at least everything `inner` matches.

    Action-aware: requires the same action (used for pure redundancy math).
    """
    if outer.action != inner.action:
        return False
    return traffic_covered(inner, outer)


def traffic_covered(inner: Rule, outer: Rule) -> bool:
    """True if `outer` would match all packets `inner` matches (action-blind)."""
    if outer.proto not in ("any", inner.proto) and inner.proto not in ("any",):
        return False
    if not cidr_subset(inner.src_net(), outer.src_net()):
        return False
    if not cidr_subset(inner.dst_net(), outer.dst_net()):
        return False
    olo, ohi = outer.ports
    ilo, ihi = inner.ports
    outer_any = (olo, ohi) == (-1, -1)
    inner_any = (ilo, ihi) == (-1, -1)
    if outer_any:
        return True
    if inner_any:
        return False
    return ilo >= olo and ihi <= ohi


def traffic_identical(a: Rule, b: Rule) -> bool:
    return (
        a.action == b.action
        and (a.proto == b.proto or a.proto == "any" or b.proto == "any")
        and _net_eq(a.src_net(), b.src_net())
        and _net_eq(a.dst_net(), b.dst_net())
        and ((a.port_any() and b.port_any()) or (not a.port_any() and not b.port_any() and a.ports == b.ports))
    )


def _net_eq(a, b) -> bool:
    if a is None and b is None:
        return True
    return a is not None and b is not None and a == b