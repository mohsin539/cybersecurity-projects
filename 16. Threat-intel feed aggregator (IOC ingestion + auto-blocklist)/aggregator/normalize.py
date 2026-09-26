"""IOC normalization: canonical types, dedupe, quality gates (architecture §2.2-2.3).

PRIVACY & SAFETY: internal ranges (RFC1918, link-local, multicast, broadcast)
and our own infra ranges are guarded BEFORE anything is promoted to a
blocklist. TLP is respected at every gate.
"""
from __future__ import annotations

import hashlib
import ipaddress
import re
from dataclasses import dataclass, field
from typing import Optional

TLP_LEVELS = {"white", "green", "amber", "red"}

PRIVATE_NETWORKS = [
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("169.254.0.0/16"),
    ipaddress.ip_network("127.0.0.0/8"),
    ipaddress.ip_network("::1/128"),
    ipaddress.ip_network("fe80::/10"),
    ipaddress.ip_network("fc00::/7"),
]


@dataclass
class IOC:
    value: str
    ioc_type: str            # ipv4 | ipv6 | cidr | domain | url | file_hash
    sources: list = field(default_factory=list)
    confidence: float = 0.0
    tlp: str = "white"
    expires_at: str = "2099-12-31T23:59:59Z"
    tags: list = field(default_factory=list)
    first_seen: str = ""
    feed_id: str = ""

    @property
    def normalized(self) -> str:
        return normalize_ioc(self.value, self.ioc_type)


def classify_ioc(value: str) -> str:
    v = value.strip().lower()
    if re.match(r"^[\d.]+/\d{1,2}$", v):       # CIDR
        parts = v.split("/")[0]
        if all(0 <= int(p) <= 255 for p in parts.split(".") if p.isdigit()) and parts.count(".") == 3:
            return "cidr"
    if v.count(":") >= 2 and re.match(r"^[0-9a-f:]+$", v):
        return "ipv6"
    if re.match(r"^[\d.]+$", v) and v.count(".") == 3:
        return "ipv4"
    if v.startswith(("http://", "https://", "www.")):
        return "url"
    if re.match(r"^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}$", v):
        return "domain"
    if re.match(r"^[a-f0-9]{32}$|^[a-f0-9]{40}$|^[a-f0-9]{64}$", v):
        return "file_hash"
    return "unknown"


def normalize_ioc(value: str, ioc_type: str) -> str:
    v = value.strip().lower()
    if ioc_type == "domain":
        return v.rstrip(".")
    if ioc_type == "url":
        return v.split("://")[-1].split("/")[0]  # normalize url -> host
    if ioc_type == "file_hash":
        return v.lower()
    if ioc_type in ("ipv4", "ipv6", "cidr"):
        try:
            return str(ipaddress.ip_network(v, strict=False))
        except ValueError:
            return v
    return v


def is_internal(ip_str_or_net: str, own_ranges: Optional[list] = None) -> bool:
    """Quality gate: blocklist must NEVER include internal infra."""
    try:
        net = ipaddress.ip_network(ip_str_or_net, strict=False)
    except ValueError:
        return False
    for p in PRIVATE_NETWORKS:
        if p.version != net.version:
            continue
        if net.subnet_of(p) or p.subnet_of(net):
            return True
    for own in (own_ranges or []):
        try:
            on = ipaddress.ip_network(own, strict=False)
        except ValueError:
            continue
        if on.version != net.version:
            continue
        if net.subnet_of(on) or on.subnet_of(net):
            return True
    return False


def promote_ok(ioc: IOC, ip_feed_tlp: str = "white") -> bool:
    """Auto-blocklist admission: TLP green/white + internal-range-guard + confidence.
    `ip_feed_tlp` is the overriding minimum TLP for any feed (config).
    """
    if ioc.tlp.lower() not in TLP_LEVELS:
        return False
    if ioc.tlp.lower() in ("amber", "red"):
        return False
    # resolve to a network for guard:
    if ioc.ioc_type in ("ipv4", "ipv6", "cidr"):
        if is_internal(ioc.value):
            return False
    if ioc.ioc_type == "domain":
        if ioc.value.endswith((".internal", ".local", ".localhost")):
            return False
    if ip_feed_tlp in ("amber", "red"):
        return False
    return True


def dedupe_key(ioc: IOC) -> str:
    if ioc.ioc_type == "url":
        return f"domain:{normalize_ioc(ioc.value, 'url')}"
    return f"{ioc.ioc_type}:{ioc.normalized}"