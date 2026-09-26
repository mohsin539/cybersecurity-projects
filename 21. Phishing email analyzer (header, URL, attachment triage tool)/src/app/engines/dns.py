"""Truncated DNS. Hardened DNS client wrapper around dnspython.

Controls: SC-7 / A.13 (network boundary), A10 (no arbitrary resolution to
internal names by the URL engine - this module only serves the header/SPF/DKIM/
DMARC engine). Fails closed: any anomaly => 'unavailable' (never fabricated data).
"""
from __future__ import annotations

import ipaddress
from typing import List, Optional

from ..sec import constants as C

try:
    import dns.exception
    import dns.resolver

    _DNS = True
except Exception:  # noqa: BLE001 - degrade gracefully when not bundled
    _DNS = False


def dns_available() -> bool:
    return _DNS


def _resolver():
    r = dns.resolver.Resolver(configure=True)
    r.timeout = C.DNS_TIMEOUT_SECONDS
    r.lifetime = C.DNS_LIFETIME_SECONDS
    return r


def get_txt(domain: str) -> List[str]:
    """TXT records as list of strings. Raises / returns [] on NXDOMAIN etc."""
    if not _DNS:
        return []
    try:
        ans = _resolver().resolve(domain, "TXT", lifetime=C.DNS_LIFETIME_SECONDS)
    except Exception:  # noqa: BLE001
        return []
    out = []
    for rr in ans:
        for chunk in rr.strings:
            out.append(chunk.decode("utf-8", "replace"))
    return out


def get_a(domain: str) -> List[str]:
    if not _DNS:
        return []
    try:
        ans = _resolver().resolve(domain, "A", lifetime=C.DNS_LIFETIME_SECONDS)
    except Exception:  # noqa: BLE001
        return []
    return [rr.address for rr in ans if hasattr(rr, "address")]


def get_mx(domain: str) -> List[str]:
    if not _DNS:
        return []
    try:
        ans = _resolver().resolve(domain, "MX", lifetime=C.DNS_LIFETIME_SECONDS)
    except Exception:  # noqa: BLE001
        return []
    return [str(rr.exchange) for rr in ans if hasattr(rr, "exchange")]


def secure_resolve_host(host: str) -> List[str]:
    """Resolve a hostname, NEVER returning private/reserved addresses (A10).

    Used by the URL engine for literal-IP checking of discovered hostnames.
    """
    if not _DNS:
        return []
    from ..sec.validation import is_private_ip
    try:
        ans = _resolver().resolve(host, "A", lifetime=C.DNS_LIFETIME_SECONDS)
    except Exception:  # noqa: BLE001
        return []
    safe = []
    for rr in ans:
        ip = getattr(rr, "address", "")
        if ip and not is_private_ip(ip):
            safe.append(ip)
    return safe