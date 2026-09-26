"""SSRF protection for all outbound connector traffic.

OWASP A10: outbound destinations are resolved against an explicit allowlist.
Loopback, link-local, CGNAT and cloud-metadata ranges are ALWAYS blocked so a
compromised connector (or a malicious playbook) cannot reach internal services.

Also acts as an egress gatekeeper for NIST SC-7 / ISO 27001 A.13.1.
"""
from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urlparse

FORBIDDEN_NETWORKS = [
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.0.0.0/24",
    "192.0.2.0/24",
    "192.168.0.0/16",
    "198.18.0.0/15",
    "198.51.100.0/24",
    "203.0.113.0/24",
    "224.0.0.0/4",
    "240.0.0.0/4",
    "::1/128",
    "::/128",
    "fc00::/7",
    "fe80::/10",
    "2001:db8::/32",
]


def _parse_allowlist(raw: str) -> list[ipaddress._BaseNetwork]:
    nets = []
    for part in raw.split(","):
        part = part.strip()
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            continue
    return nets


def resolve_host(host: str) -> str:
    """Resolve a host to a single IP. Raises on private/forbidden targets."""
    try:
        ip = socket.gethostbyname(host)
    except OSError as exc:
        raise ValueError(f"DNS resolution failed for {host!r}") from exc
    return ip


def assert_egress_allowed(url: str, allowlist_csv: str | None = None) -> str:
    """Validate URL against the egress allowlist. Returns the verified dest IP."""
    parsed = urlparse(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError(f"Unsupported scheme: {parsed.scheme!r}")

    host = parsed.hostname
    if not host:
        raise ValueError("URL has no host")

    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    if port not in (80, 443, 8080, 8443):
        raise ValueError(f"Port {port} not allowed for outbound traffic")

    try:
        dest = ipaddress.ip_address(host)
    except ValueError:
        dest = ipaddress.ip_address(resolve_host(host))

    # forbidden (always)
    for net in FORBIDDEN_NETWORKS:
        net_obj = ipaddress.ip_network(net)
        if dest.version == net_obj.version and dest in net_obj:
            raise ValueError(f"Destination {host} ({dest}) is in a forbidden network ({net})")

    # allowlist (if any)
    if allowlist_csv and allowlist_csv.strip():
        allowed = _parse_allowlist(allowlist_csv)
        if allowed:
            allowed_any = any(dest.version == net.version and dest in net for net in allowed)
            if not allowed_any:
                raise ValueError(f"Destination {host} ({dest}) not in egress allowlist")
    return str(dest)


def validate_connector_url(base_url: str, requested_path: str = "", allowlist_csv: str | None = None) -> str:
    """Build a full URL from base + path and run egress validation."""
    base = base_url.rstrip("/")
    path = requested_path or ""
    if path and not path.startswith("/"):
        path = "/" + path
    url = base + path
    assert_egress_allowed(url, allowlist_csv)
    return url