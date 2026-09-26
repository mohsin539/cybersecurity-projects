"""Input validation primitives (OWASP A01/A03 / NIST SI-7, SI-12).

Everything that will later reach a subprocess, a config file, or the network
must pass through this module. Validators return (ok: bool, message: str).
"""

from __future__ import annotations

import base64
import binascii
import ipaddress
import re

_IFACE_RE = re.compile(r"^[A-Za-z0-9_=+.\-]{1,15}$")
_NAME_RE = re.compile(r"^[\w\-.]{1,64}$")

_MAX_KEY_LEN = 44
_WG_KEY_B64_RE = re.compile(r"^[A-Za-z0-9+/]+={0,2}$")


def is_ipv4(value: str) -> bool:
    try:
        return ipaddress.IPv4Address(value).version == 4
    except (ValueError, TypeError):
        return False


def is_ipv6(value: str) -> bool:
    try:
        return ipaddress.IPv6Address(value).version == 6
    except (ValueError, TypeError):
        return False


def is_cidr(value: str) -> bool:
    if not isinstance(value, str) or not value:
        return False, "CIDR must be a non-empty string"
    try:
        net = ipaddress.ip_network(value, strict=False)
    except ValueError as exc:
        return False, f"Invalid CIDR '{value}': {exc}"
    return True, f"Valid {net.version} network {net.with_prefixlen}"


def is_port(value) -> bool:
    try:
        port = int(value)
    except (ValueError, TypeError):
        return False
    return 0 < port < 65536


def is_interface_name(value: str) -> bool:
    return bool(_IFACE_RE.fullmatch(value or ""))


def is_display_name(value: str) -> bool:
    return bool(_NAME_RE.fullmatch(value or ""))


def is_wg_key(value: str) -> bool:
    """WireGuard curve25519 keys are base64 of exactly 32 bytes."""
    if not isinstance(value, str) or len(value) != _MAX_KEY_LEN:
        return False
    if not _WG_KEY_B64_RE.fullmatch(value):
        return False
    try:
        return len(base64.b64decode(value, validate=True)) == 32
    except (binascii.Error, ValueError):
        return False


def is_endpoint(value: str) -> bool:
    """host:port or host. Allows IPv4/IPv6/domain names."""
    if not isinstance(value, str) or not value:
        return False, "Endpoint must be a string"
    value = value.strip()

    if ":" in value and value.count(":") >= 2:
        # IPv6 literal — require bracket form host:port, else treat whole as host
        if value.startswith("["):
            m = re.fullmatch(r"\[([0-9A-Fa-f:.]+)\](?::([0-9]{1,5}))?", value)
            if m and m.group(2) and not is_port(int(m.group(2))):
                return False, "Endpoint port out of range"
            return (True, "Endpoint syntax OK") if m else (False, "invalid IPv6 endpoint")

    if value.count(":") == 1:
        host, _, port = value.rpartition(":")
        if not port.isdigit():
            return False, "Endpoint port must be numeric"
        if not is_port(int(port)):
            return False, "Endpoint port out of range"
        value = host
    elif ":" in value:
        return False, "Endpoint must be bracket-quoted IPv6 if it contains ':port'"

    if not value:
        return False, "Endpoint host is empty"
    if is_ipv4(value) or is_ipv6(value):
        return True, "Endpoint syntax OK"
    if not re.fullmatch(r"^[A-Za-z0-9.\-]{1,253}$", value):
        return False, "Endpoint host must be an IP or a hostname"
    return True, "Endpoint syntax OK"


def normalize_cidrs(values) -> tuple[bool, str, list[str]]:
    """Return normalized, de-duplicated list of CIDRs."""
    if not isinstance(values, (list, tuple)):
        return False, "allowed_ips must be a list of CIDRs", []
    seen: list[str] = []
    try:
        for raw in values:
            if not isinstance(raw, str) or not raw:
                return False, f"Empty CIDR entry in {values!r}", []
            net = ipaddress.ip_network(raw, strict=False)
            if isinstance(net, ipaddress.IPv6Network):
                net = net.supernet(prefixlen_diff=0)
            canonical = net.with_prefixlen
            if canonical not in seen:
                seen.append(canonical)
    except ValueError as exc:
        return False, f"Invalid CIDR list: {exc}", []
    return True, "", seen


def validate_tunnel_input(data: dict) -> list[str]:
    """Structural rules for tunnel creation. Returns list of error strings."""
    errors: list[str] = []
    if not is_interface_name(str(data.get("interface", ""))):
        errors.append("interface must be 1-15 chars of [A-Za-z0-9_=+.-]")
    if data.get("name") is not None and not is_display_name(str(data.get("name"))):
        errors.append("name must be 1-64 word chars")
    role = str(data.get("role", "server"))
    if role not in ("server", "client"):
        errors.append("role must be 'server' or 'client'")
    port = data.get("listen_port")
    if port is None or not is_port(port):
        errors.append("listen_port must be 1-65535")
    for addr in data.get("addresses", []) or []:
        addr = str(addr)
        if is_ipv4(addr) or is_ipv6(addr):
            continue
        if not is_cidr(addr)[0]:
            errors.append(f"tunnel address '{addr}' is not a valid IP or CIDR")
    mtu = data.get("mtu")
    if mtu is not None:
        try:
            if not (576 <= int(mtu) <= 65535):
                errors.append("mtu must be 576-65535")
        except (ValueError, TypeError):
            errors.append("mtu must be an integer")
    return errors


def validate_peer_input(data: dict) -> list[str]:
    errors: list[str] = []
    if not is_display_name(str(data.get("name", ""))):
        errors.append("name must be 1-64 word chars")
    pk = str(data.get("public_key", ""))
    if pk and not is_wg_key(pk):
        errors.append("public_key is not a valid WireGuard key")
    allowed, _, _ = normalize_cidrs(data.get("allowed_ips", []) or [])
    if not allowed:
        errors.append("allowed_ips must contain at least one valid CIDR")
    ep = data.get("endpoint")
    if ep:
        ok, msg = is_endpoint(str(ep))
        if not ok:
            errors.append(msg)
    ka = data.get("persistent_keepalive")
    if ka is not None:
        try:
            if not (0 <= int(ka) <= 65535):
                errors.append("persistent_keepalive must be 0-65535")
        except (ValueError, TypeError):
            errors.append("persistent_keepalive must be an integer")
    return errors