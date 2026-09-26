from __future__ import annotations

from ipaddress import ip_network

from . import db
from .config import CFG, SCOPE_DENY_CIDRS

DENY_NETS = [ip_network(cidr, strict=False) for cidr in SCOPE_DENY_CIDRS]


class ScopeError(Exception):
    pass


def list_scopes() -> list[dict]:
    return db.q("SELECT id,cidr,label,added_at FROM scopes ORDER BY id")


def add_scope(cidr: str, label: str = "") -> dict:
    try:
        net = ip_network(cidr.strip(), strict=False)
    except ValueError:
        raise ScopeError(f"invalid CIDR: {cidr!r}")
    if net.prefixlen == 32 and str(net.network_address) not in cidr:
        raise ScopeError("use CIDR notation (e.g. 192.168.1.0/24)")
    db.run("INSERT OR IGNORE INTO scopes(cidr,label,added_at) VALUES(?,?,?)",
           (str(net), label, __import__("app.util", fromlist=["now_ts"]).now_ts()))
    return {"cidr": str(net)}


def remove_scope(cidr: str) -> None:
    db.run("DELETE FROM scopes WHERE cidr=?", (cidr,))


def reset_scopes(default_cidrs: list[str]) -> None:
    db.run("DELETE FROM scopes")
    for cidr in default_cidrs:
        try:
            add_scope(cidr, "default")
        except ScopeError:
            pass


def validate_ip(ip: str) -> bool:
    """True only if ip is inside an operator-declared scope and not in deny list."""
    from .util import ipv4_valid
    if not ipv4_valid(ip):
        return False
    for net in DENY_NETS:
        if ip in net:
            return False
    for row in list_scopes():
        if ip in ip_network(row["cidr"], strict=False):
            return True
    return False


def scope_check(ip: str) -> None:
    if not validate_ip(ip):
        raise ScopeError(f"target {ip!r} not in any declared scope (SCR/SSRF guard)")