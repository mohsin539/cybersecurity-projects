"""Pure WireGuard config rendering (no secrets leak: caller supplies keys).

Produces a full, valid wg-quick `[Interface]`/`[Peer]` document. This is the
single source of truth for what actually gets applied to the kernel — so it is
kept as a pure function, unit-testable without root (NIST CM-6, SI-12).
"""

from __future__ import annotations

from ..core.models import Peer, Tunnel
from ..core.validate import is_wg_key


def build_wireguard_config(
    tunnel: Tunnel,
    peers: list[Peer],
    private_key: str,
    psk_map: dict[str, str] | None = None,
) -> str:
    psk_map = psk_map or {}
    lines: list[str] = ["[Interface]", f"PrivateKey = {private_key}"]
    if tunnel.addresses:
        lines.append(f"Address = {', '.join(tunnel.addresses)}")
    if tunnel.role == "server":
        lines.append(f"ListenPort = {tunnel.listen_port}")
        if tunnel.dns:
            pass  # DNS is a client-side directive
    if tunnel.mtu:
        lines.append(f"MTU = {tunnel.mtu}")
    if tunnel.fwmark:
        lines.append(f"FwMark = {tunnel.fwmark}")
    if tunnel.dns and tunnel.role != "server":
        lines.append(f"DNS = {', '.join(tunnel.dns)}")

    for peer in peers:
        if not peer.enabled:
            continue
        lines.append("")
        lines.append("[Peer]")
        lines.append(f"PublicKey = {peer.public_key}")
        psk = psk_map.get(peer.id)
        if psk and is_wg_key(psk):
            lines.append(f"PresharedKey = {psk}")
        if peer.endpoint and tunnel.role != "server":
            lines.append(f"Endpoint = {peer.endpoint}")
        if peer.allowed_ips:
            lines.append(f"AllowedIPs = {', '.join(peer.allowed_ips)}")
        if peer.persistent_keepalive:
            lines.append(f"PersistentKeepalive = {peer.persistent_keepalive}")
    return "\n".join(lines) + "\n"


def strip_private_key(conf_text: str) -> str:
    """Redacted copy of a config for display/audit (keys never logged)."""
    out: list[str] = []
    for line in conf_text.splitlines():
        if line.strip().lower().startswith("privatekey"):
            out.append("PrivateKey = REDACTED")
        elif line.strip().lower().startswith("presharedkey"):
            out.append("PresharedKey = REDACTED")
        else:
            out.append(line)
    return "\n".join(out)


def validate_config_structure(conf_text: str) -> list[str]:
    """Static structural checks — no root, no `wg` binary required."""
    issues: list[str] = []
    if "[Interface]" not in conf_text:
        issues.append("missing [Interface] section")
    if "PrivateKey" not in conf_text:
        issues.append("missing PrivateKey in [Interface]")
    peer_count = conf_text.count("[Peer]")
    if peer_count == 0 and "Server" in conf_text:
        issues.append("no [Peer] sections found")
    for line in conf_text.splitlines():
        key = line.split("=", 1)[0].strip()
        if key and not key[0].isalnum() and not key.startswith("["):
            issues.append(f"suspicious config line: {line[:32]}")
    return issues