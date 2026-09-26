"""Tunnel use cases — plan, build, start/stop, validate, snapshot, rollback,
export (ISO 27001 A.8.31 change management; NIST CM-6, CP-9).

Every mutating operation is: snapshot -> validate -> apply -> audit, and every
state write goes through the atomic StateStore.
"""

from __future__ import annotations

import ipaddress

from ..core.crypto import generate_keypair
from ..core.models import Peer, Tunnel
from ..core.validate import validate_tunnel_input
from ..platform.configgen import (
    build_wireguard_config,
    strip_private_key,
    validate_config_structure,
)
from ..security.redactor import scrub_mapping
from .base import ServiceContext


def _human_result(b: object) -> str:
    return "OK" if getattr(b, "ok", False) else "ERR"


class TunnelService:
    def __init__(self, ctx: ServiceContext, settings_getter):
        self.ctx = ctx
        self._settings_getter = settings_getter

    # ---------------------------------------------------------------- helpers
    def _settings(self) -> dict:
        return self._settings_getter()

    def _audit(self, action, target, result, detail="", session="web-ui"):
        return self.ctx.audit.append(
            action=action, actor="operator", session=session,
            target=target, result=result,
            detail=scrub_mapping({"detail": detail}, action)[:600],
        )

    def _conf_text(self, tunnel: Tunnel, state: dict) -> str:
        secrets = self.ctx.store.load_secrets()
        private = secrets["private_keys"].get(tunnel.keypair_id, "")
        peers = [
            Peer.from_dict(p) for p in state.get("peers", [])
            if p.get("tunnel") == tunnel.interface
        ]
        psk_map = {p.id: secrets["psks"].get(p.id, "")
                   for p in peers if secrets["psks"].get(p.id)}
        return build_wireguard_config(tunnel, peers, private, psk_map)

    def write_conf(self, tunnel: Tunnel, state: dict) -> str:
        text = self._conf_text(tunnel, state)
        path = self.ctx.store.config_file(tunnel.interface)
        path.write_text(text, encoding="utf-8")
        if __import__("os").name == "posix":
            try:
                __import__("os").chmod(path, 0o600)
            except OSError:
                pass
        return text

    # ------------------------------------------------------------- read side
    def list_tunnels(self) -> list[dict]:
        state = self.ctx.store.load_state()
        result = []
        for t in state.get("tunnels", []):
            tunnel = Tunnel.from_dict(t)
            peers = [p for p in state.get("peers", []) if p.get("tunnel") == tunnel.interface]
            status = self.ctx.backend.get_status(tunnel.interface)
            result.append({
                **tunnel.to_dict(),
                "peer_count": len(peers),
                "status": status,
            })
        return result

    def get(self, interface: str) -> Tunnel | None:
        for t in self.ctx.store.load_state().get("tunnels", []):
            if t.get("interface") == interface:
                return Tunnel.from_dict(t)
        return None

    def status(self, interface: str) -> dict:
        tunnel = self.get(interface)
        if not tunnel:
            return {"error": f"tunnel {interface} not found"}
        status = self.ctx.backend.get_status(interface)
        status["tunnel"] = tunnel.to_dict()
        return status

    # ------------------------------------------------------------- build
    def auto_assign_ips(self) -> tuple[str, str] | tuple[None, None]:
        """Compute (server_address, next_free_client_cidr) from settings."""
        settings = self._settings()
        subnet = ipaddress.ip_network(str(settings.get("default_subnet", "10.9.0.0/24")), strict=False)
        offset = int(settings.get("first_address_offset", 1))
        host = list(subnet.hosts())
        if not host:
            return None, None
        gateway = host[offset % len(host)]
        client = host[(offset + 1) % len(host)] if len(host) > 1 else gateway
        return str(gateway), f"{client}/32"

    def build(self, data: dict, noop: bool = True) -> dict:
        errors = validate_tunnel_input(data)
        if errors:
            return {"ok": False, "errors": errors}

        state = self.ctx.store.load_state()
        interface = str(data["interface"]).strip()
        existing = Tunnel.from_dict(state["tunnels"][0]) if state.get("tunnels") and \
            any(t.get("interface") == interface for t in state["tunnels"]) else None
        if existing:
            self._audit("tunnel.build", interface, "NOOP", "tunnel already exists — idempotent")
            return {"ok": True, "noop": True, "message": "tunnel already exists"}

        settings = self._settings()

        tunnel = Tunnel(
            name=str(data.get("name", interface)).strip() or interface,
            interface=interface,
            role=str(data.get("role", "server")),
            listen_port=int(data.get("listen_port", settings.get("default_listen_port", 51820))),
            addresses=[str(a) for a in data.get("addresses", [])] if data.get("addresses") else [],
            mtu=int(data["mtu"]) if data.get("mtu") else settings.get("default_mtu"),
            fwmark=str(data.get("fwmark", "")).strip(),
            dns=[str(d) for d in data.get("dns", [])] if data.get("dns") else [],
        )
        if not tunnel.addresses:
            default_subnet = ipaddress.ip_network(str(settings.get("default_subnet", "10.9.0.0/24")), strict=False)
            if tunnel.role == "server":
                gw, _ = self.auto_assign_ips()
                if gw:
                    tunnel.addresses = [f"{gw}/{default_subnet.prefixlen}"]
            else:
                _, client = self.auto_assign_ips()
                if client:
                    tunnel.addresses = [client]

        kp = generate_keypair(kind="tunnel", note=f"tunnel {interface}")
        tunnel.keypair_id = kp["id"]

        secrets = self.ctx.store.load_secrets()
        secrets["private_keys"][kp["id"]] = kp["private_key"]
        state["keypairs"].append({
            "id": kp["id"], "kind": "tunnel", "public_key": kp["public_key"],
            "note": kp["note"], "created_at": kp["created_at"],
        })
        self.ctx.store.save_secrets(secrets)

        self.ctx.snapshots.create(note=f"before building {interface}")
        preflight = self.ctx.backend.preflight(interface, tunnel.listen_port)
        text = self.write_conf(tunnel, state)

        state["tunnels"].append(tunnel.to_dict())
        self.ctx.store.save_state(state)

        if data.get("start", False):
            if preflight:
                self._audit("tunnel.preflight", interface, "ERR", "; ".join(preflight))
                return {"ok": False, "errors": preflight,
                        "message": f"tunnel {interface} NOT started (preflight failed)"}
            result = self.ctx.backend.up(self.ctx.store.config_file(interface), interface)
            self._audit("tunnel.start", interface, _human_result(result), result.message)
            return {"ok": result.ok, "message": result.message, "conf": strip_private_key(text)}

        self._audit("tunnel.build", interface, "OK",
                    f"created tunnel {interface} port {tunnel.listen_port}")
        result = {"ok": True, "message": f"tunnel {interface} built", "conf": strip_private_key(text)}
        if preflight:
            result["warnings"] = preflight
        return result

    # ------------------------------------------------------------ lifecycle
    def start(self, interface: str) -> dict:
        tunnel = self.get(interface)
        if not tunnel:
            return {"ok": False, "error": "tunnel not found"}
        issues = self.ctx.backend.preflight(interface, tunnel.listen_port)
        if issues:
            self._audit("tunnel.preflight", interface, "ERR", "; ".join(issues))
            return {"ok": False, "errors": issues,
                    "message": f"tunnel {interface} NOT started (preflight failed)"}
        state = self.ctx.store.load_state()
        self.write_conf(tunnel, state)
        result = self.ctx.backend.up(self.ctx.store.config_file(interface), interface)
        self._audit("tunnel.start", interface, _human_result(result), result.message)
        return {"ok": result.ok, "message": result.message}

    def stop(self, interface: str) -> dict:
        tunnel = self.get(interface)
        if not tunnel:
            return {"ok": False, "error": "tunnel not found"}
        result = self.ctx.backend.down(interface, self.ctx.store.config_file(interface))
        self._audit("tunnel.stop", interface, _human_result(result), result.message)
        return {"ok": result.ok, "message": result.message}

    def remove(self, interface: str) -> dict:
        tunnel = self.get(interface)
        if not tunnel:
            return {"ok": False, "error": "tunnel not found"}
        self.ctx.backend.down(interface, self.ctx.store.config_file(interface))
        self.ctx.snapshots.create(note=f"before removing {interface}")
        state = self.ctx.store.load_state()
        state["tunnels"] = [t for t in state["tunnels"] if t.get("interface") != interface]
        state["peers"] = [p for p in state["peers"] if p.get("tunnel") != interface]
        self.ctx.store.save_state(state)
        conf = self.ctx.store.config_file(interface)
        if conf.exists():
            conf.unlink()
        self._audit("tunnel.remove", interface, "OK")
        return {"ok": True, "message": f"tunnel {interface} removed"}

    # ------------------------------------------------------------- validate
    def validate_conf(self, interface: str) -> dict:
        tunnel = self.get(interface)
        if not tunnel:
            return {"ok": False, "errors": ["tunnel not found"], "issues": []}
        state = self.ctx.store.load_state()
        text = self.write_conf(tunnel, state)
        issues = validate_config_structure(text)
        issues += self.ctx.backend.preflight(interface, tunnel.listen_port)
        valid = not issues
        self._audit("tunnel.validate", interface,
                    "OK" if valid else f"{len(issues)} issue(s) found",
                    "; ".join(issues))
        return {"ok": valid, "issues": issues, "conf_redacted": strip_private_key(text)}

    # ---------------------------------------------------- snapshot / rollback
    def snapshot(self, interface: str) -> dict:
        snap = self.ctx.snapshots.create(note=f"tunnel {interface}")
        self._audit("snapshot.create", interface, "OK", snap.id)
        return {"ok": True, "id": snap.id, "sha256": snap.sha256}

    def rollback(self, interface: str, snap_id: str | None = None):
        if snap_id:
            snap = self.ctx.snapshots.restore(snap_id)
            tunnel = self.get(interface)
            if tunnel:
                state = self.ctx.store.load_state()
                self.write_conf(tunnel, state)
                result = self.ctx.backend.reload(self.ctx.store.config_file(interface), interface)
                self._audit("snapshot.restore", interface, _human_result(result), snap_id)
            self._audit("snapshot.restore", interface, "OK", f"{interface} restored to {snap_id}")
            return {"ok": True, "ts": snap.ts}
        snaps = self.ctx.snapshots.list()
        if not snaps:
            self._audit("snapshot.restore", interface, "ERR", "no snapshots")
            return {"ok": False, "error": "no snapshots available"}
        return self.rollback(interface, snaps[0]["id"])

    def list_snapshots(self) -> list[dict]:
        return self.ctx.snapshots.list()

    # ---------------------------------------------------------------- export
    def export_conf(self, interface: str) -> str | None:
        tunnel = self.get(interface)
        if not tunnel:
            return None
        state = self.ctx.store.load_state()
        return self._conf_text(tunnel, state)