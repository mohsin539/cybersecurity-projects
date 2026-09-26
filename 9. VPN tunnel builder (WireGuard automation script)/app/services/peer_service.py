"""Peer use cases — add, update, remove, rotate PSK (NIST IA-5, AC-3;
OWASP A07 auth of peers by their public key).

Every mutation regenerates the interface config, reloads a running tunnel
(best-effort), and writes an audit event.
"""

from __future__ import annotations

import secrets as _secrets

from ..core.crypto import fingerprint, generate_keypair, generate_preshared_key
from ..core.models import Peer, Tunnel
from ..core.validate import is_wg_key, normalize_cidrs, validate_peer_input
from ..security.redactor import scrub_mapping
from .base import ServiceContext


class PeerService:
    def __init__(self, ctx: ServiceContext, settings_getter, tunnel_service):
        self.ctx = ctx
        self._settings_getter = settings_getter
        self.tunnels = tunnel_service

    def _settings(self) -> dict:
        return self._settings_getter()

    def _audit(self, action, target, result, detail=""):
        self.ctx.audit.append(
            action=action, actor="operator", session="web-ui",
            target=target, result=result,
            detail=scrub_mapping({"detail": (detail or "")[:500]}, action)[:600],
        )

    def list_for(self, interface: str) -> list[dict]:
        state = self.ctx.store.load_state()
        peers = [Peer.from_dict(p) for p in state.get("peers", [])
                 if p.get("tunnel") == interface]
        return [self._decorate(p, state) for p in peers]

    def _decorate(self, peer: Peer, state: dict) -> dict:
        secrets = self.ctx.store.load_secrets()
        has_psk = bool(secrets.get("psks", {}).get(peer.id))
        return {
            **peer.to_dict(),
            "fingerprint": fingerprint(peer.public_key) if is_wg_key(peer.public_key) else "-",
            "has_psk": has_psk,
        }

    def _save_and_reload(self, interface: str) -> None:
        tunnel = self.tunnels.get(interface)
        if not tunnel:
            return
        state = self.ctx.store.load_state()
        self.tunnels.write_conf(tunnel, state)
        conf = self.ctx.store.config_file(interface)
        status = self.ctx.backend.get_status(interface)
        if status.get("running") and not status.get("error"):
            try:
                self.ctx.backend.reload(conf, interface)
            except Exception as exc:  # best-effort reload
                self._audit("peer.reload", interface, "WARN", str(exc)[:300])

    # ------------------------------------------------------------------ add
    def add(self, interface: str, data: dict) -> dict:
        tunnel = self.tunnels.get(interface)
        if not tunnel:
            return {"ok": False, "errors": ["tunnel not found"]}

        errors = validate_peer_input(data)
        if errors:
            return {"ok": False, "errors": errors}
        request_new_key = bool(data.get("generate_keypair"))
        if not request_new_key and not is_wg_key(str(data.get("public_key", ""))):
            return {"ok": False, "errors": ["public_key required unless generating a new keypair"]}

        state = self.ctx.store.load_state()
        settings = self._settings()

        if request_new_key:
            kp = generate_keypair(kind="peer", note=f"peer {data.get('name')}")
            secrets = self.ctx.store.load_secrets()
            secrets["private_keys"][kp["id"]] = kp["private_key"]
            self.ctx.store.save_secrets(secrets)
            public_key = kp["public_key"]
        else:
            public_key = str(data["public_key"]).strip()

        allowed, _, ips = normalize_cidrs(data.get("allowed_ips", []) or [])
        if not allowed:
            return {"ok": False, "errors": ["allowed_ips must contain valid CIDRs > 0"]}

        keepalive = int(data.get("persistent_keepalive", settings.get("default_keepalive", 0)) or 0)

        psk_id = ""
        if settings.get("psk_enabled") and data.get("psk_enabled", True) is not False:
            psk = generate_preshared_key()
            psk_id = _secrets.token_hex(8)
            secrets = self.ctx.store.load_secrets()
            secrets["psks"][psk_id] = psk
            self.ctx.store.save_secrets(secrets)

        peer = Peer(
            id=psk_id or _secrets.token_hex(8),
            tunnel=interface,
            name=str(data.get("name", ""))[:64],
            public_key=public_key,
            allowed_ips=ips,
            endpoint=str(data.get("endpoint", "")).strip() if data.get("endpoint") else "",
            persistent_keepalive=keepalive,
            preshared=bool(psk_id),
            notes=str(data.get("notes", ""))[:200],
        )
        if not peer.id:
            peer.id = _secrets.token_hex(8)

        if tunnel.role == "server":
            peer.endpoint = ""

        state["peers"].append(peer.to_dict())
        self.ctx.store.save_state(state)
        self._save_and_reload(interface)

        self._audit("peer.add", interface, "OK",
                    f"{peer.name} allowed_ips={','.join(ips)} psk={bool(psk_id)}")
        return {"ok": True, "peer": self._decorate(peer, state),
                "message": f"peer {peer.name} added"}

    def _auto_assign_next(self, interface: str, state: dict, tunnel: Tunnel) -> str:
        """Next free /32 in the default subnet (settings-aware)."""
        import ipaddress
        settings = self._settings()
        subnet = ipaddress.ip_network(str(settings.get("default_subnet", "10.9.0.0/24")), strict=False)
        used: set = set()
        used.update(tunnel.addresses)
        for peer in state.get("peers", []):
            if peer.get("tunnel") != interface:
                continue
            for c in peer.get("allowed_ips", []):
                try:
                    used.add(ipaddress.ip_network(c, strict=False).network_address)
                except ValueError:
                    pass
        offset = int(settings.get("first_address_offset", 1))
        for host in list(subnet.hosts())[max(offset, 1):]:
            if host not in used:
                return f"{host}/32"
        return f"{list(subnet.hosts())[1]}/32"

    # ---------------------------------------------------------------- mutate
    def delete(self, peer_id: str) -> dict:
        state = self.ctx.store.load_state()
        target = next((p for p in state.get("peers", []) if p.get("id") == peer_id), None)
        if not target:
            return {"ok": False, "error": "peer not found"}
        interface = target["tunnel"]
        state["peers"] = [p for p in state["peers"] if p.get("id") != peer_id]
        self.ctx.store.save_state(state)
        secrets = self.ctx.store.load_secrets()
        secrets.get("psks", {}).pop(peer_id, None)
        self.ctx.store.save_secrets(secrets)
        self._save_and_reload(interface)
        self._audit("peer.delete", interface, "OK", f"{target.get('name')} removed")
        return {"ok": True, "message": f"peer {target.get('name')} removed"}

    def rotate_psk(self, peer_id: str) -> dict:
        state = self.ctx.store.load_state()
        peer = next((p for p in state.get("peers", []) if p.get("id") == peer_id), None)
        if not peer:
            return {"ok": False, "error": "peer not found"}
        interface = peer["tunnel"]
        secrets = self.ctx.store.load_secrets()
        secrets["psks"][peer_id] = generate_preshared_key()
        self.ctx.store.save_secrets(secrets)
        self._save_and_reload(interface)
        self._audit("peer.rotate_psk", interface, "OK", f"psk rotated for {peer.get('name')}")
        return {"ok": True, "message": f"PSK rotated for {peer.get('name')}"}

    def set_enabled(self, peer_id: str, enabled: bool) -> dict:
        state = self.ctx.store.load_state()
        for p in state.get("peers", []):
            if p.get("id") == peer_id:
                p["enabled"] = bool(enabled)
                interface = p["tunnel"]
                self.ctx.store.save_state(state)
                self._save_and_reload(interface)
                self._audit("peer.enabled" if enabled else "peer.disabled", interface,
                            "OK", p.get("name"))
                return {"ok": True, "message": f"peer {p.get('name')} {'enabled' if enabled else 'disabled'}"}
        return {"ok": False, "error": "peer not found"}

    def update(self, peer_id: str, data: dict) -> dict:
        state = self.ctx.store.load_state()
        for p in state.get("peers", []):
            if p.get("id") != peer_id:
                continue
            interface = p["tunnel"]
            for field in ("notes", "endpoint", "name"):
                if field in data and data[field] is not None:
                    p[field] = str(data[field])[:200 if field == "notes" else 64]
            if data.get("keepalive") is not None:
                try:
                    p["persistent_keepalive"] = max(0, min(65535, int(data["keepalive"])))
                except (ValueError, TypeError):
                    pass
            self.ctx.store.save_state(state)
            self._save_and_reload(interface)
            self._audit("peer.update", interface, "OK", f"updated {p.get('name')}")
            return {"ok": True, "message": "peer updated"}
        return {"ok": False, "error": "peer not found"}