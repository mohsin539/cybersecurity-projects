import pathlib
import sys

import pytest

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.core.config import get_defaults
from app.persistence.audit import AuditLog
from app.persistence.snapshots import SnapshotManager
from app.persistence.store import StateStore
from app.platform.backend import SimulatorBackend
from app.services.base import ServiceContext
from app.services.peer_service import PeerService
from app.services.tunnel_service import TunnelService


@pytest.fixture()
def runtime(tmp_path):
    store = StateStore(tmp_path / "data")
    audit = AuditLog(store.audit_path)
    snapshots = SnapshotManager(store)
    backend = SimulatorBackend(store)
    settings = store.load_settings(get_defaults())
    settings["backend"] = "simulator"

    ctx = ServiceContext.from_parts(store, audit, snapshots, backend)
    tunnels = TunnelService(ctx, lambda: settings)
    peers = PeerService(ctx, lambda: settings, tunnels)
    return {"ctx": ctx, "tunnels": tunnels, "peers": peers,
            "settings": settings, "store": store, "audit": audit}


def test_build_tunnel_idempotent(runtime):
    r = runtime["tunnels"].build({
        "name": "office", "interface": "wg0", "role": "server",
        "listen_port": 51820, "start": True,
    })
    assert r["ok"]
    assert "REDACTED" in r.get("conf", "")
    # rebuilding is a NOOP — same interface must not duplicate
    r2 = runtime["tunnels"].build({
        "name": "office", "interface": "wg0", "role": "server",
        "listen_port": 51820,
    })
    assert r2.get("noop")
    state = runtime["store"].load_state()
    assert len(state["tunnels"]) == 1


def test_build_validates_input(runtime):
    r = runtime["tunnels"].build({"interface": "bad iface name", "role": "x"})
    assert not r["ok"]
    assert r["errors"]


def test_tunnel_start_stop_status(runtime):
    runtime["tunnels"].build({"interface": "wg0", "listen_port": 51820})
    runtime["tunnels"].start("wg0")
    status = runtime["tunnels"].status("wg0")
    assert status["running"] is True
    runtime["tunnels"].stop("wg0")
    assert runtime["tunnels"].status("wg0")["running"] is False


def test_add_peer_and_psk(runtime):
    runtime["tunnels"].build({"interface": "wg0", "listen_port": 51820})
    rt = runtime["tunnels"]
    rp = runtime["peers"]
    result = rp.add("wg0", {
        "name": "laptop",
        "generate_keypair": True,
        "allowed_ips": ["10.9.0.3/32"],
    })
    assert result["ok"]
    peer = result["peer"]
    assert peer["has_psk"]  # psk_enabled by default
    assert peer["allowed_ips"] == ["10.9.0.3/32"]
    conf = rt.export_conf("wg0")
    assert "PresharedKey" in conf
    assert 'PrivateKey = ' in conf
    # conf rendered for display must not leak private key
    from app.platform.configgen import strip_private_key
    shown = strip_private_key(conf)
    assert "REDACTED" in shown
    assert "-- Keypair --" not in shown


def test_add_imported_public_key(runtime):
    from app.core.crypto import generate_private_key, public_from_private
    runtime["tunnels"].build({"interface": "wg0", "listen_port": 51820})
    pub = public_from_private(generate_private_key())
    result = runtime["peers"].add("wg0", {
        "name": "external", "public_key": pub,
        "allowed_ips": ["10.9.0.4/32"], "psk_enabled": False,
    })
    assert result["ok"]
    assert result["peer"]["has_psk"] is False


def test_peer_delete_updates_conf(runtime):
    runtime["tunnels"].build({"interface": "wg0", "listen_port": 51820})
    rp = runtime["peers"]
    p1 = rp.add("wg0", {"name": "a", "generate_keypair": True,
                        "allowed_ips": ["10.9.0.3/32"]})["peer"]
    p2 = rp.add("wg0", {"name": "b", "generate_keypair": True,
                        "allowed_ips": ["10.9.0.4/32"]})["peer"]
    conf = runtime["tunnels"].export_conf("wg0")
    assert conf.count("[Peer]") == 2
    rp.delete(p1["id"])
    conf2 = runtime["tunnels"].export_conf("wg0")
    assert conf2.count("[Peer]") == 1


def test_snapshot_rollback(runtime):
    runtime["tunnels"].build({"interface": "wg0", "listen_port": 51820})
    snap = runtime["tunnels"].snapshot("wg0")
    assert snap["ok"]
    runtime["peers"].add("wg0", {"name": "a", "generate_keypair": True,
                                 "allowed_ips": ["10.9.0.3/32"]})
    assert len(runtime["store"].load_state()["peers"]) == 1
    rt = runtime["tunnels"].rollback("wg0", snap["id"])
    assert rt["ok"]
    assert len(runtime["store"].load_state()["peers"]) == 0


def test_preflight_detects_port_use(runtime):
    # simulator preflight shares socket-based port check; use a bound socket
    import socket
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.bind(("", 0))
    port = s.getsockname()[1]
    issues = runtime["ctx"].backend.preflight("wg0", port)
    assert any("in use" in i for i in issues)
    s.close()


def test_audit_events_recorded_for_mutations(runtime):
    runtime["tunnels"].build({"interface": "wg0", "listen_port": 51820})
    runtime["peers"].add("wg0", {"name": "a", "generate_keypair": True,
                                 "allowed_ips": ["10.9.0.3/32"]})
    events = runtime["audit"].read_all()
    actions = {e["action"] for e in events}
    assert "tunnel.build" in actions
    assert "peer.add" in actions
    ok, _ = runtime["audit"].verify()
    assert ok


def test_fresh_stores_do_not_share_mutable_defaults(tmp_path):
    # Regression: load_state() used to return dict(EMPTY_STATE), a shallow copy
    # whose nested "peers"/"tunnels" lists were shared globals. Mutating state
    # from one fresh store leaked into every other fresh store in the process.
    store_a = StateStore(tmp_path / "a")
    store_b = StateStore(tmp_path / "b")

    state = store_a.load_state()
    assert state["peers"] == []
    state["peers"].append({"id": "leak", "name": "x"})

    fresh_a = store_a.load_state()
    fresh_b = store_b.load_state()
    assert fresh_a["peers"] == []      # end-to-end isolation within one store
    assert fresh_b["peers"] == []      # no leakage across store instances
    assert fresh_b["tunnels"] is not fresh_a["tunnels"]