"""End-to-end HTTP/WS smoke tests using FastAPI's TestClient."""
from fastapi.testclient import TestClient

from application.alerts import AlertRule, AlertService
from application.monitoring import TelemetryService
from config import Settings
from infrastructure.storage.ring_buffer import RingBufferSnapshotStore
from infrastructure.web.server import create_app

from .fakes import ScriptedNetworkSource, rate_sample

S0 = ({"eth0": rate_sample(1.0, 0, 0)}, rate_sample(1.0, 0, 0))
S1 = ({"eth0": rate_sample(2.0, 2000, 1000)}, rate_sample(2.0, 2000, 1000))
S2 = ({"eth0": rate_sample(3.0, 4000, 3000)}, rate_sample(3.0, 4000, 3000))


def _settings() -> Settings:
    return Settings(
        host="127.0.0.1",
        port=8000,
        refresh_interval=0.05,
        connections_enabled=True,
        alert_download_bps=1_000_000,
        alert_upload_bps=1_000_000,
    )


def _app():
    source = ScriptedNetworkSource([S0, S1, S2])
    store = RingBufferSnapshotStore(capacity=100)
    alert_service = AlertService([], cooldown_seconds=60)
    telemetry = TelemetryService(source=source, store=store, interval=0.05)
    telemetry.subscribe(alert_service.evaluate)
    app = create_app(
        telemetry=telemetry,
        store=store,
        source=source,
        alert_service=alert_service,
        settings=_settings(),
    )
    return app, telemetry, store


def test_health_and_index():
    app, _, _ = _app()
    with TestClient(app) as client:
        root = client.get("/")
        assert root.status_code == 200
        assert "Bandwidth" in root.text

        health = client.get("/api/health")
        assert health.status_code == 200
        assert health.json()["status"] == "ok"


def test_current_with_data_after_samples():
    app, telemetry, _ = _app()
    telemetry.capture_once()
    telemetry.capture_once()

    with TestClient(app) as client:
        current = client.get("/api/current").json()
        assert current["has_data"] is True
        assert current["totals"]["download"] > 0


def test_history_shapes():
    app, telemetry, store = _app()
    store.push(telemetry.capture_once())
    store.push(telemetry.capture_once())

    with TestClient(app) as client:
        total = client.get("/api/history?interface=total&range_seconds=60").json()
        assert total["sample_count"] >= 2
        assert len(total["download"]) >= 2

        iface = client.get("/api/history?interface=eth0&range_seconds=60").json()
        assert iface["interface"] == "eth0"


def test_connections_and_config():
    app, _, _ = _app()
    with TestClient(app) as client:
        conns = client.get("/api/connections").json()
        assert conns["total"] == 0
        assert "by_protocol" in conns

        cfg = client.get("/api/config").json()
        assert cfg["refresh_interval"] == 0.05
        assert "version" in cfg


def test_websocket_live_feed():
    app, _, _ = _app()
    with TestClient(app) as client:
        with client.websocket_connect("/ws") as ws:
            # Blocks until the first broadcast arrives from the telemetry loop.
            payload = ws.receive_json()
            assert payload["type"] == "telemetry"
            assert "totals" in payload
            assert len(payload["interfaces"]) > 0