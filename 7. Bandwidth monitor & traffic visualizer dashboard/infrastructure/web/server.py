"""FastAPI application factory — the composition root of the delivery layer.

Assembles the domain services and infrastructure adapters into a running web
application, wires the real-time pipeline (telemetry > WebSocket) and exposes
the REST API + static dashboard.
"""
from __future__ import annotations

import asyncio
import logging
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Optional

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from application.alerts import AlertRule, AlertService
from application.dto import alert_payload, process_stats_payload, snapshot_payload
from application.monitoring import TelemetryService
from application.process_stats import ProcessTrafficService
from config import Settings
from domain.entities import Snapshot
from domain.interfaces import SnapshotStore, SystemNetworkSource

from . import controllers
from .manager import ConnectionManager

logger = logging.getLogger(__name__)

STATIC_ROOT = Path(__file__).resolve().parents[2] / "presentation" / "static"


def create_app(
    *,
    telemetry: TelemetryService,
    store: SnapshotStore,
    source: SystemNetworkSource,
    alert_service: AlertService,
    settings: Settings,
    process_service: Optional[ProcessTrafficService] = None,
) -> FastAPI:
    """Build a fully wired FastAPI instance."""
    manager = ConnectionManager()

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        manager.bind_loop(asyncio.get_running_loop())
        telemetry.start()
        yield
        telemetry.stop()

    app = FastAPI(
        title="Bandwidth Monitor & Traffic Visualizer",
        description="Real-time network traffic monitoring and visualization dashboard.",
        version=settings.version,
        lifespan=lifespan,
    )

    # ------------------------------------------------------------------ #
    # Real-time pipeline: telemetry thread -> WebSocket broadcast.
    # ------------------------------------------------------------------ #
    def publish_snapshot(snapshot: Snapshot) -> None:
        payload = snapshot_payload(snapshot)
        pending_alerts = alert_service.drain_pending()
        if pending_alerts:
            payload["alerts"] = [alert_payload(a) for a in pending_alerts]
        manager.publish(payload)

    telemetry.subscribe(publish_snapshot)

    # ------------------------------------------------------------------ #
    # HTTP REST API
    # ------------------------------------------------------------------ #
    @app.get("/", include_in_schema=False)
    def index() -> FileResponse:
        return FileResponse(STATIC_ROOT / "index.html")

    @app.get("/api/health", tags=["system"])
    def api_health() -> dict:
        return controllers.health(telemetry, source, settings, process_service)

    @app.get("/api/processes", tags=["telemetry"])
    def api_processes(limit: int = 10):
        if process_service is None:
            return {
                "enabled": False,
                "processes": [],
                "total_recv_rate": 0.0,
                "total_sent_rate": 0.0,
                "ts": None,
                "sample_count": 0,
            }
        payload = process_stats_payload(process_service.snapshot(limit=max(1, min(limit, 50))))
        payload["enabled"] = True
        return payload

    @app.get("/api/interfaces", tags=["telemetry"])
    def api_interfaces():
        return controllers.list_interfaces(source, settings)

    @app.get("/api/current", tags=["telemetry"])
    def api_current() -> dict:
        return controllers.current(telemetry, alert_service, settings)

    @app.get("/api/history", tags=["telemetry"])
    def api_history(interface: Optional[str] = "total", range_seconds: int = 300):
        return controllers.history(store, interface, range_seconds)

    @app.get("/api/connections", tags=["telemetry"])
    def api_connections():
        return controllers.connections(source, settings)

    @app.get("/api/alerts", tags=["system"])
    def api_alerts():
        return controllers.alerts(alert_service)

    @app.get("/api/config", tags=["system"])
    def api_config() -> dict:
        return controllers.config(settings)

    # ------------------------------------------------------------------ #
    # WebSocket live feed
    # ------------------------------------------------------------------ #
    @app.websocket("/ws")
    async def websocket_endpoint(websocket: WebSocket) -> None:
        await manager.connect(websocket)
        try:
            while True:
                # Keep the socket healthy; clients send lightweight pings.
                await websocket.receive_text()
        except WebSocketDisconnect:
            manager.disconnect(websocket)
            logger.info("WebSocket client disconnected")
        except Exception:  # noqa: BLE001
            manager.disconnect(websocket)

    # ------------------------------------------------------------------ #
    # Static assets (JS / CSS / images)
    # ------------------------------------------------------------------ #
    app.mount("/static", StaticFiles(directory=STATIC_ROOT), name="static")
    return app


def build_default_alert_service(settings: Settings) -> AlertService:
    """Construct alert rules from the runtime settings's threshold policy."""
    rules = [
        AlertRule(
            direction="download",
            threshold_bps=settings.alert_download_bps,
            severity="warning",
            source="policy",
        ),
        AlertRule(
            direction="upload",
            threshold_bps=settings.alert_upload_bps,
            severity="warning",
            source="policy",
        ),
    ]
    return AlertService(
        rules,
        cooldown_seconds=settings.alert_cooldown_seconds,
        history_size=200,
    )