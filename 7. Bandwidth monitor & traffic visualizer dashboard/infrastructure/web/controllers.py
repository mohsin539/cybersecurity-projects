"""HTTP route handlers (controllers).

Each handler is a plain callable receiving its dependencies explicitly so the
application factory stays the single composition root.  Controllers only speak
in JSON-safe dictionaries produced by ``application.dto``.
"""
from __future__ import annotations

import time
from typing import List, Optional

from application.alerts import AlertService
from application.dto import (
    alert_payload,
    connection_summary_payload,
    history_payload,
    interface_info_payload,
    process_stats_payload,
    snapshot_payload,
)
from application.process_stats import ProcessTrafficService
from application.monitoring import TelemetryService
from config import Settings
from domain.interfaces import SnapshotStore, SystemNetworkSource

# Fixed cap on items flowing over the wire.
MAX_CONNECTIONS_LISTED = 100


def health(
    telemetry: TelemetryService,
    source: SystemNetworkSource,
    settings: Settings,
    process_service: Optional[ProcessTrafficService] = None,
) -> dict:
    latest = telemetry.latest
    payload = {
        "status": "ok",
        "version": settings.version,
        "uptime_seconds": round(telemetry.uptime, 1),
        "samples": telemetry.sample_count,
        "active_interfaces": len(source.list_interfaces()),
        "last_sample_age": round(time.time() - latest.timestamp, 2) if latest else None,
    }
    if process_service is not None:
        payload["process_samples"] = process_service.sample_count
    return payload


def list_interfaces(source: SystemNetworkSource, settings: Settings) -> List[dict]:
    interfaces = [
        interface_info_payload(i)
        for i in source.list_interfaces()
        if settings.interface_enabled(i.name)
    ]
    return interfaces


def current(
    telemetry: TelemetryService,
    alert_service: AlertService,
    settings: Settings,
) -> dict:
    latest = telemetry.latest
    payload = {
        "config_poll_interval": settings.refresh_interval,
        "has_data": latest is not None,
    }
    if latest is not None:
        payload.update(snapshot_payload(latest))
    payload["alerts"] = [alert_payload(a) for a in alert_service.recent(20)]
    return payload


def history(
    store: SnapshotStore,
    interface: Optional[str],
    range_seconds: int,
) -> dict:
    range_seconds = max(5, min(range_seconds, 86400))
    snapshots = store.window(float(range_seconds))

    if interface and interface != "total":
        timestamps = [s.timestamp for s in snapshots]
        download = [
            s.interfaces[interface].download_rate for s in snapshots if interface in s.interfaces
        ]
        upload = [
            s.interfaces[interface].upload_rate for s in snapshots if interface in s.interfaces
        ]
        # Align timestamps with series that may be missing an interface.
        aligned_ts = [s.timestamp for s in snapshots if interface in s.interfaces]
        return history_payload(interface, range_seconds, aligned_ts, download, upload)

    return history_payload(
        "total",
        range_seconds,
        [s.timestamp for s in snapshots],
        [s.total_download for s in snapshots],
        [s.total_upload for s in snapshots],
    )


def connections(source: SystemNetworkSource, settings: Settings) -> dict:
    raw = source.read_connections(MAX_CONNECTIONS_LISTED)
    by_state: dict = {}
    by_protocol: dict = {}
    by_process: dict = {}
    for conn in raw:
        state = conn.state or "UNKNOWN"
        by_state[state] = by_state.get(state, 0) + 1
        by_protocol[conn.protocol] = by_protocol.get(conn.protocol, 0) + 1
        if conn.process_name:
            by_process[conn.process_name] = by_process.get(conn.process_name, 0) + 1

    from domain.entities import ConnectionSummary

    summary = ConnectionSummary(
        total=len(raw),
        by_state=by_state,
        by_protocol=by_protocol,
        by_process=by_process,
        samples=raw,
    )
    return connection_summary_payload(summary, limit=settings.connections_limit)


def alerts(alert_service: AlertService) -> List[dict]:
    return [alert_payload(a) for a in alert_service.recent(100)]


def process_traffic(service: ProcessTrafficService, limit: int = 10) -> dict:
    """Ranked per-process traffic attribution (top talkers)."""
    return process_stats_payload(service.snapshot(limit=limit))


def config(settings: Settings) -> dict:
    return {
        "host": settings.host,
        "port": settings.port,
        "refresh_interval": settings.refresh_interval,
        "history_capacity": settings.history_capacity,
        "connections_enabled": settings.connections_enabled,
        "connections_limit": settings.connections_limit,
        "include_interfaces": settings.include_interfaces,
        "exclude_interfaces": settings.exclude_interfaces,
        "version": settings.version,
        "alerts": {
            "upload_bps": settings.alert_upload_bps,
            "download_bps": settings.alert_download_bps,
            "cooldown_seconds": settings.alert_cooldown_seconds,
        },
    }