"""Serializers that translate domain entities into JSON-safe dictionaries.

Kept in the application layer so that the web adapter never needs to know
about domain internals, and the domain layer never needs to know about JSON.
"""
from __future__ import annotations

from typing import Dict, List

from application.process_stats import ProcessStatsSnapshot
from domain.entities import (
    Alert,
    ConnectionInfo,
    ConnectionSummary,
    InterfaceTraffic,
    NetworkInterfaceInfo,
    RateSample,
    Snapshot,
)


def process_stats_payload(stats: ProcessStatsSnapshot) -> Dict:
    """JSON view of the ranked per-process traffic attribution."""
    return {
        "ts": stats.timestamp,
        "sample_count": stats.sample_count,
        "total_recv_rate": round(stats.total_recv_rate, 3),
        "total_sent_rate": round(stats.total_sent_rate, 3),
        "processes": [
            {
                "pid": p.pid,
                "name": p.name,
                "rate_recv": round(p.rate_recv, 3),
                "rate_sent": round(p.rate_sent, 3),
                "total_recv": round(p.total_recv, 1),
                "total_sent": round(p.total_sent, 1),
            }
            for p in stats.rows
        ],
    }


def _rate_payload(sample: RateSample) -> Dict:
    return {
        "rx_bytes": sample.bytes_recv,
        "tx_bytes": sample.bytes_sent,
        "rx_packets": sample.packets_recv,
        "tx_packets": sample.packets_sent,
        "err_in": sample.errors_in,
        "err_out": sample.errors_out,
        "drop_in": sample.drops_in,
        "drop_out": sample.drops_out,
    }


def interface_traffic_payload(traffic: InterfaceTraffic) -> Dict:
    payload = {
        "name": traffic.name,
        "download": round(traffic.download_rate, 3),  # bytes / second
        "upload": round(traffic.upload_rate, 3),
    }
    payload.update(_rate_payload(traffic.counters))
    return payload


def snapshot_payload(snapshot: Snapshot) -> Dict:
    """The canonical real-time payload streamed to the web socket."""
    totals = _rate_payload(snapshot.total_counters)
    totals["download"] = round(snapshot.total_download, 3)
    totals["upload"] = round(snapshot.total_upload, 3)
    interfaces = sorted(
        (interface_traffic_payload(t) for t in snapshot.interfaces.values()),
        key=lambda item: item["download"] + item["upload"],
        reverse=True,
    )
    return {
        "type": "telemetry",
        "ts": snapshot.timestamp,
        "totals": totals,
        "interfaces": interfaces,
    }


def interface_info_payload(info: NetworkInterfaceInfo) -> Dict:
    return {
        "name": info.name,
        "up": info.is_up,
        "running": info.is_running,
        "mac": info.mac_address,
        "addresses": info.addresses,
        "speed_mbps": info.speed_mbps,
        "virtual": info.is_virtual,
    }


def connection_payload(conn: ConnectionInfo) -> Dict:
    return {
        "process": conn.process_name,
        "pid": conn.pid,
        "proto": conn.protocol,
        "family": conn.family,
        "state": conn.state,
        "local": conn.local,
        "remote": conn.remote,
        "fd": conn.fd,
    }


def connection_summary_payload(summary: ConnectionSummary, limit: int) -> Dict:
    by_process = sorted(
        summary.by_process.items(), key=lambda kv: kv[1], reverse=True
    )[:limit]
    return {
        "total": summary.total,
        "by_state": summary.by_state,
        "by_protocol": summary.by_protocol,
        "top_processes": [
            {"name": name, "count": count} for name, count in by_process
        ],
        "connections": [connection_payload(c) for c in summary.samples],
    }


def alert_payload(alert: Alert) -> Dict:
    return {
        "severity": alert.severity,
        "source": alert.source,
        "message": alert.message,
        "timestamp": alert.timestamp,
        "value_bps": round(alert.value_bps),
        "threshold_bps": round(alert.threshold_bps),
    }


def history_payload(
    interface: str,
    seconds: int,
    timestamps: List[float],
    download: List[float],
    upload: List[float],
) -> Dict:
    return {
        "interface": interface,
        "range": seconds,
        "sample_count": len(timestamps),
        "timestamps": timestamps,
        "download": [round(v, 3) for v in download],
        "upload": [round(v, 3) for v in upload],
    }