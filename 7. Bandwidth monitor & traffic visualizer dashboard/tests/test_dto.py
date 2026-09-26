"""DTO serializers must always produce JSON-safe, versioned payloads."""
import json

from application.dto import (
    connection_summary_payload,
    history_payload,
    interface_traffic_payload,
    snapshot_payload,
)
from domain.entities import (
    ConnectionInfo,
    ConnectionSummary,
    InterfaceTraffic,
    Snapshot,
)

from .fakes import rate_sample


def _sample() -> Snapshot:
    return Snapshot(
        timestamp=123.456,
        interfaces={
            "eth0": InterfaceTraffic(
                name="eth0",
                download_rate=1024.5,
                upload_rate=512.25,
                counters=rate_sample(123.456, rx=9000, tx=4500, rxp=18, txp=9),
            )
        },
        total_download=1024.5,
        total_upload=512.25,
        total_counters=rate_sample(123.456, rx=9000, tx=4500, rxp=18, txp=9),
    )


def test_snapshot_payload_json_safe():
    payload = snapshot_payload(_sample())
    json.dumps(payload)  # must not raise
    assert payload["type"] == "telemetry"
    assert payload["ts"] == 123.456
    assert payload["totals"]["rx_bytes"] == 9000
    assert payload["interfaces"][0]["name"] == "eth0"
    assert payload["interfaces"][0]["download"] == 1024.5


def test_interface_traffic_payload_shape():
    payload = interface_traffic_payload(_sample().interfaces["eth0"])
    assert set(payload) >= {"name", "download", "upload", "rx_bytes", "tx_bytes"}


def test_history_payload_shape():
    payload = history_payload(
        "eth0", 300, [1.0, 2.0], [10.0, 20.0], [5.0, 15.0]
    )
    json.dumps(payload)
    assert payload["sample_count"] == 2
    assert payload["timestamps"] == [1.0, 2.0]


def test_connection_summary_payload():
    summary = ConnectionSummary(
        total=2,
        by_state={"ESTABLISHED": 2},
        by_protocol={"tcp": 2},
        by_process={"prog": 2},
        samples=[
            ConnectionInfo(
                process_name="prog",
                pid=1,
                protocol="tcp",
                family="ipv4",
                state="ESTABLISHED",
                local="127.0.0.1:80",
                remote="127.0.0.1:5000",
            )
        ],
    )
    payload = connection_summary_payload(summary, limit=10)
    json.dumps(payload)
    assert payload["total"] == 2
    assert payload["top_processes"][0]["count"] == 2
    assert payload["connections"][0]["process"] == "prog"