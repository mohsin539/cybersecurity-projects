"""Alert engine: threshold firing, cooldown and pending drains."""
import json

from application.alerts import AlertRule, AlertService
from domain.entities import Snapshot

from .fakes import rate_sample


def _snapshot(download_bps, upload_bps) -> Snapshot:
    return Snapshot(
        timestamp=100.0,
        interfaces={
            "eth0": _iface(download_bps, upload_bps),
        },
        total_download=download_bps / 8.0,
        total_upload=upload_bps / 8.0,
        total_counters=rate_sample(100.0, 0, 0),
    )


def _iface(download_bps, upload_bps):
    from domain.entities import InterfaceTraffic

    return InterfaceTraffic(
        name="eth0",
        download_rate=download_bps / 8.0,
        upload_rate=upload_bps / 8.0,
        counters=rate_sample(100.0, 0, 0),
    )


def _service() -> AlertService:
    rules = [
        AlertRule(direction="download", threshold_bps=10_000, interface="eth0"),
        AlertRule(direction="upload", threshold_bps=10_000, interface=None),
    ]
    return AlertService(rules, cooldown_seconds=60.0, history_size=10)


def test_alert_fires_above_threshold():
    svc = _service()
    svc.evaluate(_snapshot(download_bps=20_000, upload_bps=5_000))
    recent = svc.recent()
    assert len(recent) == 1
    assert "exceeds threshold" in recent[0].message
    assert recent[0].value_bps == 20_000.0


def test_alert_payload_is_json_safe():
    from application.dto import alert_payload

    svc = _service()
    svc.evaluate(_snapshot(download_bps=99_000, upload_bps=50_000))
    payloads = [alert_payload(a) for a in svc.recent()]
    json.dumps(payloads)  # must not raise
    assert payloads
    assert payloads[0]["source"] == "bandwidth-policy"


def test_cooldown_suppresses_repeat_emissions():
    svc = _service()
    svc.evaluate(_snapshot(download_bps=20_000, upload_bps=1_000))
    svc.evaluate(_snapshot(download_bps=50_000, upload_bps=1_000))
    assert len(svc.recent()) == 1
    assert len(svc.drain_pending()) == 1
    assert len(svc.drain_pending()) == 0  # second drain is empty


def test_no_alert_under_threshold():
    svc = _service()
    svc.evaluate(_snapshot(download_bps=1_000, upload_bps=1_000))
    assert svc.recent() == []