"""End-to-end tests: real browser, real server, real WebSocket stream.

Run with:
    pytest tests/test_e2e_dashboard.py -m e2e

Requires:
    pip install -r requirements-dev.txt
    playwright install chromium

These tests boot the actual FastAPI app (uvicorn on a free port) with a
synthetic network source, load the dashboard in headless Chromium, and assert
that the charts render, gauges show the alert-threshold marker, and live
telemetry flows through the WebSocket.
"""
from __future__ import annotations

import socket
import threading
import time
import urllib.request

import pytest

pytest.importorskip("playwright.sync_api", reason="playwright is not installed")

from playwright.sync_api import sync_playwright  # noqa: E402

from application.alerts import AlertService  # noqa: E402
from application.monitoring import TelemetryService  # noqa: E402
from application.process_stats import ProcessTrafficService  # noqa: E402
from config import Settings  # noqa: E402
from domain.entities import NetworkInterfaceInfo, RateSample  # noqa: E402
from domain.interfaces import SystemNetworkSource  # noqa: E402
from infrastructure.capture.psutil_process_traffic import (  # noqa: E402
    PsutilProcessTrafficSource,
)
from infrastructure.storage.ring_buffer import RingBufferSnapshotStore  # noqa: E402
from infrastructure.web.server import build_default_alert_service, create_app  # noqa: E402

DL_RATE_BPS = 2_000_000  # synthetic download: 2 Mbit/s
UL_RATE_BPS = 600_000  # synthetic upload
DL_THRESHOLD_BPS = 10_000_000  # gauge marker sits at 10 Mbit/s


class SyntheticNetworkSource(SystemNetworkSource):
    """Grows counters at a constant rate so derived rates are stable/non-zero."""

    def __init__(self) -> None:
        self._t0 = time.time()
        self._interfaces = [
            NetworkInterfaceInfo(
                name="eth0",
                is_up=True,
                is_running=True,
                mac_address="00:11:22:33:44:55",
                addresses=["ipv4 10.0.0.2"],
                speed_mbps=1000,
                is_virtual=False,
            )
        ]

    def _counters(self) -> RateSample:
        elapsed = max(0.0, time.time() - self._t0)
        rx = int(elapsed * DL_RATE_BPS / 8)
        tx = int(elapsed * UL_RATE_BPS / 8)
        return RateSample(
            timestamp=time.time(),
            bytes_recv=rx,
            bytes_sent=tx,
            packets_recv=rx // 1500,
            packets_sent=tx // 1500,
        )

    def list_interfaces(self):
        return self._interfaces

    def read_counters(self):
        return {"eth0": self._counters()}

    def read_total(self):
        return self._counters()

    def read_connections(self, limit):
        return []


def _free_port() -> int:
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


@pytest.fixture(scope="session")
def live_server():
    """Boot the real app on a free port and yield its base URL."""
    port = _free_port()
    settings = Settings(
        host="127.0.0.1",
        port=port,
        refresh_interval=0.5,
        alert_download_bps=DL_THRESHOLD_BPS,
        alert_upload_bps=DL_THRESHOLD_BPS,
        processes_enabled=True,
        process_scan_spacing=1.0,
    )
    source = SyntheticNetworkSource()
    store = RingBufferSnapshotStore(capacity=1000)
    alert_service: AlertService = build_default_alert_service(settings)
    telemetry = TelemetryService(source=source, store=store, interval=0.5)
    telemetry.subscribe(alert_service.evaluate)

    process_source = PsutilProcessTrafficSource(min_scan_spacing=1.0)
    process_service = ProcessTrafficService(process_source)
    telemetry.subscribe(lambda _snap: process_service.update(process_source.sample()))

    app = create_app(
        telemetry=telemetry,
        store=store,
        source=source,
        alert_service=alert_service,
        settings=settings,
        process_service=process_service,
    )

    import uvicorn

    config = uvicorn.Config(app, host="127.0.0.1", port=port, log_level="warning", access_log=False)
    server = uvicorn.Server(config)
    thread = threading.Thread(target=server.run, daemon=True)
    thread.start()

    base = f"http://127.0.0.1:{port}"
    deadline = time.time() + 20
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(f"{base}/api/health", timeout=1) as resp:
                if resp.status == 200:
                    break
        except Exception:
            time.sleep(0.2)
    else:
        telemetry.stop()
        raise RuntimeError("e2e server did not become ready in time")

    yield base
    telemetry.stop()
    server.should_exit = True
    thread.join(timeout=10)


@pytest.fixture(scope="session")
def browser():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        yield browser
        browser.close()


@pytest.fixture()
def page(browser):
    context = browser.new_context()
    page = context.new_page()
    yield page
    context.close()


def _open_dashboard(page, live_server):
    page.goto(f"{live_server}/")
    page.wait_for_function("() => window.__bwmon !== undefined", timeout=15000)


@pytest.mark.e2e
def test_dashboard_loads_and_all_charts_render(live_server, page):
    _open_dashboard(page, live_server)

    assert "Bandwidth" in page.title()
    for selector in [
        "#traffic-chart",
        "#iface-chart",
        "#proto-chart",
        "#gauge-in",
        "#gauge-out",
        "#proc-chart",
    ]:
        assert page.locator(selector).count() == 1, f"missing canvas {selector}"

    wired = page.evaluate("Object.keys(window.__bwmon.charts)")
    assert set(wired) >= {"traffic", "interface", "protocol", "processes", "gaugeIn", "gaugeOut"}


@pytest.mark.e2e
def test_live_telemetry_flows_through_websocket(live_server, page):
    _open_dashboard(page, live_server)

    # WebSocket must connect…
    page.wait_for_function("() => window.__bwmon.wsConnected()", timeout=10000)
    # …and the traffic chart must accumulate live points.
    page.wait_for_function(
        "() => (window.__bwmon.charts.traffic.data.labels || []).length >= 3",
        timeout=20000,
    )

    # Gauge readout shows a formatted rate.
    text = page.locator("#gauge-in-value").inner_text()
    assert "bps" in text

    # KPI cards show a non-zero cumulative download (synthetic source grows).
    page.wait_for_function(
        "() => document.querySelector('#kpi-rx').textContent.trim() !== '0 B'",
        timeout=15000,
    )


@pytest.mark.e2e
def test_gauge_threshold_marker_matches_config(live_server, page):
    _open_dashboard(page, live_server)

    threshold = page.evaluate("window.__bwmon.charts.gaugeIn.$gauge.threshold")
    assert threshold == DL_THRESHOLD_BPS

    # Scale always leaves headroom above the threshold so the marker is visible.
    scale_max = page.evaluate("window.__bwmon.charts.gaugeIn.$gauge.max")
    assert scale_max >= threshold

    # Threshold marker plugin is registered on the gauge instance.
    plugins = page.evaluate(
        "window.__bwmon.charts.gaugeIn.config.plugins.map(p => p.id)"
    )
    assert "thresholdMarker" in plugins


@pytest.mark.e2e
def test_process_attribution_renders(live_server, page):
    _open_dashboard(page, live_server)

    payload = page.evaluate("fetch('/api/processes?limit=5').then(r => r.json())")
    assert payload["enabled"] is True
    assert isinstance(payload["processes"], list)

    # The card reports status (labels may lag while the baseline is collected).
    page.wait_for_function(
        "() => document.querySelector('#proc-meta').textContent.length > 0",
        timeout=10000,
    )


@pytest.mark.e2e
def test_history_endpoint_backs_the_chart_seed(live_server, page):
    _open_dashboard(page, live_server)

    payload = page.evaluate(
        "fetch('/api/history?interface=total&range_seconds=60').then(r => r.json())"
    )
    assert payload["interface"] == "total"
    assert payload["sample_count"] >= 1
    assert len(payload["download"]) == payload["sample_count"]
