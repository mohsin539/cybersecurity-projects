"""Rate derivation between consecutive counter reads."""
import time

from application.monitoring import TelemetryService
from infrastructure.storage.ring_buffer import RingBufferSnapshotStore

from .fakes import DummySnapshotListener, ScriptedNetworkSource, rate_sample

ETH0_T0 = rate_sample(100.0, 0, 0)
WLAN_T0 = rate_sample(100.0, 0, 0)
ETH0_T1 = rate_sample(102.0, 2000, 1000, rxp=40, txp=20)
WLAN_T1 = rate_sample(102.0, 500, 250, rxp=10, txp=5)

T0_COUNTERS = {"eth0": ETH0_T0, "wlan0": WLAN_T0}
T1_COUNTERS = {"eth0": ETH0_T1, "wlan0": WLAN_T1}
TOTAL_T1 = rate_sample(102.0, 2500, 1250)


def _service(script) -> TelemetryService:
    source = ScriptedNetworkSource(script)
    store = RingBufferSnapshotStore(capacity=64)
    return TelemetryService(source=source, store=store, interval=0.05)


def test_first_sample_has_zero_rates():
    service = _service([(T1_COUNTERS, TOTAL_T1)])
    snap = service.capture_once()
    assert snap.interfaces["eth0"].download_rate == 0.0
    assert snap.total_upload == 0.0


def test_rates_derived_from_delta():
    service = _service([(T0_COUNTERS, rate_sample(100.0, 0, 0)), (T1_COUNTERS, TOTAL_T1)])
    service.capture_once()  # baseline
    snap = service.capture_once()

    eth0 = snap.interfaces["eth0"]
    # 2000 bytes ingress over 2 seconds -> 1000 B/s; egress 500 B/s.
    assert eth0.download_rate == 1000.0
    assert eth0.upload_rate == 500.0
    assert snap.total_download == 1250.0
    assert snap.total_upload == 625.0


def test_counter_reset_is_guarded():
    script = [
        (T0_COUNTERS, rate_sample(100.0, 0, 0)),
        (T1_COUNTERS, TOTAL_T1),
        ({"eth0": rate_sample(103.0, 100, 50), "wlan0": rate_sample(103.0, 10, 5)},
         rate_sample(103.0, 110, 55)),
    ]
    service = _service(script)
    service.capture_once()
    service.capture_once()
    snap = service.capture_once()
    # Counter went backwards: treat as reset, rate clamps to zero.
    assert snap.interfaces["eth0"].download_rate == 0.0
    assert snap.interfaces["eth0"].upload_rate == 0.0


def test_loop_pushes_snapshots_and_notifies_listeners():
    listener = DummySnapshotListener()
    service = _service([(T0_COUNTERS, rate_sample(100.0, 0, 0)), (T1_COUNTERS, TOTAL_T1)])
    service.subscribe(listener)
    service.start()
    try:
        deadline = time.time() + 2.0
        while len(listener.received) < 2 and time.time() < deadline:
            time.sleep(0.02)
    finally:
        service.stop()

    assert service.running is False
    assert len(listener.received) >= 1
    assert service.sample_count >= 1


def test_monotonic_multiple_interfaces():
    service = _service([(T0_COUNTERS, rate_sample(100.0, 0, 0)), (T1_COUNTERS, TOTAL_T1)])
    service.capture_once()
    snap = service.capture_once()
    assert {k for k in snap.interfaces} == {"eth0", "wlan0"}
    assert snap.interfaces["eth0"].download_rate == 1000.0
    assert snap.interfaces["wlan0"].download_rate == 250.0
    assert snap.total_download == 1250.0