"""Ring buffer store behaviour: eviction, windowing, ordering."""
from infrastructure.storage.ring_buffer import RingBufferSnapshotStore

from .fakes import rate_sample
from domain.entities import Snapshot


def _snapshot(ts: float, dl: float = 1.0, ul: float = 0.5) -> Snapshot:
    return Snapshot(
        timestamp=ts,
        interfaces={},
        total_download=dl,
        total_upload=ul,
        total_counters=rate_sample(ts, 0, 0),
    )


def test_capacity_evicts_oldest():
    store = RingBufferSnapshotStore(capacity=3)
    for ts in range(10, 14):
        store.push(_snapshot(float(ts)))
    assert store.size == 3
    latest = store.latest()
    assert latest is not None and latest.timestamp == 13.0


def test_window_returns_chronological_subset():
    store = RingBufferSnapshotStore(capacity=100)
    for ts in range(10, 20):
        store.push(_snapshot(float(ts)))

    # Session now: ts=19; window of 6s => >= 13.0
    results = store.window(seconds=6.0)
    assert [s.timestamp for s in results] == [13.0, 14.0, 15.0, 16.0, 17.0, 18.0, 19.0]


def test_latest_empty_store_is_none():
    store = RingBufferSnapshotStore()
    assert store.latest() is None
    assert store.window(10.0) == []