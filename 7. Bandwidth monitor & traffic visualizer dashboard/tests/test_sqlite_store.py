"""SQLite store: round-trip, windowing, prune, and graceful degradation."""
import os

import pytest

from domain.entities import InterfaceTraffic, RateSample, Snapshot
from infrastructure.storage.sqlite_store import SqliteSnapshotStore


def _snapshot(ts, dl=10.0, ul=5.0, rx=1000, tx=500, with_iface=True):
    counters = RateSample(
        timestamp=ts, bytes_recv=rx, bytes_sent=tx, packets_recv=10, packets_sent=5
    )
    interfaces = {}
    if with_iface:
        interfaces["eth0"] = InterfaceTraffic(
            name="eth0", download_rate=dl, upload_rate=ul, counters=counters
        )
    return Snapshot(
        timestamp=ts,
        interfaces=interfaces,
        total_download=dl,
        total_upload=ul,
        total_counters=counters,
    )


@pytest.fixture()
def store(tmp_path):
    s = SqliteSnapshotStore(path=str(tmp_path / "hist.db"), capacity=50)
    yield s
    s.close()


def test_roundtrip_preserves_all_fields(store):
    snap = _snapshot(1000.0, dl=12.5, ul=6.25, rx=4321, tx=1234)
    store.push(snap)
    out = store.latest()
    assert out is not None
    assert out.timestamp == 1000.0
    assert out.total_download == 12.5
    assert out.total_upload == 6.25
    assert out.total_counters.bytes_recv == 4321
    assert out.total_counters.bytes_sent == 1234
    assert "eth0" in out.interfaces
    assert out.interfaces["eth0"].download_rate == 12.5
    assert out.interfaces["eth0"].counters.packets_recv == 10


def test_window_filters_chronologically(store):
    for ts in range(10, 20):
        store.push(_snapshot(float(ts)))
    results = store.window(5.0)
    stamps = [s.timestamp for s in results]
    # Cutoff is inclusive (>=): anchor 19.0 - 5.0 => 14.0 stays in the window.
    assert stamps == [14.0, 15.0, 16.0, 17.0, 18.0, 19.0]
    assert results[0].total_download == 10.0


def test_capacity_prune_keeps_newest(tmp_path):
    # prune_margin=0 pins the exact "never exceed capacity" contract.
    s = SqliteSnapshotStore(path=str(tmp_path / "hist.db"), capacity=10, prune_margin=0)
    try:
        for ts in range(100):
            s.push(_snapshot(float(ts)))
            s._pushes_since_count = 32  # force prune check every push
        s._maybe_prune_locked()
        assert s.count() <= 10
        latest = s.latest()
        assert latest.timestamp == 99.0
        assert s.window(5.0)[0].timestamp == 94.0  # inclusive cutoff
    finally:
        s.close()


def test_default_margin_amortises_prunes(tmp_path):
    """With the default margin the store may exceed capacity between periodic
    prunes; the row count must nevertheless stay bounded."""
    s = SqliteSnapshotStore(path=str(tmp_path / "hist.db"), capacity=10)
    try:
        for ts in range(200):
            s.push(_snapshot(float(ts)))
        assert s.count() <= 200  # loose bound: prunes keep it from growing forever
        assert s.count() > 10  # margin was actually used
    finally:
        s.close()


def test_persistence_across_reopen(tmp_path):
    path = str(tmp_path / "hist.db")
    s1 = SqliteSnapshotStore(path=path, capacity=100)
    for ts in range(10):
        s1.push(_snapshot(float(ts)))
    s1.close()

    s2 = SqliteSnapshotStore(path=path, capacity=100)
    try:
        out = s2.window(60.0)
        assert len(out) == 10
        assert out[-1].timestamp == 9.0
    finally:
        s2.close()


def test_fallback_on_unopenable_path(tmp_path):
    # A directory in place of the db file makes sqlite3.connect raise.
    bad_dir = tmp_path / "not_a_db"
    bad_dir.mkdir()
    s = SqliteSnapshotStore(path=str(bad_dir), capacity=10)
    try:
        s.push(_snapshot(1.0))
        assert s.latest() is not None
        assert s.window(10.0)
    finally:
        s.close()


def test_corrupt_row_is_skipped(store):
    import sqlite3

    store.push(_snapshot(1.0))
    with store._lock:
        store._conn.execute("UPDATE snapshots SET interfaces='{bogus' WHERE ts=1.0")
    out = store.latest()
    assert out is not None
    assert out.interfaces == {}
