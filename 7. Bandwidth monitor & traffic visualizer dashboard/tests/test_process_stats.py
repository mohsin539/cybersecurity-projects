"""Per-process attribution: smoothing, ranking, totals, adapter deltas."""
import time

import pytest

from application.process_stats import ProcessTrafficService
from domain.process_traffic import ProcessTrafficDelta


class ScriptedProcessSource:
    """Test double returning queued delta batches."""

    def __init__(self, batches):
        self._batches = list(batches)
        self._i = 0

    def sample(self):
        if self._i < len(self._batches):
            b = self._batches[self._i]
        else:
            b = {}
        self._i += 1
        return b


def _delta(pid, name, sent, recv):
    return ProcessTrafficDelta(pid=pid, name=name, bytes_sent=sent, bytes_recv=recv)


def test_baseline_returns_zero_deltas_and_first_real_batch_rates():
    svc = ProcessTrafficService(ScriptedProcessSource([{}]), smooth_window=1)
    svc.update({1: _delta(1, "a", 0, 0)}, now=1.0)  # baseline
    svc.update({1: _delta(1, "a", 500, 1500)}, now=2.0)
    snap = svc.snapshot(limit=5)
    assert snap.rows[0].name == "a"
    assert snap.rows[0].rate_recv == pytest.approx(1500.0)
    assert snap.rows[0].rate_sent == pytest.approx(500.0)


def test_smoothing_averages_recent_windows():
    svc = ProcessTrafficService(ScriptedProcessSource([{}, {}]), smooth_window=2)
    svc.update({7: _delta(7, "b", 0, 1000)}, now=1.0)
    svc.update({7: _delta(7, "b", 0, 3000)}, now=2.0)
    row = svc.snapshot(limit=5).rows[0]
    assert row.rate_recv == pytest.approx(2000.0)


def test_ranking_by_combined_rate():
    svc = ProcessTrafficService(ScriptedProcessSource([{}, {}]), smooth_window=1)
    svc.update({1: _delta(1, "chatty", 0, 5000)}, now=1.0)
    svc.update({2: _delta(2, "quiet", 0, 100)}, now=1.0)
    rows = svc.snapshot(limit=10).rows
    assert rows[0].name == "chatty"
    assert rows[1].name == "quiet"


def test_totals_accumulate():
    svc = ProcessTrafficService(ScriptedProcessSource([{}, {}]), smooth_window=1)
    svc.update({3: _delta(3, "c", 100, 200)}, now=1.0)
    svc.update({3: _delta(3, "c", 300, 400)}, now=2.0)
    row = svc.snapshot().rows[0]
    assert row.total_recv == 600.0
    assert row.total_sent == 400.0


def test_empty_batch_is_ignored_but_counts_nothing():
    svc = ProcessTrafficService(ScriptedProcessSource([{}]), smooth_window=1)
    svc.update({4: _delta(4, "d", 10, 10)}, now=1.0)
    svc.update({}, now=2.0)
    assert svc.sample_count == 1
    snap = svc.snapshot()
    assert snap.rows[0].rate_recv > 0


def test_max_tracked_prunes_cold_processes():
    svc = ProcessTrafficService(ScriptedProcessSource([{}]), smooth_window=1, max_tracked=2)
    svc.update({1: _delta(1, "p1", 0, 1000)}, now=1.0)
    svc.update({2: _delta(2, "p2", 0, 2000)}, now=1.1)
    svc.update({3: _delta(3, "p3", 0, 3000)}, now=1.2)
    snap = svc.snapshot(limit=10)
    names = {r.name for r in snap.rows}
    assert "p1" not in names  # coldest row pruned
    assert {"p2", "p3"} <= names


def test_psutil_adapter_derives_deltas(monkeypatch):
    from infrastructure.capture.psutil_process_traffic import PsutilProcessTrafficSource

    class FakeProc:
        def __init__(self, pid, name, read, write):
            self.info = {"pid": pid, "name": name}
            self._r, self._w = read, write

        def io_counters(self):
            class IO:
                read_bytes = self._r
                write_bytes = self._w
            return IO()

    procs = [FakeProc(1, "a", 0, 0), FakeProc(2, "b", 0, 0)]
    monkeypatch.setattr("psutil.process_iter", lambda attrs=None: procs)
    src = PsutilProcessTrafficSource(min_scan_spacing=0.0)

    first = src.sample()  # baseline
    assert first == {}
    # grow counters
    procs[0]._r, procs[0]._w = 4000, 1000
    procs[1]._r, procs[1]._w = 0, 500
    second = src.sample()
    assert second[1].bytes_recv == 4000
    assert second[1].bytes_sent == 1000
    assert second[2].bytes_sent == 500
    # vanished process should not break the next scan; proc 1 keeps moving
    procs.pop()
    procs[0]._r, procs[0]._w = 5000, 1500
    third = src.sample()
    assert third[1].bytes_recv == 1000
    assert 2 not in third
    # a process with unchanged counters produces no delta row
    fourth = src.sample()
    assert 1 not in fourth


def test_psutil_adapter_throttles_scans(monkeypatch):
    from infrastructure.capture.psutil_process_traffic import PsutilProcessTrafficSource

    monkeypatch.setattr("psutil.process_iter", lambda attrs=None: [])
    src = PsutilProcessTrafficSource(min_scan_spacing=60.0)
    assert src.sample() == {}
    time.sleep(0.05)
    assert src.sample() == {}  # still inside the throttle window
