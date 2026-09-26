from __future__ import annotations

import os
import sys
import tempfile
import unittest
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from timeline_builder.correlation import Correlator
from timeline_builder.export import export_csv, export_html, export_json
from timeline_builder.models import Severity, SourceType, TimeKind, TimelineEvent
from timeline_builder.normalizer import TimelineNormalizer
from timeline_builder.storage import CaseStore


def make_event(offset_seconds: int, path: str = "/a", severity=Severity.INFO, host: str = "h1") -> TimelineEvent:
    base = datetime(2026, 6, 1, 8, 0, 0, tzinfo=timezone.utc)
    return TimelineEvent(
        timestamp=base + timedelta(seconds=offset_seconds),
        source_type=SourceType.LOG,
        source_path=path,
        description=f"event {offset_seconds}",
        time_kind=TimeKind.EVENT,
        severity=severity,
        host=host,
    )


class NormalizerTests(unittest.TestCase):
    def test_sorts_and_dedupes(self):
        events = [make_event(10), make_event(0), make_event(10)]
        normalized = TimelineNormalizer(dedupe=True).normalize(events)
        self.assertEqual(len(normalized), 2)
        self.assertLess(normalized[0].timestamp, normalized[1].timestamp)

    def test_summary(self):
        events = [make_event(0, severity=Severity.CRITICAL), make_event(1, host="h2")]
        summary = TimelineNormalizer().summarize(events)
        self.assertEqual(summary["total"], 2)
        self.assertEqual(summary["high_or_above"], 1)


class CorrelationTests(unittest.TestCase):
    def test_burst_detection(self):
        events = [make_event(i, path="/same") for i in range(5)]
        groups = Correlator(window=timedelta(seconds=5), min_events=3).correlate(events)
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0].count, 5)


class StorageTests(unittest.TestCase):
    def test_add_query_count(self):
        with tempfile.TemporaryDirectory() as tmp:
            store = CaseStore(Path(tmp) / "case.tbcase", case_id="t")
            events = [make_event(i, path=f"/p{i}", severity=Severity.HIGH if i % 2 else Severity.INFO) for i in range(6)]
            store.add_events(events)
            self.assertEqual(store.count(), 6)
            self.assertEqual(store.count(severities=["high"]), 3)
            self.assertEqual(len(store.query(text="event 3")), 1)
            self.assertEqual(store.distinct("host"), ["h1"])
            self.assertEqual(store.stats()["total"], 6)
            store.close()


class ExportTests(unittest.TestCase):
    def test_exporters(self):
        events = [make_event(0, severity=Severity.CRITICAL), make_event(1)]
        with tempfile.TemporaryDirectory() as tmp:
            csv_path = export_csv(events, Path(tmp) / "t.csv")
            json_path = export_json(events, Path(tmp) / "t.json")
            html_path = export_html(events, Path(tmp) / "t.html", case_id="demo", chain_status="INTACT")
            self.assertIn("timestamp", csv_path.read_text(encoding="utf-8-sig"))
            self.assertIn('"event_count": 2', json_path.read_text(encoding="utf-8"))
            document = html_path.read_text(encoding="utf-8")
            self.assertIn("Unified Forensic Timeline", document)
            self.assertIn("#f43f5e", document)


if __name__ == "__main__":
    unittest.main()
