from __future__ import annotations

import json
import os
import sys
import tempfile
import unittest
from pathlib import Path

sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "src"))

from timeline_builder.collectors import FilesystemCollector, LogCollector, detect_format
from timeline_builder.collectors.base import CollectorContext
from timeline_builder.collectors.logs import infer_severity, parse_timestamp
from timeline_builder.config import ScanOptions
from timeline_builder.models import Severity, SourceType, TimeKind


class TimestampTests(unittest.TestCase):
    def test_iso_z(self):
        parsed = parse_timestamp("2026-06-01T08:00:00Z")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.year, 2026)

    def test_epoch_millis(self):
        parsed = parse_timestamp(1_700_000_000_000)
        self.assertIsNotNone(parsed)

    def test_garbage(self):
        self.assertIsNone(parse_timestamp("not-a-time"))

    def test_severity_inference(self):
        self.assertEqual(infer_severity("CRITICAL brute force"), Severity.CRITICAL)
        self.assertEqual(infer_severity("all good"), Severity.INFO)


class FilesystemCollectorTests(unittest.TestCase):
    def test_collects_macb(self):
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.txt").write_text("hello", encoding="utf-8")
            (root / "sub").mkdir()
            (root / "sub" / "b.txt").write_text("world", encoding="utf-8")
            options = ScanOptions(compute_hashes=True)
            result = FilesystemCollector(root, options=options).collect(CollectorContext())
            self.assertEqual(result.files_seen, 2)
            self.assertGreaterEqual(len(result.events), 2)
            self.assertTrue(all(e.source_type is SourceType.FILESYSTEM for e in result.events))
            modified = [e for e in result.events if e.time_kind is TimeKind.MODIFIED]
            self.assertEqual(len(modified), 2)
            self.assertTrue(all(len(e.sha256) == 64 for e in modified))


class LogCollectorTests(unittest.TestCase):
    def test_text_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "auth.log"
            path.write_text(
                "2026-06-01T08:00:00Z INFO login ok\n2026-06-01T08:01:00Z ERROR failed login\n",
                encoding="utf-8",
            )
            result = LogCollector(path).collect(CollectorContext())
            self.assertEqual(len(result.events), 2)
            self.assertEqual(result.events[1].severity, Severity.HIGH)
            self.assertEqual(result.events[0].source_type, SourceType.LOG)

    def test_jsonl_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "events.jsonl"
            rows = [
                {"@timestamp": "2026-06-01T08:05:00Z", "level": "info", "message": "started", "host": "srv"},
                {"@timestamp": "2026-06-01T08:06:00Z", "level": "error", "message": "boom", "user": "bob"},
            ]
            path.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
            self.assertEqual(detect_format(path), "jsonl")
            result = LogCollector(path).collect(CollectorContext())
            self.assertEqual(len(result.events), 2)
            self.assertEqual(result.events[0].host, "srv")
            self.assertEqual(result.events[1].user, "bob")

    def test_csv_log(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "audit.csv"
            path.write_text(
                "timestamp,level,user,message\n"
                "2026-06-01T09:00:00Z,warn,alice,disk almost full\n",
                encoding="utf-8",
            )
            self.assertEqual(detect_format(path), "csv")
            result = LogCollector(path).collect(CollectorContext())
            self.assertEqual(len(result.events), 1)
            self.assertEqual(result.events[0].severity, Severity.MEDIUM)


if __name__ == "__main__":
    unittest.main()
