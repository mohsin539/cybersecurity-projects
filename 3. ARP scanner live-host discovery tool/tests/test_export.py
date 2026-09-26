import json

import pytest

from arp_scanner.core.result import HostInfo, ScanResult
from arp_scanner.report.exporters import result_to_csv, result_to_json, write_export
from arp_scanner.security.guard import sanitize_cell, validate_export_path


def _sample_result() -> ScanResult:
    return ScanResult(
        targets=["192.168.1.1", "192.168.1.7"],
        hosts=[
            HostInfo(
                ip="192.168.1.7",
                mac="b8:27:eb:11:22:33",
                vendor="Raspberry Pi",
                rtt_ms=1.25,
                interface="eth0",
                discovered_at_epoch=1700000000.0,
            ),
            HostInfo(
                ip="192.168.1.1",
                mac="aa:bb:cc:dd:ee:01",
                vendor=None,
                rtt_ms=0.5,
                interface="eth0",
                discovered_at_epoch=1700000000.0,
            ),
        ],
        scanned_at="2026-09-12T10:00:00+00:00",
        duration_s=1.23,
        interface="eth0",
    )


def test_csv_rows_sorted_and_escaped():
    text = result_to_csv(_sample_result())
    lines = text.strip().splitlines()
    assert lines[0] == "ip,mac,vendor,rtt_ms,interface"
    assert "192.168.1.1,aa:bb:cc:dd:ee:01,unknown," in lines[1]
    assert "192.168.1.7,b8:27:eb:11:22:33,Raspberry Pi," in lines[2]


def test_json_roundtrip():
    data = json.loads(result_to_json(_sample_result()))
    assert data["schema_version"] == 1
    assert data["hosts_found"] == 2
    assert data["hosts"][0]["ip"] == "192.168.1.1"  # sorted
    assert data["hosts"][1]["vendor"] == "Raspberry Pi"


@pytest.mark.parametrize(
    "dangerous,expected",
    [("=1+1", "'=1+1"), ("+SUM(A1)", "'+SUM(A1)"), ("-cmd", "'-cmd"), ("@cell", "'@cell"), ("safe", "safe"), (42, "42")],
)
def test_csv_injection_sanitized(dangerous, expected):
    assert sanitize_cell(dangerous) == expected


@pytest.mark.parametrize(
    "path",
    ["", "   ", "foo<bar.csv", r"x\..\evil.csv", "x\x00.csv", 'bad"quote.csv', "sub/../../escape.csv"],
)
def test_unsafe_export_paths_rejected(path):
    with pytest.raises(ValueError):
        validate_export_path(path)


def test_write_export_atomic(tmp_path):
    out = tmp_path / "out" / "report.csv"
    written = write_export(str(out), _sample_result(), "csv")
    assert written.exists()
    assert written.read_text(encoding="utf-8").startswith("ip,mac,vendor,rtt_ms,interface\n")
    assert not list(out.parent.glob(".*.tmp"))