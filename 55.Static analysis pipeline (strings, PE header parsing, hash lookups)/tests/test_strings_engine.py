"""Strings engine tests — charset runs, entropy scoring, typed artifacts."""
import math

from sap.engines.strings_engine import (
    HIGH_ENTROPY_THRESHOLD,
    MIN_STRING_LENGTH,
    extract_strings,
    shannon_entropy,
)


def test_shannon_entropy_uniform_byte():
    e = shannon_entropy(bytes(range(256)))
    assert e == 8.0
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"\x00" * 32) == 0.0


def test_extract_ascii_and_offsets():
    data = b"\x00" + b"Hello World! This is a fairly long string." + b"\x00\x00"
    res = extract_strings(data)
    assert res.status == "ok"
    assert res.ascii_count >= 1
    sample = res.samples[0]
    assert sample.value.startswith("Hello World!")
    assert data[sample.offset] == ord("H")
    assert res.stats["bytes_scanned"] == len(data)


def test_utf16le_detection():
    text = "C:\\Windows\\System32\\cmd.exe /c start ".encode("utf-16le")
    data = b"\x00" + text
    res = extract_strings(data)
    assert res.utf16_count >= 1
    assert any(h.value == text.decode("utf-16le") for h in res.samples)


def test_short_runs_ignored():
    res = extract_strings(b"abc" + b"\x00" * 10)
    assert res.ascii_count == 0
    assert res.utf16_count == 0


def test_high_entropy_detection(high_entropy_bytes):
    res = extract_strings(high_entropy_bytes)
    assert res.high_entropy_count >= 1
    for sample in res.high_entropy_samples:
        assert len(sample.value) >= 32
        assert sample.entropy >= HIGH_ENTROPY_THRESHOLD


def test_random_ascii_entropy_is_low():
    res = extract_strings(b"A" * 64 + b"B" * 64)
    assert res.high_entropy_count == 0


def test_artifact_types(minimal_pe):
    res = extract_strings(minimal_pe.read_bytes())
    counts = res.artifact_counts
    assert counts.get("url", 0) >= 2
    assert counts.get("ipv4", 0) >= 1
    assert counts.get("domain", 0) >= 2
    assert counts.get("registry", 0) >= 1
    arts = [a.value for a in res.artifacts]
    assert any(v.startswith("http") for v in arts)
    assert any(v == "182.55.44.7" for v in arts)
    assert any("HKEY" in v or v.startswith("HKLM") for v in arts)


def test_suspicious_apis_extracted(minimal_pe):
    res = extract_strings(minimal_pe.read_bytes())
    apis = set(res.suspicious_apis)
    assert {"createremotethread", "virtualallocex", "writeprocessmemory"} <= apis


def test_empty_input():
    res = extract_strings(b"")
    assert res.status == "ok"
    assert res.artifact_counts == {}