"""PE header parsing engine tests — pefile primary + failure isolation."""
from sap.engines.pe_engine import parse_pe


def test_parse_minimal_pe(minimal_pe):
    res = parse_pe(minimal_pe)
    assert res.status == "ok"
    assert res.mz is True
    assert res.machine == "I386"
    assert res.machine_id == "0x14c"
    assert res.bitness == "PE32"
    assert res.entry_point == 0x1000
    assert res.image_base == "0x400000"
    assert res.subsystem == 2
    assert len(res.sections) == 1
    assert res.sections[0]["name"] == ".text"
    assert res.sections[0]["executable"] is True
    assert res.sections[0]["writable"] is False
    assert res.fingerprint and len(res.fingerprint) == 16
    assert isinstance(res.timestamp_utc, str)


def test_parse_not_pe(not_pe):
    res = parse_pe(not_pe)
    assert res.status == "not-pe"
    assert res.error


def test_parse_missing_file(tmp_path):
    res = parse_pe(tmp_path / "nope.exe")
    assert res.status == "error"
    assert res.error


def test_section_entropy_reported(minimal_pe):
    res = parse_pe(minimal_pe)
    sec = res.sections[0]
    assert sec["entropy"] is not None and 0 <= sec["entropy"] <= 8
    assert sec["characteristics"].startswith("0x")
    assert sec["raw_size"] > 0
    assert sec["virtual_address"] == 0x1000


def test_checksum_flag_present(minimal_pe):
    res = parse_pe(minimal_pe)
    assert isinstance(res.checksum_ok, bool)


def test_anomaly_detection_overlay(minimal_pe):
    res = parse_pe(minimal_pe)
    assert res.overlay_size > 0
    assert any("overlay" in a.lower() for a in res.anomalies)


def test_cross_check_shape(minimal_pe):
    res = parse_pe(minimal_pe)
    assert "lief_available" in res.cross_check
    if res.cross_check.get("lief_available"):
        assert "sections_match" in res.cross_check