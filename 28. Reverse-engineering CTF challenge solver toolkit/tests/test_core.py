"""Tests: core analyzers (pure functions + adversarial inputs)."""
from __future__ import annotations

import io
import struct
import zipfile

from rekt.core.analyzer import (
    entropy_profile,
    parse_elf,
    parse_pe,
    quick_identify,
    shannon_entropy,
)
from rekt.core.carver import carve_images, carve_zip
from rekt.core.flagfinder import extract_strings, find_flags, find_interesting_strings


# ------------------------------------------------------------------ entropy
def test_entropy_bounds():
    assert shannon_entropy(b"") == 0.0
    assert shannon_entropy(b"A" * 1000) == 0.0
    data = bytes(range(256)) * 4
    assert 7.0 < shannon_entropy(data) <= 8.0


def test_entropy_profile_chunking():
    series = entropy_profile(bytes(range(256)) * 8, chunks=16)
    assert len(series) <= 17  # step-slicing may overshoot by one
    assert all(0 <= v <= 8 for v in series)


# ------------------------------------------------------------------ PE parsing
def _minimal_pe() -> bytes:
    """Craft a tiny valid PE64 header (0 sections) — parser must accept it."""
    d = bytearray(b"MZ" + b"\x00" * 0x3E)  # pad to 0x40 so e_lfanew fits
    struct.pack_into("<I", d, 0x3C, 0x40)
    d += b"PE\x00\x00"
    d += struct.pack("<HHIIIHH", 0x8664, 0, 0, 0, 0, 240, 0x22)  # COFF
    d += struct.pack("<H", 0x20B)  # optional header magic PE32+
    d += b"\x00" * (240 - 2)
    return bytes(d)


def test_parse_pe_minimal():
    pe = parse_pe(_minimal_pe())
    assert pe is not None
    assert pe["bits"] == 64
    assert pe["machine"] == "x86-64"
    assert pe["sections"] == []
    assert pe["imports"] == []


def test_parse_pe_rejects_truncated_header():
    assert parse_pe(b"MZ\x00\x00") is None


def test_parse_pe_garbage_returns_none():
    assert parse_pe(b"MZ not really a pe") is None
    assert parse_pe(b"") is None
    assert parse_pe(b"\x7fELF" + b"\x00" * 40) is None


def test_parse_pe_hostile_section_count():
    d = bytearray(_minimal_pe())
    # nsec field at COFF+2 -> claim 5000 sections but provide no table (must not hang/DoS)
    struct.pack_into("<H", d, 0x40 + 4 + 2, 5000)
    pe = parse_pe(bytes(d))
    assert pe is not None and len(pe["sections"]) == 0


# ------------------------------------------------------------------ ELF
def test_parse_elf_header():
    elf = parse_elf(b"\x7fELF\x02\x01\x01" + b"\x00" * 60)
    assert elf is not None and elf["bits"] == 64


# ------------------------------------------------------------------ identify
def test_quick_identify():
    r = quick_identify(b"\x89PNG\r\n\x1a\n" + b"\x00" * 32)
    assert "PNG image" in r["kinds"]
    r2 = quick_identify(b"just some plain text here")
    assert any("text" in k for k in r2["kinds"])


# ------------------------------------------------------------------ flags/strings
def test_find_flags():
    data = b"junk\x00flag{h1dd3n_1n_pl41n_s1ght}more\x00picoCTF{also}"
    hits = find_flags(data)
    values = {h["value"] for h in hits}
    assert "flag{h1dd3n_1n_pl41n_s1ght}" in values
    assert "picoCTF{also}" in values


def test_extract_strings_ascii_and_utf16():
    data = b"hello_world\x00\x00h\x00e\x00l\x00l\x00o\x00"
    strings = extract_strings(data, min_len=5)
    kinds = {s[1] for s in strings}
    assert "ascii" in kinds and "utf-16le" in kinds


def test_find_interesting_strings_b64():
    hits = find_interesting_strings(b"carry on. SGVsbG9Xb3JsZDEyM1hYwg== done")
    assert any(h["kind"] == "base64ish" for h in hits)


# ------------------------------------------------------------------ carver
def test_carve_zip_blocks_traversal(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("ok.txt", "fine")
        zf.writestr("../evil.txt", "pwned")
        zf.writestr("..\\..\\evil2.txt", "pwned2")
    out = carve_zip(buf.getvalue(), tmp_path / "out")
    names = {p.name for p in out}
    assert "ok.txt" in names
    assert not (tmp_path / "evil.txt").exists()
    assert not (tmp_path / "evil2.txt").exists()
    assert all((tmp_path / "out").resolve() in p.resolve().parents or
               p.resolve().parent == (tmp_path / "out").resolve() for p in out)


def test_carve_zip_garbage(tmp_path):
    assert carve_zip(b"not a zip at all", tmp_path / "o") == []


def test_carve_images_png_and_jpeg(tmp_path):
    png = b"\x89PNG\r\n\x1a\n" + b"A" * 100 + b"IEND\xaeB`\x82"
    jpg = b"\xff\xd8\xff" + b"B" * 50 + b"\xff\xd9"
    out = carve_images(b"xx" + png + b"pad" + jpg + b"yy", tmp_path / "img")
    kinds = {p.suffix for p in out}
    assert ".png" in kinds and ".jpg" in kinds
