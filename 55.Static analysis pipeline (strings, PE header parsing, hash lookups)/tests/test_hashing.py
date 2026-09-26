"""Hashing engine + integrity digest tests."""
import hashlib

from sap.engines.hashing import compute_all, format_ietf
from sap.security.integrity import digests_of_path, sha256_file, stream_digests


def test_compute_all_known_input(tmp_path):
    p = tmp_path / "x.bin"
    p.write_bytes(b"hello sap" * 1000)
    d = compute_all(p)
    assert len(d["sha256"]) == 64
    assert len(d["sha1"]) == 40
    assert len(d["md5"]) == 32
    assert len(d["blake2b"]) == 64
    assert d["sha256"] == hashlib.sha256(b"hello sap" * 1000).hexdigest()
    assert d["blake2b"] == hashlib.blake2b(
        b"hello sap" * 1000, digest_size=32).hexdigest()


def test_compute_all_and_digests_of_path_agree(tmp_path):
    p = tmp_path / "y.bin"
    p.write_bytes(b"0" * 2048)
    a = compute_all(p)
    b = digests_of_path(p)
    assert a["sha256"] == b["sha256"]
    assert a["sha1"] == b["sha1"]
    assert a["md5"] == b["md5"]
    assert a["blake2b"] == hashlib.blake2b(b"0" * 2048, digest_size=32).hexdigest()


def test_stream_digests_single_pass(tmp_path):
    p = tmp_path / "z.bin"
    p.write_bytes(b"abc" * 3333)
    import os

    fd = os.open(p, os.O_RDONLY)
    try:
        d = stream_digests(fd)
    finally:
        os.close(fd)
    assert d["sha256"] == sha256_file(p)


def test_format_ietf_mapping():
    d = {"sha256": "a" * 64, "sha1": "b" * 40, "md5": "c" * 32}
    ietf = format_ietf(d)
    assert ietf["SHA-256"] == "a" * 64
    assert ietf["SHA-1"] == "b" * 40
    assert ietf["MD5"] == "c" * 32


def test_digests_of_path_streams_large(tmp_path):
    import os

    p = tmp_path / "big.bin"
    p.write_bytes(b"\x5a" * (8 * 1024 * 1024))  # 8 MiB > streaming chunk boundary
    d = digests_of_path(p)
    assert len(d["sha256"]) == 64