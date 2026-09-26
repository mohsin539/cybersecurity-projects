"""Bloom filter tests — membership, persistence round-trip, collision sanity."""
import os

from sap.intel.bloom import BloomFilter


def test_add_and_contains():
    bf = BloomFilter(capacity=100_000, error_rate=0.001)
    bf.add(b"a" * 32)
    bf.add(b"b" * 32)
    assert bf.count == 2
    assert b"a" * 32 in bf
    assert b"b" * 32 in bf
    assert b"c" * 32 not in bf


def test_hex_api():
    bf = BloomFilter(capacity=10_000, error_rate=0.01)
    h = "ab" * 32
    bf.add_hex(h)
    assert bf.contains_hex(h)
    assert not bf.contains_hex("cd" * 32)


def test_add_is_idempotent_count_but_not_membership():
    bf = BloomFilter(capacity=10_000, error_rate=0.01)
    bf.add(b"k")
    bf.add(b"k")
    assert bf.count == 2  # expected: count tracks inserts, not unique keys


def test_roundtrip_bytes():
    bf = BloomFilter(capacity=50_000, error_rate=0.001)
    bf.add_hex("11" * 32)
    bf.add_hex("22" * 32)
    blob = bf.to_bytes()
    reloaded = BloomFilter.from_bytes(blob)
    assert reloaded.contains_hex("11" * 32)
    assert reloaded.contains_hex("22" * 32)
    assert not reloaded.contains_hex("ff" * 32)
    assert reloaded.capacity == bf.capacity
    assert reloaded.num_hashes == bf.num_hashes


def test_save_load(tmp_path):
    path = tmp_path / "bloom.bin"
    bf = BloomFilter(capacity=10_000, error_rate=0.01)
    bf.add_hex("33" * 32)
    bf.save(path)
    assert path.exists() and path.stat().st_size > 25
    loaded = BloomFilter.load_or_new(path)
    assert loaded.contains_hex("33" * 32)
    assert not loaded.contains_hex("44" * 32)


def test_load_or_new_creates(tmp_path):
    path = tmp_path / "missing.bin"
    bf = BloomFilter.load_or_new(path, capacity=5_000)
    assert bf.count == 0
    assert path.exists() is False  # load_or_new never writes lazily


def test_collision_probability_sanity():
    bf = BloomFilter(capacity=10_000, error_rate=0.01)
    for i in range(2_000):
        bf.add(f"key-{i}".encode())
    false_positives = sum(1 for i in range(2_000, 4_000) if f"key-{i}".encode() in bf)
    # 2000 extra probes at acceptable error rate → expect < 150 FPs, +slack
    assert false_positives < 500


def test_rejects_bad_params():
    import pytest

    with pytest.raises(ValueError):
        BloomFilter(capacity=0)
    with pytest.raises(ValueError):
        BloomFilter(error_rate=1.0)
    with pytest.raises(ValueError):
        BloomFilter.from_bytes(b"garbage")