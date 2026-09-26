"""Tests for memory preservation (sanitised, integrity-checked memory store)."""

from __future__ import annotations

import pytest

from anonymizer.gui.memory_manager import (
    GENUINE,
    MEMORY_PREFIX,
    CustomRule,
    MemoryError,
    MemoryManager,
)


@pytest.fixture
def mem_dir(tmp_path):
    return tmp_path / "memdir"


def test_empty_memory_defaults(mem_dir):
    memory = MemoryManager(mem_dir)
    assert memory.load().version == 1
    assert memory.memory.recent_files == []


def test_remember_file_stores_metadata_only(mem_dir, tmp_path):
    log = tmp_path / "customer.log"
    log.write_text("real secret data 555-66-7777\n", encoding="utf-8")

    memory = MemoryManager(mem_dir)
    memory.remember_file(str(log), line_count=1, sensitive_hits=3)
    memory.save()

    raw = (mem_dir / "memory.json").read_bytes()
    # Original content must NEVER leak into memory
    assert b"555-66-7777" not in raw
    assert b"real secret data" not in raw
    # but the path metadata is preserved
    assert b"customer.log" in raw


def test_remember_dedupes_and_caps_recent(mem_dir):
    memory = MemoryManager(mem_dir)
    for i in range(30):
        memory.remember_file(f"C:\\logs\\file{i:02d}.log")
    memory.save()
    assert len(memory.load().recent_files) == 20
    assert memory.memory.recent_files[0].path.endswith("file29.log")


def test_custom_rule_roundtrip(mem_dir):
    memory = MemoryManager(mem_dir)
    memory.add_rule(
        CustomRule(entity_type="INTERNAL_ID", pattern=r"ID-\d{6}", strategy="PARTIAL_MASK")
    )
    memory.save()

    reloaded = MemoryManager(mem_dir).load()
    assert len(reloaded.custom_rules) == 1
    rule = reloaded.custom_rules[0]
    assert rule.entity_type == "INTERNAL_ID"
    assert rule.pattern == r"ID-\d{6}"
    assert rule.strategy == "PARTIAL_MASK"


def test_add_duplicate_rule_replaces(mem_dir):
    memory = MemoryManager(mem_dir)
    memory.add_rule(CustomRule(entity_type="X", pattern="one"))
    memory.add_rule(CustomRule(entity_type="X", pattern="two"))
    memory.save()
    rules = MemoryManager(mem_dir).load().custom_rules
    assert len(rules) == 1
    assert rules[0].pattern == "two"


def test_entity_stats_are_fingerprinted(mem_dir):
    memory = MemoryManager(mem_dir)
    memory.record_stats({"SSN": 3, "EMAIL": 2})
    memory.save()
    raw = (mem_dir / "memory.json").read_bytes()
    # entity type names are stored fingerprinted, never the raw names
    assert b"SSN" not in raw
    assert b"EMAIL" not in raw
    reloaded = MemoryManager(mem_dir).load()
    assert len(reloaded.entity_stats) == 2


def test_preferences_allowlist(mem_dir):
    memory = MemoryManager(mem_dir)
    memory.set_preference("theme", "light")
    memory.set_preference("keep_last_chars", 9)
    memory.set_preference("hostile", "value")  # ignored: not in allowlist
    memory.save()
    reloaded = MemoryManager(mem_dir).load()
    assert reloaded.theme == "light"
    assert reloaded.keep_last_chars == 9


def test_integrity_detects_tampering(mem_dir):
    memory = MemoryManager(mem_dir)
    memory.save()
    path = mem_dir / "memory.json"
    raw = bytearray(path.read_bytes())
    raw[-2] ^= 0x01
    path.write_bytes(bytes(raw))
    with pytest.raises(MemoryError):
        MemoryManager(mem_dir).load()


def test_forget_all_erases(mem_dir):
    memory = MemoryManager(mem_dir)
    memory.remember_file("C:\\logs\\a.log")
    memory.save()
    assert (mem_dir / "memory.json").exists()
    memory.forget_all()
    assert not (mem_dir / "memory.json").exists()
    assert MemoryManager(mem_dir).load().recent_files == []


def test_safer_marker_present(mem_dir):
    memory = MemoryManager(mem_dir)
    memory.save()
    raw = (mem_dir / "memory.json").read_bytes()
    assert raw.startswith(MEMORY_PREFIX)
    assert GENUINE.encode() in raw
