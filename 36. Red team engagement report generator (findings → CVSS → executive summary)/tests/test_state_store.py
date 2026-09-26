"""Tests for the GUI state store (paths-only persistence)."""

import json

from redteam_report.state_store import (
    DEFAULT_KEYS,
    clear_state,
    load_state,
    save_state,
    state_path,
)


def test_round_trip(tmp_path):
    base = tmp_path / ".local"
    save_state(base, {"input_file": "a.json", "output_dir": "out"})
    state = load_state(base)
    assert state == {"input_file": "a.json", "output_dir": "out"}
    assert state_path(base).name == "state.json"


def test_keys_are_filtered(tmp_path):
    base = tmp_path / "b"
    save_state(base, {"input_file": "x.json", "secret": "nope", "output_dir": ""})
    raw = json.loads(state_path(base).read_text(encoding="utf-8"))
    assert set(raw) == {"input_file"}
    assert "secret" not in raw


def test_corrupt_or_missing_state_fails_open(tmp_path):
    base = tmp_path / "c"
    assert load_state(base) == {}
    base.mkdir()
    state_path(base).write_text("{not json", encoding="utf-8")
    assert load_state(base) == {}


def test_save_creates_base_dir(tmp_path):
    base = tmp_path / "no" / "such" / "dir"
    path = save_state(base, {"output_dir": "out"})
    assert path is not None
    assert load_state(base) == {"output_dir": "out"}


def test_clear_state(tmp_path):
    base = tmp_path / "d"
    save_state(base, {"input_file": "x.json"})
    assert clear_state(base) is True
    assert load_state(base) == {}
    assert clear_state(base) is True


def test_empty_state_returns_none(tmp_path):
    base = tmp_path / "e"
    assert save_state(base, {}) is None


def test_default_keys_are_expected():
    assert DEFAULT_KEYS == ("input_file", "output_dir")