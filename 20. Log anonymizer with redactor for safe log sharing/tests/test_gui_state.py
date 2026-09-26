"""Tests for state preservation (DPAPI-protected state manager)."""

from __future__ import annotations

import json

import pytest

from anonymizer.gui import dpapi
from anonymizer.gui.state_manager import (
    DEFAULT_STATE,
    GENUINE,
    USAGE_PREFIX,
    AppState,
    StateError,
    StateManager,
)


@pytest.fixture
def state_dir(tmp_path):
    return tmp_path / "appdir"


def test_defaults_loaded_when_no_file(state_dir):
    manager = StateManager(state_dir)
    loaded = manager.load()
    assert loaded.version == 1
    assert loaded.theme == "dark"
    assert loaded.keep_last_chars == 4


def test_save_load_roundtrip(state_dir):
    manager = StateManager(state_dir)
    state = AppState(theme="light", keep_last_chars=6, window_width=900, window_height=700)
    state.token_salt = "tenant-salt"
    path = manager.save(state)

    assert path.exists()
    raw = path.read_bytes()
    assert raw.startswith(USAGE_PREFIX)

    # Secrets must never appear in plaintext in the file
    manager2 = StateManager(state_dir)
    loaded = manager2.load()
    assert loaded.theme == "light"
    assert loaded.keep_last_chars == 6
    assert loaded.window_width == 900
    if dpapi.dpapi_available:
        assert b"tenant-salt" not in raw
        assert loaded.token_salt == "tenant-salt"
    else:
        assert loaded.token_salt == "tenant-salt"


def test_atomic_write_leaves_no_temp_files(state_dir):
    manager = StateManager(state_dir)
    manager.save(DEFAULT_STATE)
    leftovers = [p for p in state_dir.iterdir() if p.name.startswith(".state-")]
    assert leftovers == []


def test_integrity_detects_tampering(state_dir):
    manager = StateManager(state_dir)
    manager.save(DEFAULT_STATE)

    path = state_dir / "state.json"
    raw = bytearray(path.read_bytes())
    raw[-2] ^= 0x01  # flip a byte in the payload
    path.write_bytes(bytes(raw))

    with pytest.raises(StateError):
        StateManager(state_dir).load()


def test_truncation_detected(state_dir):
    manager = StateManager(state_dir)
    manager.save(DEFAULT_STATE)
    raw = state_dir / "state.json"
    data = raw.read_bytes()
    raw.write_bytes(data[: len(data) // 2])
    with pytest.raises(StateError):
        StateManager(state_dir).load()


def test_secret_roundtrip_is_dpapi_protected(state_dir):
    if not dpapi.dpapi_available:
        pytest.skip("DPAPI unavailable on this platform")
    manager = StateManager(state_dir)
    manager.state.token_salt = "super-secret-salt-42"
    manager.save()

    raw = (state_dir / "state.json").read_bytes()
    assert b"super-secret-salt-42" not in raw
    assert b"LAC1-STATE" in raw

    loaded = StateManager(state_dir).load()
    assert loaded.token_salt == "super-secret-salt-42"


def test_update_dotted_keys(state_dir):
    manager = StateManager(state_dir)
    manager.update(**{"window.width": 1111, "preferences.keep_last_chars": 2})
    reloaded = StateManager(state_dir).load()
    assert reloaded.window_width == 1111
    assert reloaded.keep_last_chars == 2


def test_forget_removes_file(state_dir):
    manager = StateManager(state_dir)
    manager.save(AppState(theme="light"))
    assert (state_dir / "state.json").exists()
    manager.forget()
    assert not (state_dir / "state.json").exists()
    assert StateManager(state_dir).load().theme == "dark"


def test_marker_required(state_dir):
    body = {
        "version": 1,
        "window": {},
        "preferences": {},
        "recent": {},
        "secrets": {},
    }
    payload = json.dumps(body).encode()
    import hashlib

    content = (
        USAGE_PREFIX
        + b" "
        + str(len(payload)).encode()
        + b"\n"
        + hashlib.sha256(USAGE_PREFIX + payload).hexdigest().encode()
        + b"\n"
        + payload
        + b"\n"
    )
    state_dir.mkdir(parents=True, exist_ok=True)
    (state_dir / "state.json").write_bytes(content)
    with pytest.raises(StateError):
        StateManager(state_dir).load()


def test_safer_marker_present(state_dir):
    manager = StateManager(state_dir)
    manager.save(DEFAULT_STATE)
    raw = (state_dir / "state.json").read_bytes()
    assert GENUINE.encode() in raw
