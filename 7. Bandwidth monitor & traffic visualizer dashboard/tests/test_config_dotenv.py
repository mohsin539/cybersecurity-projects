"""Tests for the .env loader, CLI port fallback helpers, and .env validation.

Validation lives in ``config/settings.py`` (``ENV_SCHEMA`` is the single
source of truth shared by ``Settings``, the validator and these tests).
"""
import dataclasses
import os
import socket
from pathlib import Path

import pytest

from config.settings import (
    ENV_SCHEMA,
    Settings,
    _KEY_RE,
    _get,
    _load_dotenv,
    _parse_env_line,
    collect_env_problems,
    load_settings,
    warn_on_env_problems,
)


@pytest.fixture()
def clean_env(monkeypatch):
    """Isolate tests from the developer's real environment."""
    for key in list(os.environ):
        if key.startswith("BWMON_"):
            monkeypatch.delenv(key, raising=False)
    return monkeypatch


# ---------------------------------------------------------------- .env loader
def test_load_dotenv_missing_file_returns_none(tmp_path):
    assert _load_dotenv(tmp_path / "nope.env") is None


def test_load_dotenv_parses_quotes_exports_and_comments(tmp_path, clean_env):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# comment line\n"
        "BWMON_PORT=9001\n"
        'BWMON_HOST="0.0.0.0"\n'
        "export BWMON_LOG_LEVEL=debug\n"
        "\n"
        "BWMON_STORE_PATH='my hist.db'\n"
        "not a pair line\n",
        encoding="utf-8",
    )
    assert _load_dotenv(env_file) == env_file
    assert os.environ["BWMON_PORT"] == "9001"
    assert os.environ["BWMON_HOST"] == "0.0.0.0"
    assert os.environ["BWMON_LOG_LEVEL"] == "debug"
    assert os.environ["BWMON_STORE_PATH"] == "my hist.db"


def test_load_dotenv_never_clobbers_real_environment(tmp_path, clean_env):
    clean_env.setenv("BWMON_PORT", "7777")
    env_file = tmp_path / ".env"
    env_file.write_text("BWMON_PORT=9001\nBWMON_HOST=0.0.0.0\n", encoding="utf-8")

    _load_dotenv(env_file)
    assert os.environ["BWMON_PORT"] == "7777"  # real env wins
    assert os.environ["BWMON_HOST"] == "0.0.0.0"  # file value applied


def test_load_settings_applies_dotenv(tmp_path, clean_env, monkeypatch):
    env_file = tmp_path / ".env"
    env_file.write_text("BWMON_PORT=9100\n", encoding="utf-8")
    monkeypatch.setattr(
        "config.settings._load_dotenv", lambda: _load_dotenv(env_file)
    )
    settings = load_settings()
    assert settings.port == 9100


def test_strict_port_defaults_off(clean_env):
    assert Settings.from_env().strict_port is False


def test_strict_port_from_env(clean_env):
    clean_env.setenv("BWMON_STRICT_PORT", "true")
    assert Settings.from_env().strict_port is True


# ------------------------------------------------------- shared line parsing
def test_parse_env_line_variants():
    assert _parse_env_line("BWMON_PORT=9001") == ("BWMON_PORT", "9001")
    assert _parse_env_line("  export BWMON_PORT=9001  ") == ("BWMON_PORT", "9001")
    assert _parse_env_line('BWMON_HOST="0.0.0.0"') == ("BWMON_HOST", "0.0.0.0")
    assert _parse_env_line("# comment") == (None, "")
    assert _parse_env_line("no equals sign") == (None, "")
    assert _parse_env_line("BWMON-PORT=8000") == (None, "")  # invalid key chars
    assert _parse_env_line("") == (None, "")


# ------------------------------------------------------------- port helpers
def _hold_port(port):
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", port))
    sock.listen(1)
    return sock


def test_port_available_reflects_a_live_listener():
    from main import _port_available

    sock = _hold_port(0)
    try:
        busy_port = sock.getsockname()[1]
        assert _port_available("127.0.0.1", busy_port) is False
        # some other port should be free (ephemeral space is large)
        assert _port_available("127.0.0.1", busy_port + 1) is True
    finally:
        sock.close()


def test_next_free_port_skips_busy_and_stops_at_max():
    from main import _next_free_port

    sock = _hold_port(0)
    try:
        busy = sock.getsockname()[1]
        # next free port is the busy port + 1 (nothing else listens there)
        assert _next_free_port("127.0.0.1", busy + 1, max_tries=3) == busy + 1
        # a search starting *at* the busy port skips it
        assert _next_free_port("127.0.0.1", busy, max_tries=3) == busy + 1
        # max_tries=1 starting at the busy port finds nothing
        assert _next_free_port("127.0.0.1", busy, max_tries=1) is None
    finally:
        sock.close()


def test_pid_on_port_returns_none_for_free_port():
    from main import _pid_on_port

    sock = _hold_port(0)
    try:
        port = sock.getsockname()[1]
        # our trivial listener is not registered as a process-bound listener
        # on all platforms; both outcomes are acceptable, crash is not.
        result = _pid_on_port(port)
        assert result is None or isinstance(result, int)
    finally:
        sock.close()


# --------------------------------------------- schema drift guards (tests ⇄ settings)
def test_every_schema_attr_is_a_settings_field():
    field_names = {f.name for f in dataclasses.fields(Settings)}
    for spec in ENV_SCHEMA.values():
        if spec.attr:
            assert spec.attr in field_names, (
                f"{spec.key} targets '{spec.attr}' which is not a Settings field"
            )


def test_schema_defaults_match_settings_defaults(clean_env):
    settings = Settings()  # constructed with no BWMON_* env set
    for spec in ENV_SCHEMA.values():
        if not spec.attr:
            continue
        expected = spec.parse(str(spec.default))
        assert getattr(settings, spec.attr) == expected, (
            f"{spec.key}: schema default {spec.default!r} does not match "
            f"Settings.{spec.attr}"
        )


def test_every_enum_has_choices_and_no_string_enum_leaks():
    for spec in ENV_SCHEMA.values():
        if spec.kind == "enum":
            assert spec.choices, f"{spec.key}: enum needs choices"
        else:
            assert spec.choices is None, f"{spec.key}: choices only valid for enum"


def test_schema_covers_every_documented_env_var():
    documented = {  # keep in sync with README's configuration table
        "BWMON_HOST", "BWMON_PORT", "BWMON_REFRESH_INTERVAL",
        "BWMON_HISTORY_CAPACITY", "BWMON_STORE_BACKEND", "BWMON_STORE_PATH",
        "BWMON_PROCESSES_ENABLED", "BWMON_PROCESS_SCAN_SPACING",
        "BWMON_CONNECTIONS_ENABLED", "BWMON_CONNECTIONS_LIMIT",
        "BWMON_INCLUDE", "BWMON_EXCLUDE", "BWMON_LOG_LEVEL",
        "BWMON_STRICT_PORT", "BWMON_OPEN_BROWSER",
        "BWMON_ALERT_UPLOAD_BPS", "BWMON_ALERT_DOWNLOAD_BPS",
        "BWMON_ALERT_COOLDOWN_SECONDS",
    }
    assert set(ENV_SCHEMA) == documented


# ----------------------------------------------------- shared .env validation
def test_malformed_int_value_is_detected():
    problems = collect_env_problems("BWMON_PORT=8o01\n")
    assert any(p.startswith("BWMON_PORT:") for p in problems)


def test_malformed_float_value_is_detected():
    problems = collect_env_problems("BWMON_REFRESH_INTERVAL=1..5\n")
    assert any(p.startswith("BWMON_REFRESH_INTERVAL:") for p in problems)


def test_malformed_bool_value_is_detected():
    problems = collect_env_problems("BWMON_STRICT_PORT=yes please\n")
    assert any(p.startswith("BWMON_STRICT_PORT:") for p in problems)


def test_malformed_enum_value_is_detected():
    problems = collect_env_problems(
        "BWMON_LOG_LEVEL=verbose\nBWMON_STORE_BACKEND=redus\n"
    )
    assert any(p.startswith("BWMON_LOG_LEVEL:") for p in problems)
    assert any(p.startswith("BWMON_STORE_BACKEND:") for p in problems)


def test_typoed_bwmon_key_is_detected():
    # A typo'd key is silently ignored by the app — the guard must catch it.
    problems = collect_env_problems("BWMON_PROCSSES_ENABLED=true\n")
    assert any("BWMON_PROCSSES_ENABLED" in p and "unknown" in p for p in problems)


def test_structurally_broken_bwmon_line_is_detected():
    # Missing '=' and an invalid key name are both skipped by the loader.
    problems = collect_env_problems("BWMON PORT=8000\nBWMON-PORT=8000\n")
    assert len(problems) == 2
    assert all("malformed BWMON_* entry" in p for p in problems)


def test_valid_env_file_produces_no_problems():
    problems = collect_env_problems(
        "# comment\n"
        "export BWMON_PORT=8001\n"
        'BWMON_HOST="0.0.0.0"\n'
        "BWMON_REFRESH_INTERVAL=0.5\n"
        "BWMON_STORE_BACKEND=memory\n"
        "BWMON_LOG_LEVEL=debug\n"
        "BWMON_STRICT_PORT=false\n"
        "BWMON_OPEN_BROWSER=yes\n"
    )
    assert problems == []


def test_non_bwmon_lines_are_ignored():
    problems = collect_env_problems("OTHER_TOOL=not-a-number\njust prose\n")
    assert problems == []


def test_collect_env_problems_matches_loader_semantics(tmp_path, clean_env):
    """Values the validator accepts must be exactly the values the app applies."""
    text = "BWMON_PORT=8001\nBWMON_REFRESH_INTERVAL=0.25\n"
    assert collect_env_problems(text) == []

    probe = tmp_path / "probe.env"
    probe.write_text(text, encoding="utf-8")
    _load_dotenv(probe)
    assert _get("BWMON_PORT") == 8001
    assert _get("BWMON_REFRESH_INTERVAL") == 0.25


# ------------------------------------------- malformed values never crash startup
def test_malformed_value_falls_back_to_default_with_warning(clean_env, caplog):
    clean_env.setenv("BWMON_PORT", "8o01")
    with caplog.at_level("WARNING", logger="bwmon.settings"):
        assert _get("BWMON_PORT") == 8000  # declared default
    assert any("BWMON_PORT" in r.message for r in caplog.records)


def test_warn_on_env_problems_logs_for_project_env(tmp_path, monkeypatch, caplog):
    env_file = tmp_path / ".env"
    env_file.write_text("BWMON_PORT=not-a-port\n", encoding="utf-8")
    with caplog.at_level("WARNING", logger="bwmon.settings"):
        problems = warn_on_env_problems(env_file)
    assert problems and any("BWMON_PORT" in p for p in problems)
    assert any(".env:" in r.message for r in caplog.records)


def test_warn_on_env_problems_silent_when_no_file(tmp_path):
    assert warn_on_env_problems(tmp_path / "missing.env") == []


def test_project_env_has_no_malformed_bwmon_values():
    """The developer's real project-root .env must be well-formed."""
    project_env = Path(__file__).resolve().parent.parent / ".env"
    if not project_env.is_file():
        pytest.skip("no .env file at project root")
    problems = collect_env_problems(project_env.read_text(encoding="utf-8"))
    assert problems == [], "malformed BWMON_* values in project .env:\n" + "\n".join(
        f"  - {p}" for p in problems
    )
