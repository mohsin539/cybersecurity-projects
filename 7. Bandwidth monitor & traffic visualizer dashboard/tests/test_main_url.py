"""Tests for the startup URL announcement in main.py.

Covers display-host normalization (wildcard binds → browsable loopback),
effective-URL construction, and the "port differs from default 8000" callout
that fires when BWMON_PORT (or a busy-port fallback) moves the dashboard off
the default port.
"""
from dataclasses import replace

from config import Settings

from main import _display_host, _effective_url, _effective_url_announcement


def _settings(port: int = 8000, host: str = "127.0.0.1") -> Settings:
    return Settings(host=host, port=port)


def test_display_host_loopback_passthrough():
    assert _display_host("127.0.0.1") == "127.0.0.1"
    assert _display_host("localhost") == "localhost"


def test_display_host_wildcard_binds_map_to_loopback():
    assert _display_host("0.0.0.0") == "127.0.0.1"
    assert _display_host("::") == "[::1]"
    assert _display_host("[::]") == "[::1]"
    assert _display_host("") == "127.0.0.1"


def test_effective_url_uses_display_host_and_port():
    assert _effective_url("127.0.0.1", 8000) == "http://127.0.0.1:8000"
    assert _effective_url("0.0.0.0", 9001) == "http://127.0.0.1:9001"


def test_announcement_silent_when_default_port():
    text = _effective_url_announcement(_settings(port=8000))
    assert "http://127.0.0.1:8000" in text
    assert "differs from the default" not in text


def test_announcement_warns_when_port_differs_from_default():
    text = _effective_url_announcement(_settings(port=8001))
    assert "http://127.0.0.1:8001" in text
    assert "8001" in text
    assert "differs from the default 8000" in text


def test_announcement_always_shows_effective_fallback_port():
    # Busy-port fallback rewrites settings.port; announcement must show it.
    settings = replace(_settings(port=8000), port=8017)
    text = _effective_url_announcement(settings)
    assert "http://127.0.0.1:8017" in text
    assert "differs from the default 8000" in text


def test_announcement_includes_api_docs_link():
    text = _effective_url_announcement(_settings(port=8000))
    assert "http://127.0.0.1:8000/docs" in text
