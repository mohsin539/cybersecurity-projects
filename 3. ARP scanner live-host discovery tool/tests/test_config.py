import pytest

from arp_scanner.core.config import ConfigError, build_config


def test_defaults():
    cfg = build_config(target="192.168.1.0/24")
    assert cfg.target == "192.168.1.0/24"
    assert cfg.interface == "auto"
    assert cfg.timeout == 1.0
    assert cfg.retries == 1


def test_overrides_merge():
    cfg = build_config(target="10.0.0.0/24", timeout=2.5, quiet=True)
    assert cfg.timeout == 2.5
    assert cfg.quiet is True


@pytest.mark.parametrize(
    "overrides",
    [
        {"timeout": 0.001},
        {"timeout": 61},
        {"retries": -1},
        {"retries": 11},
        {"workers": 0},
        {"workers": 5000},
    ],
)
def test_invalid_ranges_rejected(overrides):
    with pytest.raises(ConfigError):
        build_config(target="1.1.1.0/24", **overrides)