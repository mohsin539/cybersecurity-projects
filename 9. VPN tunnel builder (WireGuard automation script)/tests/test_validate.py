import pathlib
import sys

sys.path.insert(0, str(pathlib.Path(__file__).resolve().parents[1]))

from app.core.validate import (
    is_cidr,
    is_endpoint,
    is_interface_name,
    is_port,
    is_wg_key,
    normalize_cidrs,
    validate_peer_input,
    validate_tunnel_input,
)


def test_is_cidr():
    assert is_cidr("10.9.0.0/24") == (True, "Valid 4 network 10.9.0.0/24")
    assert is_cidr("2001:db8::/32")[0]
    assert not is_cidr("10.0.0.0/33")[0]
    assert not is_cidr("banana")[0]


def test_is_port():
    assert is_port(1)
    assert is_port(65535)
    assert not is_port(0)
    assert not is_port(65536)
    assert not is_port("foo")


def test_interface_name():
    assert is_interface_name("wg0")
    assert is_interface_name("wg_1")
    assert not is_interface_name("wg interface")
    assert not is_interface_name("a" * 16)
    assert not is_interface_name(";rm -rf /")


def test_wg_key_validity():
    import base64
    import os
    private = base64.b64encode(os.urandom(32)).decode()
    assert is_wg_key(private)
    assert not is_wg_key(private[:-1])          # wrong length
    assert not is_wg_key("not a key at all!!!!")
    assert not is_wg_key("")


def test_normalize_cidrs():
    ok, _, ips = normalize_cidrs(["10.9.0.3/32", "10.9.0.3/32", "0.0.0.0/0"])
    assert ok and ips == ["10.9.0.3/32", "0.0.0.0/0"]
    assert not normalize_cidrs(["nonsense"])[0]
    assert not normalize_cidrs("string")[0]


def test_tunnel_input_validation():
    good = {"name": "office", "interface": "wg0", "role": "server",
            "listen_port": 51820, "addresses": ["10.9.0.1/24"], "mtu": 1420}
    assert validate_tunnel_input(good) == []
    assert validate_tunnel_input({**good, "interface": "evil iface"})
    assert validate_tunnel_input({**good, "role": "hacker"})
    assert validate_tunnel_input({**good, "listen_port": 99999})


def test_peer_input_validation():
    import base64
    import os
    pk = base64.b64encode(os.urandom(32)).decode()
    good = {"name": "laptop", "public_key": pk, "allowed_ips": ["10.9.0.3/32"]}
    assert validate_peer_input(good) == []
    assert validate_peer_input({**good, "public_key": "short"})
    assert validate_peer_input({**good, "allowed_ips": ["10.9.0.0/33"]})


def test_endpoint():
    assert is_endpoint("vps.example.com:51820")[0]
    assert is_endpoint("1.2.3.4:51820")[0]
    assert not is_endpoint("1.2.3.4:99999")[0]
    assert not is_endpoint("1.2.3.4:foo")[0]