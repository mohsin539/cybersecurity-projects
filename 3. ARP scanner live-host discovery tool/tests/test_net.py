import pytest

from arp_scanner.util.net import (
    TargetError,
    expand_target,
    expand_target_info,
    is_reserved_host,
    normalize_mac,
    oui_prefix,
    sort_addresses,
)


class TestExpandTarget:
    def test_cidr_hosts_excludes_network_and_broadcast(self):
        addresses = expand_target("192.168.1.0/30")
        assert [str(a) for a in addresses] == ["192.168.1.1", "192.168.1.2"]

    def test_full_range(self):
        addresses = expand_target("10.0.0.1-10.0.0.3")
        assert [str(a) for a in addresses] == ["10.0.0.1", "10.0.0.2", "10.0.0.3"]

    def test_short_range(self):
        addresses = expand_target("10.0.0.5-7")
        assert [str(a) for a in addresses] == ["10.0.0.5", "10.0.0.6", "10.0.0.7"]

    def test_single(self):
        assert [str(a) for a in expand_target("1.2.3.4")] == ["1.2.3.4"]

    def test_range_reversed_raises(self):
        with pytest.raises(TargetError):
            expand_target("10.0.0.9-10.0.0.2")

    @pytest.mark.parametrize(
        "bad",
        ["", "   ", "abc", "999.1.1.1", "1.2.3", "1.2.3.4/33", "1.2.3.4/99", "1.2.3.4-", "1.2.3.4-1.2.3"],
    )
    def test_invalid_targets_raise(self, bad):
        with pytest.raises(TargetError):
            expand_target(bad)

    def test_ipv6_rejected(self):
        with pytest.raises(TargetError):
            expand_target("2001:db8::1")

    def test_big_range_capped(self):
        with pytest.raises(TargetError):
            expand_target("0.0.0.0-255.255.255.255")


class TestReservedFilter:
    def test_network_and_broadcast_detected(self):
        _addrs, net = expand_target_info("192.168.1.0/24")
        assert is_reserved_host(__import__("ipaddress").IPv4Address("192.168.1.0"), net)
        assert is_reserved_host(__import__("ipaddress").IPv4Address("192.168.1.255"), net)
        assert not is_reserved_host(__import__("ipaddress").IPv4Address("192.168.1.5"), net)

    def test_none_network(self):
        assert not is_reserved_host(__import__("ipaddress").IPv4Address("192.168.1.5"), None)


class TestMac:
    def test_normalize_colon(self):
        assert normalize_mac("AA:BB:CC:DD:EE:F1") == "aa:bb:cc:dd:ee:f1"

    def test_normalize_dash(self):
        assert normalize_mac("AA-BB-CC-DD-EE-F1") == "aa:bb:cc:dd:ee:f1"

    def test_invalid(self):
        assert normalize_mac("not-a-mac") is None

    def test_oui_prefix(self):
        assert oui_prefix("b8:27:eb:11:22:33") == "b827eb"

    def test_sort(self):
        addrs = [__import__("ipaddress").IPv4Address(x) for x in ("192.168.1.10", "192.168.1.2")]
        assert [str(a) for a in sort_addresses(addrs)] == ["192.168.1.2", "192.168.1.10"]