from arp_scanner.core.devices import lookup_vendor


def test_known_vendor():
    assert lookup_vendor("B8:27:EB:AA:BB:CC") == "Raspberry Pi"


def test_dash_format():
    assert lookup_vendor("b8-27-eb-00-00-00") == "Raspberry Pi"


def test_unknown_vendor():
    assert lookup_vendor("02:00:00:00:00:01") is None


def test_invalid_mac():
    assert lookup_vendor("zz:zz:zz") is None
    assert lookup_vendor("") is None
    assert lookup_vendor(None) is None