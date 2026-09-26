from ipaddress import IPv4Address

from scapy.layers.l2 import ARP, Ether

from arp_scanner.core.packets import build_arp_request, parse_arp_reply


def test_build_request_is_broadcast_who_has():
    frame = build_arp_request("aa:bb:cc:dd:ee:ff", "192.168.1.5", "192.168.1.7")
    assert frame[Ether].dst == "ff:ff:ff:ff:ff:ff"
    arp = frame[ARP]
    assert arp.op == 1
    assert arp.hwsrc == "aa:bb:cc:dd:ee:ff"
    assert arp.psrc == "192.168.1.5"
    assert arp.pdst == "192.168.1.7"


def test_parse_arp_reply_roundtrip():
    reply = Ether(src="b8:27:eb:11:22:33") / ARP(
        op=2, hwsrc="b8:27:eb:11:22:33", psrc="192.168.1.7", pdst="192.168.1.5"
    )
    parsed = parse_arp_reply(reply)
    assert parsed is not None
    ip, mac = parsed
    assert ip == IPv4Address("192.168.1.7")
    assert mac == "b8:27:eb:11:22:33"


def test_parse_ignores_requests():
    request = Ether() / ARP(op=1, psrc="192.168.1.7", pdst="192.168.1.5")
    assert parse_arp_reply(request) is None


def test_parse_none_and_garbage():
    assert parse_arp_reply(None) is None
    assert parse_arp_reply("garbage") is None
    assert parse_arp_reply(Ether()) is None