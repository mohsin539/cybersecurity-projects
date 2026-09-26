"""Demo mode — synthetic traffic through the real pipeline.

Runs the actual parse/enrich/render stack against generated frames so the
tool can be validated without admin privileges. Also fires a scripted port
scan and cleartext-credential event to exercise the ThreatAnalyzer.
"""
from __future__ import annotations

import queue
import struct
import threading
import time
import random

from parsers import parse_packet
import gui


def _eth(dst: bytes, src: bytes, ethertype: int) -> bytes:
    return dst + src + struct.pack("!H", ethertype)


def _ipv4(src: str, dst: str, proto: int, payload: bytes, ttl=64,
          ident=None) -> bytes:
    ident = ident if ident is not None else random.randint(0, 0xFFFF)
    total = 20 + len(payload)
    hdr = struct.pack("!BBHHHBBH4s4s",
                      0x45, 0, total, ident, 0x4000, ttl, proto, 0,
                      bytes(int(x) for x in src.split(".")),
                      bytes(int(x) for x in dst.split(".")))
    return hdr + payload


def _tcp(sport, dport, flags, payload=b"", seq=1, ack=1, win=64240) -> bytes:
    return struct.pack("!HHIIBBHHH",
                       sport, dport, seq, ack, 0x50, flags, win, 0, 0) + payload


def _udp(sport, dport, payload: bytes) -> bytes:
    return struct.pack("!HHHH", sport, dport, 8 + len(payload), 0) + payload


def _dns_query(name: str) -> bytes:
    parts = name.split(".")
    qname = b"".join(bytes([len(p)]) + p.encode() for p in parts) + b"\x00"
    return struct.pack("!6H", 0x1234, 0x0100, 1, 0, 0, 0) + qname + struct.pack("!HH", 1, 1)


MAC_A = bytes.fromhex("aabbccddeeff")
MAC_B = bytes.fromhex("112233445566")
BCAST = b"\xff" * 6


def build_frames() -> list[bytes]:
    frames = []

    # ARP request + reply
    arp_req = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 1) + MAC_A + \
        bytes(map(int, "192.168.1.10".split("."))) + b"\x00" * 6 + \
        bytes(map(int, "192.168.1.1".split(".")))
    arp_rep = struct.pack("!HHBBH", 1, 0x0800, 6, 4, 2) + MAC_B + \
        bytes(map(int, "192.168.1.1".split("."))) + MAC_A + \
        bytes(map(int, "192.168.1.10".split(".")))
    frames.append(_eth(BCAST, MAC_A, 0x0806) + arp_req)
    frames.append(_eth(MAC_A, MAC_B, 0x0806) + arp_rep)

    # TCP 3-way handshake 10.0.0.5 → 93.184.216.34:443
    ip_a, ip_b = "10.0.0.5", "93.184.216.34"
    for fl in (0x02, 0x12, 0x10):
        frames.append(_eth(MAC_A, MAC_B, 0x0800) +
                      _ipv4(ip_a, ip_b, 6, _tcp(51000, 443, fl)))

    # HTTP GET (cleartext → triggers CREDS only if pattern matches; harmless)
    http = (b"GET /login HTTP/1.1\r\nHost: example.com\r\n"
            b"user=admin&password=SuperSecret123\r\n\r\n")
    frames.append(_eth(MAC_A, MAC_B, 0x0800) +
                  _ipv4(ip_a, ip_b, 6, _tcp(51000, 80, 0x18, http)))

    # DNS query for example.com
    frames.append(_eth(MAC_A, MAC_B, 0x0800) +
                  _ipv4("10.0.0.5", "8.8.8.8", 17,
                        _udp(51001, 53, _dns_query("example.com"))))

    # ICMP echo with big payload (tunnel heuristic)
    icmp = struct.pack("!BBHHH", 8, 0, 0, 0x1234, 1) + b"A" * 64
    frames.append(_eth(MAC_A, MAC_B, 0x0800) +
                  _ipv4(ip_a, ip_b, 1, icmp))

    # Scripted port scan: 30 SYN packets to distinct ports
    scan_ip = "45.33.32.156"
    for port in range(20, 50):
        frames.append(_eth(MAC_B, MAC_A, 0x0800) +
                      _ipv4(scan_ip, "10.0.0.5", 6,
                            _tcp(random.randint(40000, 60000), port, 0x02)))

    # UDP misc + IPv6 stub frame (ethertype only)
    frames.append(_eth(MAC_A, MAC_B, 0x0800) +
                  _ipv4("10.0.0.5", "8.8.8.8", 17,
                        _udp(51002, 123, b"\x1b" + b"\x00" * 47)))
    frames.append(_eth(MAC_A, MAC_B, 0x86DD) +
                  b"\x60\x00\x00\x00\x00\x14\x11\x40" + b"\x20" * 16 +
                  b"\x20" * 16 + _udp(51003, 443, b""))

    return frames


def run_demo(stop_after: float | None = None):
    """Pump synthetic frames through parse → threat → GUI."""
    raw_q: "queue.Queue" = queue.Queue(maxsize=25000)

    # Build GUI but don't start real capture — we inject frames instead.
    app = gui.SnifferGUI()
    app.authorized.set(True)
    app.iface_cb.set("demo (synthetic traffic)")

    def feeder():
        from capture import CaptureStats, make_processor
        s = CaptureStats()
        threads, stop = make_processor(raw_q, s, app._on_packet)
        frames = build_frames()
        i = 0
        t0 = time.time()
        while time.time() - t0 < (stop_after or 3600):
            f = frames[i % len(frames)]
            try:
                raw_q.put_nowait((time.time(), f))
            except queue.Full:
                pass
            i += 1
            time.sleep(0.02)
        stop.set()

    threading.Thread(target=feeder, daemon=True).start()
    gui.theme.apply_theme(app)
    app.mainloop()


if __name__ == "__main__":
    run_demo()
