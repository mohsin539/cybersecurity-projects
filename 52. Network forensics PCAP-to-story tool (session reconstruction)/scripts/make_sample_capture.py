"""make_sample_capture.py - synthesizes a small but realistic triage PCAP.

Creates a 100% valid pcap using dpkt so the suite has reproducible demo data and
the smoke test can verify the full pipeline headless.

Scenarios encoded in the sample:
  1. DNS reconnaissance   - internal host resolving suspicious domains
  2. Cleartext HTTP       - GET + credentials-in-URI (cred in transit)
  3. Periodic UDP beacon  - 8 x 1.0s small UDP probes (C2 beacon pattern)
  4. Large TCP exfil POST - outbound burst >> inbound (T1041)
  5. TLS ClientHello      - encrypted channel start
"""

from __future__ import annotations

import socket
import struct

import dpkt


def _eth(inner: bytes, src=b"\x00\x11\x22\x33\x44\x55", dst=b"\x66\x77\x88\x99\xaa\xbb") -> bytes:
    return dst + src + struct.pack("!H", 0x0800) + inner


def _tcp(sport, dport, seq, payload: bytes, flags: int = dpkt.tcp.TH_ACK) -> bytes:
    tcp = dpkt.tcp.TCP(sport=sport, dport=dport, seq=seq, ack=1, flags=flags, win=65535, data=payload)
    return tcp.pack()


def _ip4(src: str, dst: str, proto: int, payload: bytes) -> bytes:
    ip = dpkt.ip.IP(src=socket.inet_aton(src), dst=socket.inet_aton(dst), p=proto, ttl=64, data=payload)
    return ip.pack()


def _udp(sport, dport, payload: bytes) -> bytes:
    return dpkt.udp.UDP(sport=sport, dport=dport, data=payload).pack()


def build(out_path: str) -> int:
    t0 = 1758000000.0
    writer = dpkt.pcap.Writer(open(out_path, "wb"))
    n = 0
    src = "10.10.0.55"
    dst = "203.0.113.9"

    def emit(ts, raw):
        nonlocal n
        writer.writepkt(_eth(raw), ts)
        n += 1

    # 1) DNS queries
    dns_payload = (
        b"\x9f\x2a\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x04evil\x07example\x03com\x00\x00\x01\x00\x01"
    )
    emit(t0 + 0.1, _ip4(src, "8.8.8.8", 17, _udp(53444, 53, dns_payload)))

    dns2 = (
        b"\x9f\x2b\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00"
        b"\x0acloud\\x2dmirror\x07example\x03net\x00\x00\x01\x00\x01"
    )
    emit(t0 + 0.3, _ip4(src, "8.8.8.8", 17, _udp(53445, 53, dns2)))

    # 2) TCP handshake + HTTP GET with credentials
    a = 4000
    emit(t0 + 1.0, _ip4(src, dst, 6, _tcp(49152, 80, a, b"", dpkt.tcp.TH_SYN)))
    emit(t0 + 1.05, _ip4(dst, src, 6, _tcp(80, 49152, 9000, b"", dpkt.tcp.TH_SYN | dpkt.tcp.TH_ACK)))
    emit(t0 + 1.1, _ip4(src, dst, 6, _tcp(49152, 80, a + 1, b"", dpkt.tcp.TH_ACK)))
    get = b"GET /admin?user=root&password=P@ssw0rd HTTP/1.1\r\nHost: internal.corp.local\r\nUser-Agent: curl/8.4\r\n\r\n"
    a += 1
    emit(t0 + 1.15, _ip4(src, dst, 6, _tcp(49152, 80, a, get)))
    a += len(get)
    resp = b"HTTP/1.1 401 Unauthorized\r\nServer: nginx/1.24\r\nContent-Length: 0\r\n\r\n"
    emit(t0 + 1.18, _ip4(dst, src, 6, _tcp(80, 49152, 9001, resp)))
    emit(t0 + 1.2, _ip4(src, dst, 6, _tcp(49152, 80, a, b"")))

    # 3) TLS ClientHello (partial record header + handshake bytes)
    tls = b"\x16\x03\x03\x00\x50\x01\x00\x00\x4c\x03\x03" + b"\x00" * 100
    emit(t0 + 2.0, _ip4(src, dst, 6, _tcp(49153, 443, 6000, tls)))

    # 4) Periodic UDP beacon every 1.0 s
    for i in range(8):
        emit(t0 + 10.0 + i * 1.0, _ip4(src, dst, 17, _udp(4444, 8080, b"\xde\xad\xbe\xef\x01")))

    # 5) TCP exfil POST burst (segmented outbound -> contiguous stream)
    bseq = 100000
    post_head = b"POST /upload HTTP/1.1\r\nContent-Length: 51200\r\n\r\n"
    emit(t0 + 20.0, _ip4(src, dst, 6, _tcp(50000, 80, bseq, post_head)))
    bseq += len(post_head)
    block = b"A" * 1024
    for i in range(50):
        emit(t0 + 20.05 + i * 0.002, _ip4(src, dst, 6, _tcp(50000, 80, bseq + i * len(block), block)))
    bseq += 50 * len(block)
    emit(t0 + 20.3, _ip4(dst, src, 6, _tcp(80, 50000, 5000, b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")))

    writer.close()
    return n


if __name__ == "__main__":
    import sys

    count = build(sys.argv[1] if len(sys.argv) > 1 else "sample_triage.pcap")
    print(f"Wrote {count} frames -> {sys.argv[1] if len(sys.argv) > 1 else 'sample_triage.pcap'}")