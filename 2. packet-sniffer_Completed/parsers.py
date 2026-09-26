"""Packet parsing engine.

Pure, dependency-free protocol parsers for Ethernet II, ARP, IPv4, TCP, UDP,
ICMPv4 and DNS. All parsing works on ``memoryview`` slices via
``struct.unpack_from`` for zero-copy performance.

Every parser is defensive by design: malformed or truncated packets raise
:class:`PacketParseError` which the caller converts to a log + counter —
never a crash. A hostile packet must not be a DoS vector against the sniffer.
"""
from __future__ import annotations

import struct
import time
from dataclasses import dataclass, field
from typing import Optional

MAX_SANE_LEN = 65535


class PacketParseError(ValueError):
    """Raised when a packet is truncated or structurally invalid."""


# --------------------------------------------------------------------------
# Protocol constants
# --------------------------------------------------------------------------
ETH_P_IPV4 = 0x0800
ETH_P_ARP = 0x0806
ETH_P_IPV6 = 0x86DD

IPPROTO_ICMP = 1
IPPROTO_TCP = 6
IPPROTO_UDP = 17

TCP_FIN, TCP_SYN, TCP_RST, TCP_PSH, TCP_ACK, TCP_URG, TCP_ECE, TCP_CWR = (
    0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80,
)

# Well-known port → service name map (curated subset for display enrichment)
SERVICES: dict[int, str] = {
    20: "ftp-data", 21: "ftp", 22: "ssh", 23: "telnet", 25: "smtp",
    53: "domain", 67: "dhcp-srv", 68: "dhcp-cli", 80: "http", 110: "pop3",
    111: "rpcbind", 123: "ntp", 135: "msrpc", 137: "netbios-ns",
    138: "netbios-dgm", 139: "netbios-ssn", 143: "imap", 161: "snmp",
    162: "snmptrap", 389: "ldap", 443: "https", 445: "smb", 465: "smtps",
    514: "syslog", 587: "submission", 636: "ldaps", 993: "imaps",
    995: "pop3s", 1080: "socks", 1194: "openvpn", 1433: "mssql",
    1521: "oracle", 1900: "ssdp", 2082: "cpanel", 3306: "mysql",
    3389: "ms-wbt", 4444: "metasploit", 5060: "sip", 5061: "sips",
    5432: "pgsql", 5900: "vnc", 6379: "redis", 8080: "http-alt",
    8443: "https-alt", 9200: "elastic", 11211: "memcached",
    27017: "mongodb", 51820: "wireguard",
}

FLAG_NAMES = ("FIN", "SYN", "RST", "PSH", "ACK", "URG", "ECE", "CWR")

ICMP_TYPES = {
    0: "Echo Reply", 3: "Dest Unreachable", 4: "Source Quench",
    5: "Redirect", 8: "Echo Request", 9: "Router Advert",
    10: "Router Solicit", 11: "Time Exceeded", 12: "Param Problem",
    13: "Timestamp", 14: "Timestamp Reply",
}
ICMP_CODE_3 = {
    0: "Net Unreachable", 1: "Host Unreachable", 2: "Proto Unreachable",
    3: "Port Unreachable", 4: "Frag Needed", 5: "Src Route Failed",
    9: "Net Prohibited", 10: "Host Prohibited", 13: "Admin Prohibited",
}


# --------------------------------------------------------------------------
# Data models
# --------------------------------------------------------------------------
@dataclass
class Packet:
    """Normalized parse result for one captured frame."""
    timestamp: float
    src_mac: str = ""
    dst_mac: str = ""
    src_ip: str = ""
    dst_ip: str = ""
    src_port: int = 0
    dst_port: int = 0
    protocol: str = "OTHER"
    length: int = 0                       # captured frame length (L2 or L3)
    info: str = ""
    flags: str = ""
    ttl: int = 0
    ip_id: int = 0
    tos: int = 0
    ip_version: int = 4
    ethertype: int = 0
    seq: Optional[int] = None
    ack: Optional[int] = None
    window: int = 0
    tcp_options: dict = field(default_factory=dict)
    icmp_type: int = -1
    icmp_code: int = -1
    dns: Optional[dict] = None
    payload_hex: str = ""                 # first N payload bytes (display/evidence)
    payload_ascii: str = ""
    raw_hex: str = ""                     # display hex prefix (first 96 B)
    raw: bytes = b""                      # full captured frame (PCAP export)
    layers: list = field(default_factory=list)   # e.g. ["ETH","IPv4","TCP"]

    @property
    def proto(self) -> str:
        return self.protocol

    def flag_str(self) -> str:
        return self.flags


# --------------------------------------------------------------------------
# Low-level helpers
# --------------------------------------------------------------------------
def _mac(b: memoryview) -> str:
    return ":".join(f"{x:02x}" for x in b)


def _ipv4(b: memoryview) -> str:
    return ".".join(str(x) for x in b)


def _ascii(payload: bytes, limit: int = 96) -> str:
    """Printable-ASCII rendering of payload for quick-look columns."""
    out = []
    for ch in payload[:limit]:
        out.append(chr(ch) if 32 <= ch < 127 else ".")
    return "".join(out)


def _hexb(payload: bytes, limit: int = 64) -> str:
    return payload[:limit].hex()


def _tcp_flags(flags: int) -> str:
    return "[" + ", ".join(
        n for n, bit in zip(FLAG_NAMES, (0x01, 0x02, 0x04, 0x08,
                                         0x10, 0x20, 0x40, 0x80))
        if flags & bit
    ) + "]" if flags else "[]"


def _l4_payload_string(data: bytes, sport: int, dport: int) -> str:
    """Application-layer hint for common plaintext protocols."""
    try:
        if dport in (80, 8080, 8000) or sport in (80, 8080, 8000):
            if b"HTTP/1." in data[:64]:
                first = data.split(b"\r\n", 1)[0]
                return first.decode("latin-1")[:80]
        if 53 in (sport, dport) and len(data) >= 12:
            dns = parse_dns(data)
            if dns:
                q = dns.get("queries") or []
                return f"DNS Q: {q[0]['name']}" if q else "DNS"
        if 21 in (sport, dport):
            return data[:64].decode("latin-1").strip()[:80]
        if 23 in (sport, dport):
            return data[:64].decode("latin-1").strip()[:80]
    except Exception:  # noqa: BLE001 — display hints must never throw
        pass
    return ""


# --------------------------------------------------------------------------
# Layer parsers
# --------------------------------------------------------------------------
def parse_ethernet(mv: memoryview):
    if len(mv) < 14:
        raise PacketParseError("truncated Ethernet header")
    dst = _mac(mv[0:6])
    src = _mac(mv[6:12])
    ethertype = struct.unpack_from("!H", mv, 12)[0]
    return dst, src, ethertype, mv[14:]


def parse_arp(mv: memoryview) -> dict:
    if len(mv) < 28:
        raise PacketParseError("truncated ARP")
    htype, ptype, hlen, plen, oper = struct.unpack_from("!HHBBH", mv, 0)
    if plen != 4:
        raise PacketParseError("ARP with non-IPv4 protocol")
    off = 8
    sha = _mac(mv[off:off + 6]); off += 6
    spa = _ipv4(mv[off:off + 4]); off += 4
    tha = _mac(mv[off:off + 6]); off += 6
    tpa = _ipv4(mv[off:off + 4])
    return {
        "oper": oper, "sha": sha, "spa": spa, "tha": tha, "tpa": tpa,
        "summary": f"{'Who has' if oper == 1 else 'At'} {tpa}"
                   + (f" — tell {spa}" if oper == 1 else f" is-at {tha}"),
    }


def parse_ipv4(mv: memoryview):
    """Returns (src, dst, proto, ttl, ihl_words, id, tos, payload_mv, flags_frag)."""
    if len(mv) < 20:
        raise PacketParseError("truncated IPv4 header")
    v_ihl = mv[0]
    version = v_ihl >> 4
    if version != 4:
        raise PacketParseError("not IPv4")
    ihl_words = v_ihl & 0x0F
    if ihl_words < 5:
        raise PacketParseError("IPv4 IHL < 5")
    total_len = struct.unpack_from("!H", mv, 2)[0]
    tos = mv[1]
    ip_id = struct.unpack_from("!H", mv, 4)[0]
    flags_frag = struct.unpack_from("!H", mv, 6)[0]
    ttl = mv[8]
    proto = mv[9]
    src = _ipv4(mv[12:16])
    dst = _ipv4(mv[16:20])
    hdr_len = ihl_words * 4
    if hdr_len > len(mv):
        raise PacketParseError("IPv4 header length exceeds frame")
    # Payload length: trust min(total_len, captured)
    plen = min(total_len if total_len else len(mv), len(mv)) - hdr_len
    if plen < 0:
        raise PacketParseError("IPv4 total_len smaller than header")
    return (src, dst, proto, ttl, ihl_words, ip_id, tos,
            mv[hdr_len:hdr_len + plen], flags_frag)


def parse_tcp(mv: memoryview) -> dict:
    if len(mv) < 20:
        raise PacketParseError("truncated TCP header")
    sport, dport, seq, ack, doff_res, flags, win, cksum, urg = struct.unpack_from(
        "!HHIIBBHHH", mv, 0
    )
    doff = (doff_res >> 4) * 4
    if doff < 20 or doff > len(mv):
        raise PacketParseError("TCP data offset invalid")
    opts_raw = bytes(mv[20:doff])
    options: dict = {}
    i = 0
    while i < len(opts_raw):
        kind = opts_raw[i]
        if kind == 0:
            break
        if kind == 1:
            i += 1
            continue
        if i + 1 >= len(opts_raw):
            break
        olen = opts_raw[i + 1]
        if olen < 2 or i + olen > len(opts_raw):
            break
        body = opts_raw[i + 2:i + olen]
        if kind == 2 and olen == 4:
            options["MSS"] = struct.unpack("!H", body)[0]
        elif kind == 3 and olen == 3:
            options["WS"] = body[0]
        elif kind == 4 and olen == 2:
            options["SACKok"] = True
        elif kind == 8 and olen == 10:
            options["TSval"] = struct.unpack("!I", body[:4])[0]
        i += olen
    return {
        "sport": sport, "dport": dport, "seq": seq, "ack": ack,
        "flags": flags, "window": win, "options": options,
        "payload": bytes(mv[doff:]),
    }


def parse_udp(mv: memoryview) -> dict:
    if len(mv) < 8:
        raise PacketParseError("truncated UDP header")
    sport, dport, ulen, cksum = struct.unpack_from("!HHHH", mv, 0)
    if ulen and ulen > len(mv):
        raise PacketParseError("UDP length exceeds captured data")
    return {"sport": sport, "dport": dport,
            "payload": bytes(mv[8:ulen if ulen else len(mv)])}


def parse_icmp(mv: memoryview) -> dict:
    if len(mv) < 4:
        raise PacketParseError("truncated ICMP header")
    itype, code, cksum = struct.unpack_from("!BBH", mv, 0)
    rest = bytes(mv[4:])
    desc = ICMP_TYPES.get(itype, f"Type {itype}")
    if itype == 3:
        desc = f"Dest Unreachable / {ICMP_CODE_3.get(code, 'code %d' % code)}"
    ident = seq_no = 0
    if itype in (0, 8):
        if len(rest) >= 4:
            ident, seq_no = struct.unpack_from("!HH", rest, 0)
            desc = f"Echo{' Request' if itype == 8 else ' Reply'} id={ident} seq={seq_no}"
    return {"type": itype, "code": code, "desc": desc,
            "payload": rest[4:] if itype in (0, 8) else rest}


def parse_dns(data: bytes) -> Optional[dict]:
    """Decode DNS header + question/answer names (handles compression)."""
    if len(data) < 12:
        return None
    tid, flags, qd, an, ns, ar = struct.unpack_from("!6H", data, 0)
    is_response = bool(flags & 0x8000)
    opcode = (flags >> 11) & 0xF
    rcode = flags & 0xF

    def read_name(off: int) -> tuple[str, int]:
        labels = []
        jumps = 0
        orig = off
        while off < len(data):
            ln = data[off]
            if ln == 0:
                off += 1
                break
            if ln & 0xC0 == 0xC0:
                if off + 1 >= len(data):
                    break
                ptr = ((ln & 0x3F) << 8) | data[off + 1]
                if ptr >= off or jumps > 16:  # anti-loop guard
                    break
                jumps += 1
                if not labels:
                    orig = off + 2
                off = ptr
                continue
            if off + 1 + ln > len(data):
                break
            try:
                labels.append(data[off + 1:off + 1 + ln].decode("ascii"))
            except UnicodeDecodeError:
                labels.append("<binary>")
            off += 1 + ln
        return ".".join(labels) or "<root>", orig

    queries, answers = [], []
    off = 12
    for _ in range(min(qd, 16)):
        name, off = read_name(off)
        if off + 4 > len(data):
            break
        qtype, qclass = struct.unpack_from("!HH", data, off)
        off += 4
        queries.append({"name": name, "type": qtype, "class": qclass})
    for _ in range(min(an, 16)):
        if off >= len(data):
            break
        name, off = read_name(off)
        if off + 10 > len(data):
            break
        rtype, rclass, ttl, rdlen = struct.unpack_from("!HHIH", data, off)
        off += 10
        rd = data[off:off + rdlen]
        if rtype == 1 and rdlen == 4:
            rval = _ipv4(memoryview(rd))
        elif rtype == 28 and rdlen == 16:
            rval = ":".join(f"{b:02x}" for b in rd)
        else:
            rval = rd[:32].hex()
        off += rdlen
        answers.append({"name": name, "type": rtype, "value": rval})
    return {
        "id": tid, "response": is_response, "opcode": opcode, "rcode": rcode,
        "queries": queries, "answers": answers,
    }


# --------------------------------------------------------------------------
# Top-level dispatcher
# --------------------------------------------------------------------------
def parse_packet(raw: bytes, timestamp: Optional[float] = None) -> Packet:
    """Parse a captured frame. ``raw`` starts at the link-layer header
    (Ethernet on AF_PACKET). On Windows raw-IP sockets there is no Ethernet
    header; the capture engine prepends a synthetic Ethernet header so the
    dispatcher sees a uniform L2 frame (also required for valid PCAP export).
    """
    ts = timestamp if timestamp is not None else time.time()
    mv = memoryview(raw)
    p = Packet(timestamp=ts, length=len(raw))
    p.raw = raw

    # ---- L2 ------------------------------------------------------------
    eth = parse_ethernet(mv)
    p.dst_mac, p.src_mac, p.ethertype, l3 = eth
    p.layers.append("ETH")
    p.raw_hex = raw[:96].hex()

    # ---- L3 ------------------------------------------------------------
    if p.ethertype == ETH_P_ARP:
        p.protocol = "ARP"
        p.layers.append("ARP")
        try:
            arp = parse_arp(l3)
            p.src_ip, p.dst_ip = arp["spa"], arp["tpa"]
            p.info = arp["summary"]
        except PacketParseError as e:
            p.info = f"ARP (malformed: {e})"
        return p

    if p.ethertype == ETH_P_IPV6:
        p.protocol = "IPv6"
        p.layers.append("IPv6")
        p.src_ip = ".".join(str(b) for b in l3[8:12])  # placeholder display
        p.dst_ip = ".".join(str(b) for b in l3[24:28])
        p.info = "IPv6 (stub parser)"
        return p

    if p.ethertype != ETH_P_IPV4:
        p.protocol = f"0x{p.ethertype:04x}"
        p.info = f"Non-IP ethertype 0x{p.ethertype:04x}"
        return p

    src, dst, proto, ttl, ihl, ip_id, tos, l4, flags_frag = parse_ipv4(l3)
    p.src_ip, p.dst_ip = src, dst
    p.ttl, p.ip_id, p.tos = ttl, ip_id, tos
    p.layers.append("IPv4")
    if flags_frag & 0x1FFF:               # non-zero fragment offset
        p.info = "IPv4 fragment (offset %d)" % ((flags_frag & 0x1FFF) * 8)
        p.protocol = "IPv4-frag"
        return p

    # ---- L4 ------------------------------------------------------------
    if proto == IPPROTO_TCP:
        p.protocol = "TCP"
        p.layers.append("TCP")
        t = parse_tcp(l4)
        p.src_port, p.dst_port = t["sport"], t["dport"]
        p.seq, p.ack, p.window = t["seq"], t["ack"], t["window"]
        p.flags = _tcp_flags(t["flags"])
        p.tcp_options = t["options"]
        p.payload_hex = _hexb(t["payload"])
        p.payload_ascii = _ascii(t["payload"])
        hint = _l4_payload_string(t["payload"], p.src_port, p.dst_port)
        opts = " ".join(f"{k}={v}" for k, v in t["options"].items())
        p.info = f"{p.src_port} → {p.dst_port} {p.flags}" + (f" {opts}" if opts else "")
        if hint:
            p.info += f"  [{hint}]"
    elif proto == IPPROTO_UDP:
        p.protocol = "UDP"
        p.layers.append("UDP")
        u = parse_udp(l4)
        p.src_port, p.dst_port = u["sport"], u["dport"]
        p.payload_hex = _hexb(u["payload"])
        p.payload_ascii = _ascii(u["payload"])
        if 53 in (p.src_port, p.dst_port):
            p.layers.append("DNS")
            d = parse_dns(u["payload"])
            if d:
                p.dns = d
                q = d["queries"][0]["name"] if d["queries"] else "?"
                p.info = (f"{p.src_port} → {p.dst_port} "
                          f"{'RESP' if d['response'] else 'Q'} {q}"
                          + (f" → {d['answers'][0]['value']}" if d["answers"] else ""))
            else:
                p.info = f"{p.src_port} → {p.dst_port} DNS (truncated)"
        else:
            hint = _l4_payload_string(u["payload"], p.src_port, p.dst_port)
            p.info = f"{p.src_port} → {p.dst_port} len={len(u['payload'])}"
            if hint:
                p.info += f" [{hint}]"
    elif proto == IPPROTO_ICMP:
        p.protocol = "ICMP"
        p.layers.append("ICMP")
        ic = parse_icmp(l4)
        p.icmp_type, p.icmp_code = ic["type"], ic["code"]
        p.payload_hex = _hexb(ic["payload"])
        p.payload_ascii = _ascii(ic["payload"])
        extra = ""
        if ic["type"] == 8 and len(ic["payload"]) > 32:
            extra = f" (payload {len(ic['payload'])}B — tunneling?)"
        p.info = ic["desc"] + extra
    else:
        p.protocol = f"IP:{proto}"
        p.layers.append(f"IP:{proto}")
        p.info = f"{p.src_ip} → {p.dst_ip} proto {proto}"

    return p
