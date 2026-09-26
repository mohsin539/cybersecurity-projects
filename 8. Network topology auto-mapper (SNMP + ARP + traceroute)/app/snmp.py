from __future__ import annotations

"""Minimal SNMPv2c Get/GetNext walker implemented purely on stdlib UDP.

No pysnmp dependency. v2c community strings are ephemeral (memory only) and
only ever sent over the agent-side channel. v3 USM is a documented extension
point (see security.md §snmp-v3) and deliberately out of scope for the v1 client.
"""

import socket
import struct  # noqa: F401  (kept for parity with spec decoding)
import time

from .util import valid_oid


class SNMPError(Exception):
    pass


# ---------- BER encoding ----------

def _len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, content: bytes) -> bytes:
    return bytes([tag]) + _len(len(content)) + content


def enc_int(v: int) -> bytes:
    if v < 0:
        raise SNP_EncodeError  # defined below
    if v == 0:
        return _tlv(0x02, b"\x00")
    body = v.to_bytes((v.bit_length() + 7) // 8, "big")
    if body[0] & 0x80:
        body = b"\x00" + body
    return _tlv(0x02, body)


class SNP_EncodeError(SNMPError):
    pass


def enc_oid(parts: list[int]) -> bytes:
    if not parts or parts[0] > 3 or parts[1] > 40:
        raise SNP_EncodeError("bad OID head")
    head = 40 * parts[0] + parts[1]
    out = bytearray([head])
    for x in parts[2:]:
        tmp = [x & 0x7F]
        x >>= 7
        while x > 0:
            tmp.append((x & 0x7F) | 0x80)
            x >>= 7
        out.extend(reversed(tmp))
    return _tlv(0x06, bytes(out))


# ---------- BER decoding ----------

def _head(data: bytes, i: int):
    tag = data[i]
    i += 1
    ln = data[i]
    i += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(data[i:i + n], "big")
        i += n
    return tag, ln, i


def _next(data: bytes, i: int = 0):
    tag, ln, p = _head(data, i)
    val = data[p:p + ln]
    return tag, val, p + ln


def decode_oid(b: bytes) -> tuple[int, ...]:
    out = [b[0] // 40, b[0] % 40]
    cur = 0
    for x in b[1:]:
        cur = (cur << 7) | (x & 0x7F)
        if not (x & 0x80):
            out.append(cur)
            cur = 0
    return tuple(out)


def decode_val(tag: int, v: bytes):
    if tag == 0x05:
        return None
    if tag == 0x02:
        return int.from_bytes(v, "big", signed=bool(v and v[0] & 0x80))
    if tag in (0x41, 0x42, 0x43, 0x46):  # Counter32/Gauge32/TimeTicks/Counter64
        return int.from_bytes(v, "big")
    if tag == 0x04:
        return v.decode("utf-8", "replace")
    if tag == 0x06:
        return ".".join(map(str, decode_oid(v)))
    if tag == 0x80:
        return ".".join(map(str, v))
    if tag == 0x44:
        return v.hex()
    return v.hex()


def parse_response(pdu: bytes):
    i = 0
    _t, _v, i = _next(pdu, i)      # request-id
    _t, esv, i = _next(pdu, i)     # error-status
    error_status = int.from_bytes(esv, "big")
    _t, _v, i = _next(pdu, i)      # error-index
    _t, body, _ = _next(pdu, i)    # varbind list
    vbs: list[tuple[str, object]] = []
    j = 0
    while j < len(body):
        _t, seq, j = _next(body, j)
        c = 0
        _t1, ln1, p = _head(seq, c)
        ov = seq[p:p + ln1]
        c = p + ln1
        try:
            parts = decode_oid(ov)
        except Exception:  # noqa: BLE001
            break
        _t2, ln2, p2 = _head(seq, c)
        val = seq[p2:p2 + ln2]
        vbs.append((".".join(map(str, parts)), decode_val(_t2, val)))
    return error_status, vbs


# ---------- client ----------

def _parse_parts(oid: str) -> list[int]:
    return [int(x) for x in oid.strip().split(".")]


class SnmpV2c:
    """Tiny SNMPv2c client. UDP, no persistent state. timeouts in seconds."""

    def __init__(self, host: str, community: str, port: int = 161,
                 timeout: float = 2.0, retries: int = 1) -> None:
        self.host = host
        self.community = community
        self.port = port
        self.timeout = timeout
        self.retries = retries

    def _request(self, oid_parts: list[int], pdu_type: int = 0xA0) -> tuple[int, list]:
        varlist = _tlv(0x30, _tlv(0x30, enc_oid(oid_parts) + _tlv(0x05, b"")))
        yer = int(time.time() * 1000) & 0x7FFFFFFF
        pdu = _tlv(pdu_type, enc_int(yer) + enc_int(0) + enc_int(0) + varlist)
        msg = _tlv(0x30, enc_int(1) + _tlv(0x04, self.community.encode()) + pdu)
        last = None
        for _ in range(self.retries + 1):
            sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            sock.settimeout(self.timeout)
            try:
                sock.sendto(msg, (self.host, self.port))
                data, _addr = sock.recvfrom(65536)
                return _decode_message(data)
            except Exception as e:  # noqa: BLE001
                last = e
            finally:
                sock.close()
        raise SNMPError(f"no response from {self.host}:{self.port} ({last})")

    def walk(self, base_oid: str, limit: int = 500, deadline: float = 20.0) -> list:
        if not valid_oid(base_oid):
            raise SNMPError("invalid OID")
        base = _parse_parts(base_oid)
        cur = base
        out: list[tuple[str, object]] = []
        start = time.time()
        for _ in range(limit):
            if time.time() - start > deadline:
                break
            status, vbs = self._request(cur, 0xA1)
            if status != 0 or not vbs:
                break
            oid, val = vbs[-1]
            parts = _parse_parts(oid)
            if parts[:len(base)] != base:
                break
            out.append((oid, val))
            cur = parts
        return out

    def get(self, oid: str):
        status, vbs = self._request(_parse_parts(oid), 0xA0)
        if status != 0:
            raise SNMPError(f"error-status {status}")
        return vbs[-1] if vbs else (oid, None)


def _decode_message(data: bytes):
    _t, body, _ = _next(data, 0)
    i = 0
    _t, versb, i = _next(body, i)
    _t, comm, i = _next(body, i)
    pdu_tag, pdu, _ = _next(body, i)
    return parse_response(pdu)


def walk_single(host: str, community: str, base_oid: str, **kw) -> list:
    """Convenience: walk one agent, returning list of (oid, value)."""
    return SnmpV2c(host, community, **kw).walk(base_oid)