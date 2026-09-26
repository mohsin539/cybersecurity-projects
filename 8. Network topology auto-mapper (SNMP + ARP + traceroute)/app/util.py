from __future__ import annotations

import base64
import hashlib
import hmac
import ipaddress
import os
import re
import secrets
import time
from datetime import datetime, timezone

__all__ = [
    "now_ts", "new_id", "valid_oid", "parse_cidr", "ipv4_valid", "in_scope",
    "hash_val", "pbkdf2", "sign", "sig_valid", "b64e", "b64d",
    "totp_now", "totp_verify", "gen_totp_secret",
]

TS_FMT = "%Y-%m-%dT%H:%M:%SZ"
OID_RE = re.compile(r"^\d+(\.\d+){0,32}$")


def now_ts() -> str:
    return datetime.now(timezone.utc).strftime(TS_FMT)


def new_id(prefix: str = "") -> str:
    return f"{prefix}{secrets.token_hex(6)}"


def valid_oid(oid: str) -> bool:
    return bool(oid) and bool(OID_RE.match(oid)) and len(oid) <= 128


def parse_cidr(cidr: str):
    return ipaddress.ip_network(cidr.strip(), strict=False)


def ipv4_valid(ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip.strip()).version == 4
    except ValueError:
        return False


def in_scope(ip: str, net) -> bool:
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return a.version == 4 and a in net


def hash_val(s: str, size: int = 12) -> str:
    return hashlib.sha256(s.encode("utf-8", "replace")).hexdigest()[:size]


def pbkdf2(pw: str, salt: bytes, iters: int = 310_000) -> str:
    return hashlib.pbkdf2_hmac("sha256", pw.encode("utf-8"), salt, iters).hex()


def b64e(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode("ascii")


def b64d(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def sign(payload: str, key: bytes) -> str:
    sig = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    return f"{payload}.{sig}"


def sig_valid(token: str, key: bytes) -> str | None:
    """Return payload if signature valid else None."""
    try:
        payload, sig = token.rsplit(".", 1)
    except ValueError:
        return None
    expect = hmac.new(key, payload.encode("utf-8"), hashlib.sha256).hexdigest()
    if not hmac.compare_digest(expect, sig):
        return None
    return payload


def gen_totp_secret() -> str:
    return base64.b32encode(os.urandom(20)).decode("ascii")


def totp_now(secret_b32: str, step: int = 30, digits: int = 6, offset: int = 0) -> str:
    key = base64.b32decode(secret_b32.upper())
    counter = int(time.time()) // step + offset
    mac = hmac.new(key, counter.to_bytes(8, "big"), hashlib.sha1).digest()
    o = mac[-1] & 0x0F
    code = (int.from_bytes(mac[o:o + 4], "big") & 0x7FFFFFFF) % (10 ** digits)
    return f"{code:0{digits}d}"


def totp_verify(secret_b32: str, code: str, window: int = 1) -> bool:
    if not re.fullmatch(r"\d{6}", code or ""):
        return False
    return any(totp_now(secret_b32, offset=off) == code for off in range(-window, window + 1))