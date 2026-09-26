"""Synthetic traffic generation for the domain-fronting demo.

Produces deterministic, realistic-looking TLS session records (ClientHello
metadata) covering several traffic-obfuscation scenarios so the detection
engine has meaningful material to analyse:

* NORMAL       - honest TLS: SNI == Host == resolved IP owner.
* DOMAIN_FRONT - classic domain fronting: SNI points at a CDN "front" domain
                 while the Host header (and proxied destination) is the real
                 backend. The TLS handshake terminates at the CDN edge.
* SNI_SPOOF    - SNI set to an unrelated high-reputation domain; Host header
                 points at the real destination with no fronting relationship.
* HTTPS_TUNNEL - HTTPS proxy CONNECT-style flows (IP layer only, 443).
* H2_SPOOF     - HTTP/2 :authority / :scheme manipulation after ALPN "h2".
* BENIGN_CDN   - legitimate CDN traffic (SNI == Host == CDN-owned backend).
"""

from __future__ import annotations

import hashlib
import ipaddress
from dataclasses import dataclass, field, asdict
from typing import List, Optional

from src.config import CDN_NETWORKS, TLS_CIPHER_LIST


@dataclass
class AuthRecord:
    """Authentication attribution attached to a traffic record."""

    label: str
    source: str
    ref: str

    def to_dict(self) -> dict:
        return asdict(self)


@dataclass
class TrafficRecord:
    """A single observed TLS session / flow, detection-ready."""

    record_id: str
    scenario: str
    client_ip: str
    src_port: int
    dest_ip: str
    dest_port: int
    sni: str
    host_header: str
    http2_authority: Optional[str]
    js_ver: str  # JA4-style "t13d"
    alpn: List[str]
    cipher_suites: List[str]
    extensions: List[str]
    ttl: int
    asn_org: str
    cdn_flag: bool = False
    cdn_owner: str = ""
    mtu: int = 1500
    observed_ts: str = "2026-09-20T00:00:00Z"

    @property
    def sni_host_mismatch(self) -> bool:
        core = _normalise(self.host_header)
        return _normalise(self.sni) != core

    @property
    def has_authority_spoof(self) -> bool:
        if not self.http2_authority:
            return False
        return _normalise(self.http2_authority) != _normalise(self.host_header)

    def to_dict(self) -> dict:
        return asdict(self)


def _normalise(host: Optional[str]) -> str:
    if not host:
        return ""
    # strip scheme, port and trailing dot
    core = host.split("://")[-1]
    if ":" in core and not core.startswith("["):
        core = core.rsplit(":", 1)[0]
    return core.rstrip(".").lower()


def _in_cdn(cidr: str, ip: str) -> bool:
    try:
        return ipaddress.ip_address(ip) in ipaddress.ip_network(cidr)
    except Exception:
        return False


def _map_cdn(ip: str) -> tuple:
    for owner, nets in CDN_NETWORKS.items():
        if any(_in_cdn(n, ip) for n in nets):
            return True, owner
    return False, ""


def _ja4(record_ip: str, ttl: int, ciphers: List[str], alpn: List[str]) -> str:
    """Simplify JA4-style fingerprint token (t13d + TLS hash bits)."""
    seed = "-".join(ciphers) + "|" + "-".join(alpn)
    h = hashlib.sha256(seed.encode()).hexdigest()[:6]
    return f"t13d{int(ttl) % 9}{h}"


def _authority(host: str) -> str:
    if ":" in host and not host.startswith("["):
        return host.rsplit(":", 1)[0]
    return host


def _record(r: dict) -> TrafficRecord:
    base = dict(r)
    base["cipher_suites"] = list(base.get("cipher_suites", []))
    base["extensions"] = list(base.get("extensions", []))
    base["alpn"] = list(base.get("alpn", []))
    cdn, owner = _map_cdn(base["dest_ip"])
    base["cdn_flag"] = cdn
    base["cdn_owner"] = owner
    base["http2_authority"] = _authority(base["http2_authority"]) if base.get("http2_authority") else None
    base["js_ver"] = _ja4(base["dest_ip"], base["ttl"], base["cipher_suites"], base["alpn"])
    return TrafficRecord(**base)


FRONT_DOMAINS = [  # (host:port front fronts, real backend, cdn ip)
    ("cdn.example-edge.com", "api.evil.example", "172.64.128.1"),
    ("www.cloudflare.com", "panel.hidden-site.example", "104.16.44.34"),
    ("dl.google.com", "private.app.example", "172.217.14.132"),
    ("www.fastly.com", "relay.internal.example", "151.101.0.137"),
]


def build_dataset() -> List[TrafficRecord]:
    """Generate the deterministic demo dataset of TLS sessions."""
    rows: List[TrafficRecord] = []

    # NORMAL baseline
    rows.append(_record({
        "record_id": "rec-0001", "scenario": "NORMAL",
        "client_ip": "203.0.113.10", "src_port": 51234,
        "dest_ip": "104.16.44.34", "dest_port": 443,
        "sni": "www.cloudflare.com", "host_header": "www.cloudflare.com",
        "http2_authority": "www.cloudflare.com",
        "alpn": ["h2", "http/1.1"],
        "cipher_suites": ["1302", "1301", "1303", "c02f"],
        "extensions": ["sni", "alpn", "supported_versions", "sig_algs", "key_share"],
        "ttl": 56, "asn_org": "Cloudflare_Inc", "observed_ts": "2026-09-20T08:01:00Z",
    }))

    # DOMAIN FRONT - the core demo scenario (front domain at CDN edge)
    rows.append(_record({
        "record_id": "rec-0002", "scenario": "DOMAIN_FRONT",
        "client_ip": "198.51.100.7", "src_port": 60123,
        "dest_ip": "172.64.128.1", "dest_port": 443,
        "sni": "cdn.example-edge.com", "host_header": "api.evil.example",
        "http2_authority": "api.evil.example",
        "alpn": ["h2", "http/1.1"],
        "cipher_suites": ["1302", "1301", "1303", "c02f", "cca9"],
        "extensions": ["sni", "alpn", "supported_versions", "sig_algs", "key_share", "psk"],
        "ttl": 52, "asn_org": "Cloudflare_Inc", "observed_ts": "2026-09-20T08:02:12Z",
    }))

    # SNI SPOOF - malicious-CDN-with-unrelated-front
    rows.append(_record({
        "record_id": "rec-0003", "scenario": "SNI_SPOOF",
        "client_ip": "198.51.100.7", "src_port": 60124,
        "dest_ip": "104.16.44.34", "dest_port": 443,
        "sni": "www.cloudflare.com", "host_header": "bgp-relay.internal.example",
        "http2_authority": "bgp-relay.internal.example",
        "alpn": ["h2"],
        "cipher_suites": ["1302", "1301", "1303"],
        "extensions": ["sni", "alpn", "supported_versions", "sig_algs"],
        "ttl": 51, "asn_org": "Cloudflare_Inc", "observed_ts": "2026-09-20T08:02:40Z",
    }))

    # HTTPS TUNNEL (CONNECT, no SNI at tunnel endpoint)
    rows.append(_record({
        "record_id": "rec-0004", "scenario": "HTTPS_TUNNEL",
        "client_ip": "203.0.113.10", "src_port": 53109,
        "dest_ip": "172.64.128.1", "dest_port": 443,
        "sni": "cdn.example-edge.com", "host_header": "cdn.example-edge.com",
        "http2_authority": None,
        "alpn": ["http/1.1"],
        "cipher_suites": ["c02f", "c02b", "c013"],
        "extensions": ["sni", "supported_versions", "sig_algs"],
        "ttl": 54, "asn_org": "Cloudflare_Inc", "observed_ts": "2026-09-20T08:03:05Z",
    }))

    # HTTP/2 :authority spoofing
    rows.append(_record({
        "record_id": "rec-0005", "scenario": "H2_SPOOF",
        "client_ip": "198.51.100.7", "src_port": 60155,
        "dest_ip": "151.101.0.137", "dest_port": 443,
        "sni": "www.fastly.com", "host_header": "www.fastly.com",
        "http2_authority": "py-sessions.internal.example",
        "alpn": ["h2"],
        "cipher_suites": ["1302", "1301", "1303", "c02f"],
        "extensions": ["sni", "alpn", "supported_versions", "sig_algs", "settings"],
        "ttl": 49, "asn_org": "Fastly_Inc", "observed_ts": "2026-09-20T08:03:48Z",
    }))

    # BENIGN CDN (legitimate, no obfuscation)
    rows.append(_record({
        "record_id": "rec-0006", "scenario": "BENIGN_CDN",
        "client_ip": "203.0.113.55", "src_port": 49111,
        "dest_ip": "13.32.0.1", "dest_port": 443,
        "sni": "cdn.medium.example", "host_header": "cdn.medium.example",
        "http2_authority": "cdn.medium.example",
        "alpn": ["h2"],
        "cipher_suites": ["1302", "1301", "1303"],
        "extensions": ["sni", "alpn", "supported_versions", "sig_algs"],
        "ttl": 57, "asn_org": "Amazon_CloudFront", "observed_ts": "2026-09-20T08:04:20Z",
    }))

    # SNI-less (JSON/QUIC era edge) - TLS1.2 without SNI
    rows.append(_record({
        "record_id": "rec-0007", "scenario": "NORMAL",
        "client_ip": "203.0.113.88", "src_port": 50555,
        "dest_ip": "199.232.0.1", "dest_port": 443,
        "sni": "assets.fastlycdn.example", "host_header": "assets.fastlycdn.example",
        "http2_authority": "assets.fastlycdn.example",
        "alpn": ["h2", "http/1.1"],
        "cipher_suites": ["c02f", "c02b", "009c", "009d"],
        "extensions": ["sni", "alpn", "supported_versions", "sig_algs"],
        "ttl": 58, "asn_org": "Fastly_Inc", "observed_ts": "2026-09-20T08:05:02Z",
    }))

    return rows


def detect_cdn_owner(ip: str) -> tuple:
    return _map_cdn(ip)