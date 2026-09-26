"""ThreatAnalyzer — blue-team heuristics over the live packet stream.

Detections:
  * Port scan (TCP SYN sweep / NULL-FIN-Xmas variants)   — sliding 30 s window
  * Cleartext credentials (FTP/TELNET/HTTP-basic style)  — payload regex
  * ICMP tunneling (oversized echo payload)              — icmpsh/ptunnel hint
  * SYN flood (per-source SYN rate)                      — volumetric
  * ARP spoofing (duplicate IP ↔ MAC bindings)           — L2 MITM indicator
  * Suspicious service exposure (metasploit/redis/VNC…)  — banner-free flag

Emits ThreatEvent objects consumed by GUI (Threat tab) and Storage (audit).
"""
from __future__ import annotations

import re
import time
from collections import defaultdict, deque
from dataclasses import dataclass
from typing import Optional

from parsers import Packet

@dataclass
class ThreatEvent:
    ts: float
    kind: str          # PORTSCAN | CREDS | ICMP_TUNNEL | SYNFLOOD | ARP_SPOOF | SUSPICIOUS_SVC
    src_ip: str
    description: str
    severity: str      # low | medium | high | critical


_WINDOW = 30.0

_CRED_PATTERNS = [
    re.compile(rb"(?i)(user(name)?|login)\s*[=:]\s*\S{3,40}"),
    re.compile(rb"(?i)(pass(word)?|pwd)\s*[=:]\s*\S{3,40}"),
    re.compile(rb"(?i)^USER\s+\S+"),          # FTP
    re.compile(rb"(?i)^PASS\s+\S+"),          # FTP
    re.compile(rb"(?i)Authorization:\s*Basic\s+[A-Za-z0-9+/=]{8,}"),
]

# Ports that should basically never be open on a workstation
_SUSPICIOUS_PORTS = {4444, 5555, 31337, 12345, 6666, 6667, 9999,
                     6379, 5900, 5901, 3389}


class ThreatAnalyzer:
    def __init__(self, emit: Optional[callable] = None):
        """
        emit: callable(ThreatEvent) — GUI/storage sink.
        """
        self.emit = emit or (lambda e: None)

        # sliding windows per source IP
        self._syn_ports: dict[str, dict] = defaultdict(
            lambda: {"t": deque(), "ports": set(), "flag_set": set()})
        self._synflood: dict[str, deque] = defaultdict(lambda: deque())
        self._arp_table: dict[str, str] = {}      # ip -> mac
        self._seen_svc: set[tuple] = set()        # (src,dst,port) dedup
        self._events: deque[ThreatEvent] = deque(maxlen=1000)
        self._last_emit: dict[tuple, float] = {}  # (kind,src) -> ts cooldown

    # ------------------------------------------------------------------
    def analyze(self, p: Packet):
        try:
            if p.protocol == "TCP":
                self._tcp(p)
            elif p.protocol == "UDP":
                self._udp(p)
            elif p.protocol == "ICMP":
                self._icmp(p)
            elif p.protocol == "ARP":
                self._arp(p)
        except Exception:   # noqa: BLE001 — analysis must never kill pipeline
            pass

    # ------------------------------------------------------------------
    def _tcp(self, p: Packet):
        now = p.timestamp
        payload = bytes.fromhex(p.payload_hex) if p.payload_hex else b""

        # 1) Port scan detection (SYN or stealth-flag probes)
        is_syn = "SYN" in p.flags and "ACK" not in p.flags
        is_stealth = (p.flags in ("[FIN]", "[NULL]", "[FIN, PSH, URG]")
                      or p.flags == "[]")
        if is_syn or (is_stealth and p.dst_port > 0):
            st = self._syn_ports[p.src_ip]
            st["t"].append(now)
            st["ports"].add(p.dst_port)
            while st["t"] and now - st["t"][0] > _WINDOW:
                st["t"].popleft()
            if len(st["ports"]) >= 25 and now - st["t"][0] <= _WINDOW:
                self._emit_once("PORTSCAN", p.src_ip,
                                f"Port sweep: {len(st['ports'])} unique dst "
                                f"ports in ≤{_WINDOW:.0f}s (last → {p.dst_port})",
                                "high")
                st["ports"].clear()
            elif len(st["ports"]) >= 10 and now - st["t"][0] <= _WINDOW:
                self._emit_once("PORTSCAN", p.src_ip,
                                f"Slow scan pattern: {len(st['ports'])} ports "
                                f"in window (last → {p.dst_port})", "medium")

        # 2) SYN flood: > 200 SYN/s sustained from one host
        if is_syn:
            dq = self._synflood[p.src_ip]
            dq.append(now)
            while dq and now - dq[0] > 1.0:
                dq.popleft()
            if len(dq) > 200:
                self._emit_once("SYNFLOOD", p.src_ip,
                                f"{len(dq)} SYN/s to {p.dst_ip} — possible "
                                f"SYN flood / DoS", "high")

        # 3) Cleartext credentials
        for rx in _CRED_PATTERNS:
            m = rx.search(payload)
            if m:
                snippet = m.group(0)[:60].decode("latin-1", "replace")
                self._emit_once(
                    "CREDS", f"{p.src_ip}:{p.src_port}",
                    f"Cleartext credential pattern → {p.dst_ip}:{p.dst_port} "
                    f"“{snippet}”", "high")
                break

        # 4) Suspicious destination service
        if p.dst_port in _SUSPICIOUS_PORTS:
            key = (p.src_ip, p.dst_ip, p.dst_port)
            if key not in self._seen_svc:
                self._seen_svc.add(key)
                self._emit_once(
                    "SUSPICIOUS_SVC", p.src_ip,
                    f"Connection to well-known risky port {p.dst_port} "
                    f"(metasploit/vnc/redis/rdp range) on {p.dst_ip}",
                    "medium")

    # ------------------------------------------------------------------
    def _udp(self, p: Packet):
        payload = bytes.fromhex(p.payload_hex) if p.payload_hex else b""
        for rx in _CRED_PATTERNS:
            m = rx.search(payload)
            if m:
                self._emit_once("CREDS", f"{p.src_ip}:{p.src_port}",
                                f"Cleartext credential in UDP → "
                                f"{p.dst_ip}:{p.dst_port}", "medium")
                break

    # ------------------------------------------------------------------
    def _icmp(self, p: Packet):
        # Oversized echo payload → icmpsh / ptunnel / data exfil over ICMP
        payload_len = len(bytes.fromhex(p.payload_hex)) if p.payload_hex else 0
        if p.icmp_type == 8 and payload_len > 32:
            self._emit_once(
                "ICMP_TUNNEL", p.src_ip,
                f"ICMP Echo with {payload_len}B payload → {p.dst_ip} "
                f"(possible ICMP tunnel/exfil)", "medium")

    # ------------------------------------------------------------------
    def _arp(self, p: Packet):
        # ARP replies announcing an IP we've already bound to another MAC
        if "is-at" in p.info:
            ip, mac = p.src_ip, p.src_mac
            prev = self._arp_table.get(ip)
            if prev and prev != mac:
                self._emit_once("ARP_SPOOF", p.src_ip,
                                f"IP {ip} claimed by {mac} (was {prev}) — "
                                f"possible ARP spoofing/MITM", "critical")
            self._arp_table[ip] = mac

    # ------------------------------------------------------------------
    def _emit_once(self, kind: str, src: str, desc: str, sev: str,
                   cooldown: float = 10.0):
        """Emit with per-(kind,source,severity) suppression window so a
        continuing event doesn't flood the GUI/DB, while severity escalation
        (medium → high) still gets through."""
        key = (kind, src, sev)
        now = time.time()
        if now - self._last_emit.get(key, 0.0) < cooldown:
            return
        self._last_emit[key] = now
        ev = ThreatEvent(now, kind, src, desc, sev)
        self._events.append(ev)
        self.emit(ev)

    def recent(self, n: int = 100) -> list[ThreatEvent]:
        return list(self._events)[-n:]

    def counts_by_kind(self) -> dict[str, int]:
        c: dict[str, int] = defaultdict(int)
        for e in self._events:
            c[e.kind] += 1
        return dict(c)
