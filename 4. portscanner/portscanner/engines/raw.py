"""Raw-socket engines (architecture.md §5.2, §5.4) — require admin/root + scapy.

Privilege isolation: this module is the ONLY place that touches raw sockets.
Import fails cleanly without scapy; engines are privilege-checked at probe time.
"""
from __future__ import annotations

import threading
import time

from ..models import Evidence, PortState, ProbeJob
from .base import make_result

try:
    from scapy.all import IP, TCP, ICMP, sr1, conf  # type: ignore
    conf.verb = 0
    HAS_SCAPY = True
except ImportError:  # pragma: no cover
    HAS_SCAPY = False

_sport_seq = threading.local()


def _is_admin() -> bool:
    import os
    if os.name == "nt":
        try:
            import ctypes
            return bool(ctypes.windll.shell32.IsUserAnAdmin())  # type: ignore[attr-defined]
        except Exception:  # noqa: BLE001
            return False
    return os.geteuid() == 0


class _RawTcpEngine:
    name = "raw"
    flags: int = 0x02  # SYN by default

    def probe(self, job: ProbeJob, timeout_s: float):
        if not HAS_SCAPY:
            return make_result(job, self.name, PortState.UNREACHABLE, 0,
                               Evidence(detail="scapy not installed"))
        if not _is_admin():
            return make_result(job, self.name, PortState.UNREACHABLE, 0,
                               Evidence(detail="requires admin/root privileges"))
        start = time.monotonic()
        sport = 40000 + (job.port * 7 + job.attempt) % 20000
        pkt = IP(dst=job.target.ip) / TCP(
            sport=sport, dport=job.port, flags=self.flags,
            seq=int(time.time() * 1000) & 0x7FFFFFFF,  # random-ish ISN (§5.2)
        )
        try:
            resp = sr1(pkt, timeout=timeout_s, verbose=0)
            rtt_ms = (time.monotonic() - start) * 1000
        except Exception as exc:  # noqa: BLE001 — scapy raises on missing Npcap
            return make_result(job, self.name, PortState.UNREACHABLE,
                               (time.monotonic() - start) * 1000,
                               Evidence(detail=f"raw socket error: {exc}"))

        if resp is None:
            return make_result(job, self.name, PortState.OPEN_FILTERED, rtt_ms,
                               Evidence(detail="no response (silence)"))
        if resp.haslayer(ICMP) and int(resp[ICMP].type) == 3:
            code = int(resp[ICMP].code)
            state = PortState.CLOSED if code == 3 else PortState.FILTERED
            return make_result(job, self.name, state, rtt_ms,
                               Evidence(icmp_type=3, icmp_code=code))
        tcp = resp.getlayer("TCP")
        if tcp is None:
            return make_result(job, self.name, PortState.FILTERED, rtt_ms,
                               Evidence(detail="non-TCP response"))
        f = int(tcp.flags)
        if f & 0x12 == 0x12:  # SYN+ACK → open; we send RST (never complete handshake)
            from scapy.all import IP as _IP, TCP as _TCP
            sr1(_IP(dst=job.target.ip) / _TCP(sport=sport, dport=job.port,
                                             flags="R", seq=pkt[TCP].seq + 1),
                timeout=0.2, verbose=0)
            return make_result(job, self.name, PortState.OPEN, rtt_ms,
                               Evidence(detail="SYN/ACK"))
        if f & 0x04:  # RST → closed
            return make_result(job, self.name, PortState.CLOSED, rtt_ms,
                               Evidence(detail="RST"))
        return make_result(job, self.name, PortState.FILTERED, rtt_ms,
                           Evidence(detail=f"unexpected flags 0x{f:02x}"))


class SynEngine(_RawTcpEngine):
    name = "syn"
    flags = 0x02  # SYN


class FinEngine(_RawTcpEngine):
    name = "fin"
    flags = 0x01  # FIN — silent open, RST means closed (§5.4)


class NullEngine(_RawTcpEngine):
    name = "null"
    flags = 0x00  # no flags


class XmasEngine(_RawTcpEngine):
    name = "xmas"
    flags = 0x29  # FIN|PSH|URG
