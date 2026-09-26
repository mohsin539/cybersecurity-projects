"""UDP engine (architecture.md §5.3).

UDP replies → open; ICMP port unreachable → closed (Windows may not surface
per-port ICMP to userspace, so silence maps to open|filtered — honest result).
"""
from __future__ import annotations

import socket
import time

from ..models import Evidence, PortState, ProbeJob
from .base import make_result

# Small protocol-aware payloads to coax replies from silent services (§5.3)
_PAYLOADS: dict[int, bytes] = {
    53: bytes.fromhex("abcd01000001000000000000") + b"\x07version\x04bind\x00\x00\x01\x00\x01",
    123: b"\x1b" + 47 * b"\x00",                       # NTP
    161: bytes.fromhex("3082002602010004067075626c6963a08200170202040d020100020100300f300d06082b06010201010100") ,  # SNMP get public
    137: bytes.fromhex("a848000000010000000000000020434b41414141414141414141414141414141414141414141414141414141414100002100"),  # NetBIOS
    5353: bytes.fromhex("000000000001000000000000") + b"\x09_services\x07_dnsudp\x04local\x00\x00\x0c\x00\x01",
    111: bytes.fromhex("800002800000000200000000000000000000000000000002"),  # rpcbind
}


class UdpEngine:
    name = "udp"

    def probe(self, job: ProbeJob, timeout_s: float):
        start = time.monotonic()
        payload = _PAYLOADS.get(job.port, b"portscanner-probe\x00")
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout_s)
        try:
            sock.sendto(payload, (job.target.ip, job.port))
            data, _ = sock.recvfrom(2048)
            rtt_ms = (time.monotonic() - start) * 1000
            return make_result(job, self.name, PortState.OPEN, rtt_ms,
                               Evidence(detail=f"udp reply, {len(data)}B"))
        except socket.timeout:
            rtt_ms = (time.monotonic() - start) * 1000
            # Silence is ambiguous on UDP (§5.3): honest state is open|filtered.
            return make_result(job, self.name, PortState.OPEN_FILTERED, rtt_ms,
                               Evidence(detail="no reply after retries"))
        except ConnectionRefusedError:
            # ICMP port-unreachable surfaced as ECONNREFUSED on Windows/Linux
            return make_result(job, self.name, PortState.CLOSED,
                               (time.monotonic() - start) * 1000,
                               Evidence(icmp_type=3, icmp_code=3, detail="ICMP port unreachable"))
        except OSError as exc:
            return make_result(job, self.name, PortState.FILTERED,
                               (time.monotonic() - start) * 1000,
                               Evidence(errno=exc.errno or 0, detail=str(exc)))
        finally:
            try:
                sock.close()
            except OSError:
                pass
