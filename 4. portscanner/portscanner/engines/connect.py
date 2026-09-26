"""TCP Connect engine (architecture.md §5.1) — unprivileged, accurate, logged.

Timeout-mode connect with WSA-aware classification. On stock Windows/POSIX a
refused port returns ECONNREFUSED (10061/111); some hardened stacks/firewalls
suppress RSTs, in which case the port reports filtered — the honest result
(silence is indistinguishable from drop, architecture.md §5.1).
"""
from __future__ import annotations

import errno as errno_mod
import socket
import time

from ..models import Evidence, PortState, ProbeJob
from .base import make_result

# Windows WSA codes (socket layer surfaces these instead of POSIX errno)
WSAECONNREFUSED, WSAETIMEDOUT = 10061, 10060
WSAEHOSTUNREACH, WSAENETUNREACH = 10065, 10051
WSAEHOSTDOWN, WSAENETDOWN, WSAEACCES = 10064, 10050, 10013

CLOSED = {errno_mod.ECONNREFUSED, WSAECONNREFUSED}
UNREACHABLE = {errno_mod.ENETUNREACH, errno_mod.EHOSTUNREACH,
               errno_mod.ENETDOWN, errno_mod.EHOSTDOWN,
               WSAENETUNREACH, WSAEHOSTUNREACH, WSAENETDOWN, WSAEHOSTDOWN}


class ConnectEngine:
    name = "connect"

    def probe(self, job: ProbeJob, timeout_s: float):
        start = time.monotonic()
        elapsed = lambda: (time.monotonic() - start) * 1000  # noqa: E731
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout_s)
        try:
            try:
                sock.connect((job.target.ip, job.port))
            except ConnectionRefusedError as exc:
                return make_result(job, self.name, PortState.CLOSED, elapsed(),
                                   Evidence(errno=exc.errno or WSAECONNREFUSED,
                                            detail="RST/ACK (closed)"))
            except (TimeoutError, socket.timeout):
                # dropped or RST-suppressed → cannot assert closed (§5.1 honesty)
                return make_result(job, self.name, PortState.FILTERED, elapsed(),
                                   Evidence(detail="timeout (dropped/RST-suppressed)"))
            except OSError as exc:
                rc = exc.errno or 0
                if rc in CLOSED:
                    return make_result(job, self.name, PortState.CLOSED, elapsed(),
                                       Evidence(errno=rc, detail="RST/ACK (closed)"))
                if rc in UNREACHABLE:
                    return make_result(job, self.name, PortState.UNREACHABLE,
                                       elapsed(), Evidence(errno=rc, detail=_explain(rc)))
                return make_result(job, self.name, PortState.FILTERED, elapsed(),
                                   Evidence(errno=rc, detail=_explain(rc)))
            return make_result(job, self.name, PortState.OPEN, elapsed(),
                               Evidence(detail="connected"))
        except OSError as exc:  # defensive: socket-level failure
            return make_result(job, self.name, PortState.UNREACHABLE, elapsed(),
                               Evidence(errno=exc.errno or 0, detail=str(exc)))
        finally:
            try:
                sock.close()  # RST-style teardown; keeps host logs small (§5.1)
            except OSError:
                pass


def _explain(rc: int) -> str:
    return {
        errno_mod.ECONNREFUSED: "RST/ACK received (closed)",
        WSAECONNREFUSED: "RST/ACK received (closed)",
        errno_mod.ENETUNREACH: "network unreachable",
        errno_mod.EHOSTUNREACH: "host unreachable",
        errno_mod.ETIMEDOUT: "timed out (dropped)",
        WSAETIMEDOUT: "timed out (dropped)",
        errno_mod.EACCES: "blocked locally (firewall/AV)",
        WSAEACCES: "blocked locally (firewall/AV)",
    }.get(rc, f"connect error rc={rc}")
