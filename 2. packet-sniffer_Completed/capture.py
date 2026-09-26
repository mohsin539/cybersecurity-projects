"""Capture engine: raw-socket acquisition with bounded-queue producer/consumer.

Windows : AF_INET/SOCK_RAW + IP_HDRINCL + SIO_RCVALL (IP-only, no ARP, no loopback)
Linux   : AF_PACKET/SOCK_RAW + ETH_P_ALL (full L2 incl. ARP, promisc optional)
macOS   : AF_INET/SOCK_RAW (BSD IP-only, best effort)

The engine never parses on the capture thread — it only enqueues
(ts, raw_bytes) tuples so that a parser hiccup can never stall the kernel
socket buffer (backpressure safety).
"""
from __future__ import annotations

import ctypes
import platform
import queue
import socket
import struct
import threading
import time
from dataclasses import dataclass, field
from typing import Callable, Optional

from parsers import Packet, PacketParseError, parse_packet

IS_WINDOWS = platform.system() == "Windows"
IS_LINUX = platform.system() == "Linux"
IS_MACOS = platform.system() == "Darwin"

SIO_RCVALL = 0x98000001
RCVALL_ON = 1
ETH_P_ALL = 0x0003

# Synthetic Ethernet header builder for Windows raw-IP sockets (needed so
# downstream parser + PCAP export see a uniform L2 frame).
_SYNTH_ETH_TEMPLATE = bytes.fromhex("ffffffffffff")  # + src6 + type2 appended


def _synth_eth(src_mac: bytes, ethertype: int) -> bytes:
    return (_SYNTH_ETH_TEMPLATE + src_mac
            + struct.pack("!H", ethertype))


@dataclass
class CaptureStats:
    captured: int = 0
    parsed: int = 0
    parse_errors: int = 0
    dropped: int = 0          # queue overflow drops
    socket_errors: int = 0
    started_at: float = 0.0
    last_pps: float = 0.0
    pps_history: list = field(default_factory=list)   # last 60 one-second buckets
    _lock: threading.Lock = field(default_factory=threading.Lock, repr=False)

    def snapshot(self) -> dict:
        with self._lock:
            return {
                "captured": self.captured, "parsed": self.parsed,
                "parse_errors": self.parse_errors, "dropped": self.dropped,
                "socket_errors": self.socket_errors,
                "pps": self.last_pps,
                "elapsed": time.time() - self.started_at if self.started_at else 0.0,
            }


@dataclass
class _IFace:
    name: str
    ip: str


def list_interfaces() -> list[_IFace]:
    """Enumerate local IPv4 interfaces without external deps.

    Uses a UDP 'connect' trick (no packets sent) to discover the primary
    outbound IP, then enumerates all host addresses via ``getaddrinfo`` on
    the hostname plus common Windows host aliases.
    """
    out: dict[str, _IFace] = {}
    host = socket.gethostname()
    candidates: set[str] = set()
    try:
        candidates.add(socket.gethostbyname(host))
    except OSError:
        pass
    for ai in socket.getaddrinfo(host, None, socket.AF_INET):
        candidates.add(ai[4][0])
    # UDP-connect trick for the default route interface
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))          # never sent (UDP connect)
        candidates.add(s.getsockname()[0])
    except OSError:
        pass
    finally:
        s.close()

    for ip in sorted(c for c in candidates if c and not c.startswith("169.254.")):
        if ip.startswith("127."):
            continue
        out.setdefault(ip, _IFace(name=f"{host} ({ip})", ip=ip))
    return list(out.values())


class CaptureEngine:
    """Raw-socket capture worker. One engine = one bound interface."""

    def __init__(self, host_ip: str, raw_queue: "queue.Queue[tuple]",
                 stats: CaptureStats, on_error: Optional[Callable[[str], None]] = None):
        self.host_ip = host_ip
        self.q = raw_queue
        self.stats = stats
        self.on_error = on_error
        self._sock: Optional[socket.socket] = None
        self._stop = threading.Event()
        self._thread: Optional[threading.Thread] = None
        self._pps_tick = time.time()
        self._pps_count = 0

    # -- lifecycle --------------------------------------------------------
    def start(self) -> bool:
        try:
            self._sock = self._open_socket()
        except PermissionError:
            msg = ("Administrator/root privileges required for raw sockets. "
                   + ("Right-click the terminal/IDE → 'Run as administrator'."
                      if IS_WINDOWS else
                      "Run with: sudo python3 packet_sniffer_gui.py "
                      "(or grant CAP_NET_RAW: setcap cap_net_raw+ep $(readlink -f $(which python3)))"))
            if self.on_error:
                self.on_error(msg)
            return False
        except OSError as e:
            if self.on_error:
                self.on_error(f"Socket open failed: {e}")
            return False
        self._stop.clear()
        self._thread = threading.Thread(
            target=self._loop, name="CaptureEngine", daemon=True)
        self._thread.start()
        self.stats.started_at = time.time()
        return True

    def stop(self, timeout: float = 2.0):
        self._stop.set()
        if self._sock:
            try:
                self._sock.close()
            except OSError:
                pass
        if self._thread and self._thread.is_alive():
            self._thread.join(timeout=timeout)

    # -- sockets ----------------------------------------------------------
    def _open_socket(self) -> socket.socket:
        if IS_WINDOWS:
            s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
            s.bind((self.host_ip, 0))
            s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
            # SIO_RCVALL via socket.ioctl (exists on Windows Python)
            s.ioctl(SIO_RCVALL, RCVALL_ON)
            s.settimeout(0.5)
            # Windows raw-IP sockets deliver IP-only frames; stash the local
            # MAC so _loop can prepend a synthetic Ethernet header (uniform
            # L2 for the parser + valid PCAP export).
            import uuid
            mac = uuid.getnode()
            self._src_mac = mac.to_bytes(6, "big") if mac else b"\x00" * 6
            return s
        if IS_LINUX:
            s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW,
                              socket.ntohs(ETH_P_ALL))
            s.bind((self._pick_linux_ifname(), 0))
            s.settimeout(0.5)
            try:  # best-effort promiscuous mode
                import fcntl
                ifname = self._pick_linux_ifname()
                # SIOCGIFFLAGS=0x8913 / SIOCSIFFLAGS=0x8914
                ifr = struct.pack("16sH", ifname.encode(), 0)
                flags = struct.unpack("16sH", fcntl.ioctl(s.fileno(), 0x8913, ifr))[1]
                flags |= 0x100  # IFF_PROMISC
                fcntl.ioctl(s.fileno(), 0x8914,
                            struct.pack("16sH", ifname.encode(), flags))
            except Exception:  # noqa: BLE001 — promisc is optional
                pass
            return s
        # macOS / other: IP-only raw socket (BSD semantics)
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_IP)
        s.bind((self.host_ip, 0))
        s.settimeout(0.5)
        return s

    def _pick_linux_ifname(self) -> str:
        """Map the chosen IP to an interface name on Linux."""
        try:
            import fcntl
            import array
            # SIOCGIFCONF
            buf = array.array("B", b"\0" * 4096)
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            addr, ln = buf.buffer_info()
            result = fcntl.ioctl(s.fileno(), 0x8912,
                                 struct.pack("iL", 4096, addr))
            s.close()
            size = struct.unpack("iL", result)[0]
            data = buf.tobytes()[:size]
            for i in range(0, size, 40):
                ifr_name = data[i:i + 16].split(b"\0")[0].decode()
                sin = data[i + 20:i + 24]
                if sin == socket.inet_aton(self.host_ip):
                    return ifr_name
        except Exception:  # noqa: BLE001
            pass
        return "eth0"

    # -- capture loop -------------------------------------------------------
    def _loop(self):
        pps_window_start = time.time()
        pps_window_count = 0
        synth = _synth_eth(getattr(self, "_src_mac", b"\x00" * 6),
                           0x0800) if IS_WINDOWS else b""
        while not self._stop.is_set():
            try:
                data, _addr = self._sock.recvfrom(65535)
                if synth:
                    data = synth + data       # Windows: IP-only → uniform L2
                now = time.time()
                self.stats.captured += 1
                self._pps_count += 1
                if now - self._pps_tick >= 1.0:
                    self.stats.last_pps = self._pps_count / (now - self._pps_tick)
                    self.stats.pps_history.append(self.stats.last_pps)
                    if len(self.stats.pps_history) > 60:
                        del self.stats.pps_history[:-60]
                    self._pps_tick = now
                    self._pps_count = 0
                try:
                    self.q.put_nowait((now, data))
                except queue.Full:
                    self.stats.dropped += 1
            except socket.timeout:
                continue
            except OSError:
                # ECONNABORTED / EBADF etc. during shutdown — normal stop path
                if self._stop.is_set():
                    break
                self.stats.socket_errors += 1
                time.sleep(0.05)

    def enqueue_synthetic(self, raw: bytes, ts: Optional[float] = None):
        """Test hook: inject a frame as if captured (used by unit tests/demo)."""
        self.q.put((ts or time.time(), raw))


def make_processor(raw_queue, stats: CaptureStats,
                   on_packet: Callable[[Packet], None],
                   num_workers: int = 1):
    """Spawn consumer thread(s): dequeue → parse → invoke callback.

    Returns a (threads, stop_event) tuple; caller joins on stop.
    """
    stop = threading.Event()

    def worker():
        while not stop.is_set():
            try:
                ts, data = raw_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            try:
                pkt = parse_packet(data, ts)
                stats.parsed += 1
                on_packet(pkt)
            except PacketParseError as e:
                stats.parse_errors += 1
            except Exception:  # noqa: BLE001 — never let parser kill consumer
                stats.parse_errors += 1

    threads = []
    for i in range(num_workers):
        t = threading.Thread(target=worker, name=f"PacketProcessor-{i}",
                             daemon=True)
        t.start()
        threads.append(t)
    return threads, stop


def processor_stop(stop_event: threading.Event):
    stop_event.set()
