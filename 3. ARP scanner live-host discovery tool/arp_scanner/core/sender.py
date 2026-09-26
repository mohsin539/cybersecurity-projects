"""High-speed ARP sender using the burst-send / single-listener model
(archetecture.md §9, §11): all who-has requests are fired in quick succession,
then one capture window collects is-at replies. Total wall time ~= timeout
regardless of host count."""

from __future__ import annotations

import threading
import time
from ipaddress import IPv4Address
from typing import Callable

from arp_scanner.core.packets import build_arp_request, parse_arp_reply


class SenderError(RuntimeError):
    """Raised when frames cannot be sent or captured."""


class ArpSender:
    """Send broadcast ARP requests and collect unicast replies on an interface."""

    def __init__(
        self,
        *,
        interface: str,
        src_ip: str,
        src_mac: str,
        timeout: float,
        retries: int,
        pacing: float = 0.0004,
    ) -> None:
        self.interface = interface
        self.src_ip = src_ip
        self.src_mac = src_mac
        self.timeout = timeout
        self.retries = retries
        self.pacing = pacing
        self._sniffer_module = None

    def _open_socket(self):
        from scapy.all import L2Socket  # lazy: heavy import at scan time

        try:
            return L2Socket(iface=self.interface)
        except Exception as exc:  # noqa: BLE001
            raise SenderError(f"cannot open raw L2 socket on '{self.interface}': {exc}") from exc

    def _start_sniffer(self, handler: Callable):
        from scapy.all import AsyncSniffer  # lazy: heavy import at scan time

        return AsyncSniffer(iface=self.interface, prn=handler, store=False, timeout=self.timeout)

    def probe(
        self,
        targets: list[IPv4Address],
        *,
        cancel: threading.Event | None = None,
        on_progress: Callable[[int, int], None] | None = None,
    ) -> dict[str, tuple[str, float]]:
        """Return {ip: (mac, rtt_ms)} for hosts that answered. RTT is the fastest
        observed reply (duplicate/MAC-collision replies are deduped by IP)."""
        total = len(targets)
        replies: dict[str, tuple[str, float]] = {}
        sent_at: dict[str, float] = {}

        def handler(pkt) -> None:  # runs on the sniffer thread
            parsed = parse_arp_reply(pkt)
            if parsed is None:
                return
            ip, mac = parsed
            key = str(ip)
            started = sent_at.get(key)
            if started is None:
                return
            rtt_ms = (time.monotonic() - started) * 1000.0
            previous = replies.get(key)
            if previous is None or rtt_ms < previous[1]:
                replies[key] = (mac, rtt_ms)

        sock = self._open_socket()
        try:
            for _round in range(self.retries + 1):
                pending = [ip for ip in targets if str(ip) not in replies]
                if not pending:
                    break

                sniffer = self._start_sniffer(handler)
                sniffer.start()

                try:
                    for done, ip in enumerate(pending, start=1):
                        if cancel is not None and cancel.is_set():
                            break
                        sent_at[str(ip)] = time.monotonic()
                        sock.send(build_arp_request(self.src_ip, self.src_ip, ip))
                        if self.pacing > 0:
                            time.sleep(self.pacing)
                        if on_progress:
                            on_progress(total - len(pending) + done, total)
                finally:
                    # Wait out the capture window with early-exit when all hosts
                    # have answered.
                    if cancel is None or not cancel.is_set():
                        deadline = time.monotonic() + self.timeout
                        while time.monotonic() < deadline:
                            if all(str(ip) in replies for ip in pending):
                                break
                            if cancel is not None and cancel.is_set():
                                break
                            time.sleep(0.05)
                    sniffer.stop()
                    sniffer.join(timeout=2)
        finally:
            try:
                sock.close()
            except Exception:  # noqa: BLE001
                pass

        return replies