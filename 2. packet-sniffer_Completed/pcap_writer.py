"""Minimal libpcap-format writer — lets Wireshark/tcpdump open the capture.

Classic PCAP global header (microsecond variant):
    magic 0xa1b2c3d4 | ver 2.4 | thiszone 0 | sigfigs 0 | snaplen | linktype
Packet record: ts_sec | ts_usec | incl_len | orig_len | data

Frames must be full L2 Ethernet frames (LINKTYPE_ETHERNET = 1), which the
capture engine guarantees by prepending a synthetic Ethernet header on
Windows raw-IP sockets.
"""
from __future__ import annotations

import struct
import threading
from typing import Optional

LINKTYPE_ETHERNET = 1
PCAP_MAGIC_US = 0xA1B2C3D4          # microsecond-resolution magic
SNAPLEN = 65535
MAX_FILE_BYTES = 500 * 1024 * 1024  # rotate at 500 MB (disk-fill guard)


class PcapWriter:
    """Thread-safe incremental PCAP writer with size-based rotation."""

    def __init__(self, path: str):
        self.path = path
        self._fh = open(path, "wb")
        self._fh.write(struct.pack("<IHHiIII",
                                   PCAP_MAGIC_US, 2, 4, 0, 0,
                                   SNAPLEN, LINKTYPE_ETHERNET))
        self._bytes_written = 24
        self._packets = 0
        self._lock = threading.Lock()

    def write_packet(self, ts: float, frame: bytes):
        """Append one Ethernet frame. Truncated to SNAPLEN."""
        if not frame:
            return
        frame = frame[:SNAPLEN]
        sec = int(ts)
        usec = int((ts - sec) * 1_000_000) % 1_000_000
        rec = struct.pack("<IIII", sec, usec, len(frame), len(frame)) + frame
        with self._lock:
            self._fh.write(rec)
            self._bytes_written += len(rec) + 16
            self._packets += 1
            if self._bytes_written >= MAX_FILE_BYTES:
                self._rotate()

    def _rotate(self):
        self.close()
        base, _, ext = self.path.rpartition(".")
        self.path = f"{base or self.path}.1{('.' + ext) if ext else ''}"
        self.__init__(self.path)  # re-open fresh file with global header

    @property
    def packet_count(self) -> int:
        return self._packets

    def close(self):
        with self._lock:
            try:
                self._fh.flush()
                self._fh.close()
            except (OSError, ValueError):
                pass

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
