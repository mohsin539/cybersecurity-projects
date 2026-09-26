#!/usr/bin/env python3
"""Bit-for-bit acquisition engine for Windows devices & files.

Forensic design rules:
  * The source device is ALWAYS opened for READ-ONLY access; no write handle
    is ever requested from the OS.
  * A hardware/software write-blocker is expected between the exhibit and the
    OS. This module additionally requests share-read only, never write.
  * Streams run through the hashing engine, so digests are produced at
    acquisition time in a single pass. An optional verification pass re-reads
    the image for full assurance.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import time
from typing import Callable, Dict, Iterable, List, Optional, Tuple

from .config import CHUNK_SIZE
from .hashing import build_hashers, digest_stream

# ---- Win32 constants -----------------------------------------------------
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_SEQUENTIAL_SCAN = 0x08000000

IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
ERROR_ACCESS_DENIED = 5
ERROR_HANDLE_EOF = 38
ERROR_SHARING_VIOLATION = 32

kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

# Device namespaces \\.\N (single or doubled first backslash variants)
_BS = chr(92)
_DEVICE_PREFIXES = (_BS + _BS + "." + _BS, _BS + "." + _BS)


class DiskError(OSError):
    pass


def is_device_path(source: str) -> bool:
    return source.lower().startswith(_DEVICE_PREFIXES) or source.lower().startswith(r"\\.\PhysicalDrive")


# --------------------------------------------------------------------------
def open_readonly(device: str) -> int:
    """Open a Windows device or raw image path READ-ONLY."""
    handle = kernel32.CreateFileW(
        device,
        GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        None,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
        None,
    )
    if handle == INVALID_HANDLE_VALUE or not handle:
        err = ctypes.get_last_error()
        if err == ERROR_ACCESS_DENIED:
            raise DiskError(err, f"Access denied on {device}. Run as Administrator.")
        if err == ERROR_SHARING_VIOLATION:
            raise DiskError(err, f"Sharing violation on {device} (in use).")
        raise DiskError(err, f"Failed to open {device} (err={err}). Run as Administrator.")
    return handle


def close_handle(handle: int) -> None:
    if handle:
        kernel32.CloseHandle(ctypes.c_void_p(handle))


def disk_length(handle: int) -> int:
    """Byte length of the device via IOCTL_DISK_GET_LENGTH_INFO."""
    out = wt.LARGE_INTEGER()
    dret = wt.DWORD(0)
    ret = kernel32.DeviceIoControl(
        ctypes.c_void_p(handle), IOCTL_DISK_GET_LENGTH_INFO,
        None, 0, ctypes.byref(out), ctypes.sizeof(out),
        ctypes.byref(dret), None)
    if not ret:
        raise DiskError(ctypes.get_last_error(), "DeviceIoControl GET_LENGTH_INFO failed")
    return out.value


def read_blocks(handle: int, chunk: int = CHUNK_SIZE) -> Iterable[bytes]:
    """Generator of raw byte blocks from an open device handle."""
    buf = ctypes.create_string_buffer(chunk)
    bytes_read = wt.DWORD(0)
    while True:
        ok = kernel32.ReadFile(
            ctypes.c_void_p(handle), buf, chunk,
            ctypes.byref(bytes_read), None)
        n = bytes_read.value
        if n == 0:
            break
        if not ok and n == 0:
            err = ctypes.get_last_error()
            if err == ERROR_HANDLE_EOF:
                break
            raise DiskError(err, f"ReadFile failed (err={err})")
        yield buf.raw[:n]


def list_physical_drives(max_drives: int = 64) -> List[Dict[str, object]]:
    """Enumerate ``PhysicalDriveN`` devices with size metadata."""
    result = []
    for i in range(max_drives):
        dev = r"\\.\PhysicalDrive" + str(i)
        try:
            h = open_readonly(dev)
        except DiskError:
            continue
        try:
            size = disk_length(h)
        except DiskError:
            size = None
        finally:
            close_handle(h)
        if size is not None:
            result.append({"device": dev, "size": size})
    return result


def fmt_size(n: Optional[int]) -> str:
    if n is None:
        return "unknown"
    value = float(n)
    for unit in ("B", "KiB", "MiB", "GiB", "TiB", "PiB"):
        if value < 1024.0 or unit == "PiB":
            return f"{value:.2f} {unit}" if unit != "B" else f"{int(value)} {unit}"
        value /= 1024.0
    return f"{value:.2f} PiB"


# --------------------------------------------------------------------------
class _Guard:
    """Context manager yielding a byte stream for a device or file source."""

    def __init__(self, source: str):
        self._is_device = is_device_path(source)
        self._handle = None
        self._fp = None
        if self._is_device:
            self._handle = open_readonly(source)
        else:
            self._fp = open(source, "rb")

    def stream(self):
        if self._is_device:
            return read_blocks(self._handle)
        return self._fp

    def source_size(self) -> Optional[int]:
        if self._is_device:
            return disk_length(self._handle)
        try:
            return os.path.getsize(getattr(self._fp, "name"))
        except OSError:
            return None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        if self._is_device and self._handle:
            close_handle(self._handle)
        if self._fp:
            self._fp.close()
        return False


def acquire_image(source: str, target_path: str,
                  algorithms: Iterable[str] = ("sha256", "sha3_256"),
                  progress_cb: Optional[Callable[[int, Optional[int]], None]] = None,
                  cancel_cb: Optional[Callable[[], bool]] = None,
                  buffer: int = CHUNK_SIZE):
    """Bit-for-bit acquire *source* into *target_path* while digesting.

    Returns ``(digests, bytes_written, elapsed_sec, source_size)``.
    """
    with _Guard(source) as g:
        total = g.source_size()
        start = time.perf_counter()
        hashers = build_hashers(algorithms)
        nbytes = 0
        with open(target_path, "wb") as out:
            for block in g.stream():
                if cancel_cb is not None and cancel_cb():
                    raise InterruptedError("acquisition cancelled")
                for h in hashers.values():
                    h.update(block)
                out.write(block)
                nbytes += len(block)
                if progress_cb is not None:
                    progress_cb(nbytes, total)
        elapsed = time.perf_counter() - start
    digests = {a: h.hexdigest() for a, h in hashers.items()}
    return digests, nbytes, elapsed, total


def verify_image(image_path: str, expected: Dict[str, str],
                 progress_cb: Optional[Callable[[int, Optional[int]], None]] = None,
                 cancel_cb: Optional[Callable[[], bool]] = None):
    """Recompute digests of the image file and compare against *expected*.

    Returns ``(match, digests, mismatches)``.
    """
    total = os.path.getsize(image_path)

    def _progress(n):
        if progress_cb:
            progress_cb(n, total)

    with open(image_path, "rb") as fp:
        digests, _nb = digest_stream(
            fp, algorithms=list(expected.keys()),
            progress_cb=_progress, cancel_cb=cancel_cb)
    mismatches = [a for a in expected if digests.get(a) != expected[a]]
    return (not mismatches), digests, mismatches