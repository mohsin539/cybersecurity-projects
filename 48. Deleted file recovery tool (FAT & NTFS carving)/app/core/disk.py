"""Read-only backing store abstraction for raw disk access on Windows.

Security posture (OWASP A01/A07 / NIST AC-3 least privilege):
  * The source is opened READ-ONLY with GENERIC_READ only — every handle
    is created with OPEN_EXISTING and mapped to ``GENERIC_READ |
    FILE_SHARE_READ | FILE_SHARE_WRITE`` so the tool can *never* modify
    the forensic source.
  * ``MemoryView`` seals writes: all read paths return immutable bytes.
  * Physical drive enumeration/access requires elevation; we detect
    ERROR_ACCESS_DENIED and surface a friendly, actionable message.
"""

from __future__ import annotations

import ctypes
import ctypes.wintypes as wt
import os
import struct
from dataclasses import dataclass, field
from typing import List, Optional

# ---------------------------------------------------------------------------
# Win32 constants
# ---------------------------------------------------------------------------
GENERIC_READ = 0x80000000
FILE_SHARE_READ = 0x1
FILE_SHARE_WRITE = 0x2
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value

IOCTL_DISK_GET_LENGTH_INFO = 0x0007405C
IOCTL_DISK_GET_DRIVE_GEOMETRY = 0x00070000
IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS = 0x00560000
IOCTL_DISK_GET_DRIVE_LAYOUT_EX = 0x00070050

MAX_PATH = 260
ERROR_ACCESS_DENIED = 5
ERROR_NOT_READY = 21
ERROR_LOCK_VIOLATION = 33
ERROR_INVALID_FUNCTION = 1

_kernel32 = ctypes.WinDLL("kernel32", use_last_error=True)
_advapi32 = ctypes.WinDLL("advapi32", use_last_error=True)


class _SecurityAttributes(ctypes.Structure):
    _fields_ = [
        ("nLength", wt.DWORD),
        ("lpSecurityDescriptor", ctypes.c_void_p),
        ("bInheritHandle", wt.BOOL),
    ]


class _DISK_GEOMETRY(ctypes.Structure):
    _fields_ = [
        ("Cylinders", ctypes.c_ulonglong),
        ("MediaType", wt.DWORD),
        ("TracksPerCylinder", wt.DWORD),
        ("SectorsPerTrack", wt.DWORD),
        ("BytesPerSector", wt.DWORD),
    ]


class _DISK_EXTENT(ctypes.Structure):
    _fields_ = [
        ("DiskNumber", wt.DWORD),
        ("StartingOffset", ctypes.c_ulonglong),
        ("ExtentLength", ctypes.c_ulonglong),
    ]


class _VOLUME_DISK_EXTENTS(ctypes.Structure):
    _fields_ = [
        ("NumberOfDiskExtents", wt.DWORD),
        ("Extents", _DISK_EXTENT * 8),
    ]


class _DRIVE_LAYOUT_INFORMATION_EX(ctypes.Structure):
    _fields_ = [
        ("PartitionStyle", wt.DWORD),
        ("PartitionCount", wt.DWORD),
        ("Unused", wt.DWORD * 3),
        # variable-size tail (partition entries) — we read it back manually.
    ]


_kernel32.CreateFileW.restype = ctypes.c_void_p
_kernel32.CreateFileW.argtypes = [
    ctypes.c_wchar_p, wt.DWORD, wt.DWORD, ctypes.POINTER(_SecurityAttributes),
    wt.DWORD, wt.DWORD, ctypes.c_void_p,
]
_kernel32.ReadFile.argtypes = [
    ctypes.c_void_p, ctypes.c_void_p, wt.DWORD,
    ctypes.POINTER(wt.DWORD), ctypes.c_void_p,
]
_kernel32.CloseHandle.argtypes = [ctypes.c_void_p]
_kernel32.CloseHandle.restype = wt.BOOL
_kernel32.GetLastError.restype = wt.DWORD
_kernel32.DeviceIoControl.argtypes = [
    ctypes.c_void_p, wt.DWORD, ctypes.c_void_p, wt.DWORD,
    ctypes.c_void_p, wt.DWORD, ctypes.POINTER(wt.DWORD), ctypes.c_void_p,
]


@dataclass
class SourceInfo:
    """Metadata describing a scan source."""

    kind: str            # "volume" | "physical" | "image"
    label: str
    device_path: str
    size: int = 0
    bytes_per_sector: int = 512
    fs_type: str = ""    # NTFS / FAT32 / FAT16 / FAT12 / ...
    serial: str = ""
    readonly: bool = True
    partitions: List["Partition"] = field(default_factory=list)
    disk_number: int = -1

    @property
    def display(self) -> str:
        return f"{self.label}  [{self.fs_type} · {human_size(self.size)}]"


def human_size(n: int) -> str:
    if n < 0:
        n = 0
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024.0
    return f"{n:.1f} TB"


class DiskError(Exception):
    """Raised for any low-level read failure."""

    def __init__(self, msg: str, winerror: int = 0):
        super().__init__(msg)
        self.winerror = winerror


class _WinLastError:
    def __enter__(self):
        _kernel32.SetLastError(0)
        return self

    def __exit__(self, *exc):
        return False


class ReadOnlySource:
    """Read-only random-access source (volume / physical drive / image).

    All reads funnel through :meth:`read` which clamps to file size and
    returns ``bytes``.  A byte-range overlapping the end is truncated —
    never zero padded — so corrupt trailing reads are impossible.
    """

    def __init__(self, info: SourceInfo, image_path: Optional[str] = None):
        self.info = info
        self._image_path = image_path
        self._handle: Optional[int] = None
        if info.kind == "image":
            self._handle = None  # plain file object
            self._f = open(image_path, "rb")
        else:
            self._open_device()

    # ------------------------------------------------------------------
    # device lifecycle
    # ------------------------------------------------------------------
    def _open_device(self) -> None:
        with _WinLastError():
            handle = _kernel32.CreateFileW(
                self.info.device_path,
                GENERIC_READ,
                FILE_SHARE_READ | FILE_SHARE_WRITE,
                None,
                OPEN_EXISTING,
                FILE_ATTRIBUTE_NORMAL,
                None,
            )
        err = ctypes.get_last_error()
        if handle == INVALID_HANDLE_VALUE or handle is None:
            raise DiskError(
                f"Cannot open '{self.info.device_path}' read-only "
                f"({self._describe_error(err)}).",
                winerror=err,
            )
        self._handle = handle
        # Refuse to even attempt write paths - belt & braces.
        self.info.readonly = True

    @staticmethod
    def _describe_error(err: int) -> str:
        if err == ERROR_ACCESS_DENIED:
            return "access denied — elevated privileges may be required"
        if err == ERROR_NOT_READY:
            return "drive not ready (no media present?)"
        if err == ERROR_LOCK_VIOLATION:
            return "volume is locked by another process"
        return f"Win32 error {err}"

    # ------------------------------------------------------------------
    # primitives
    # ------------------------------------------------------------------
    def _device_read(self, offset: int, size: int) -> bytes:
        if self.info.kind == "image":
            self._f.seek(offset)
            return self._f.read(size)
        assert self._handle is not None
        buf = ctypes.create_string_buffer(size)
        total = 0
        while total < size:
            view = ctypes.addressof(buf) + total
            want = size - total
            chunk = wt.DWORD(0)
            ok = _kernel32.ReadFile(self._handle, ctypes.c_void_p(view), want, ctypes.byref(chunk), None)
            if not ok:
                err = ctypes.get_last_error()
                raise DiskError(
                    f"Read failed at offset {offset + total} ({self._describe_error(err)}).",
                    winerror=err,
                )
            if chunk.value == 0:
                break  # EOF
            total += chunk.value
        return buf.raw[:total]

    def read(self, offset: int, size: int) -> bytes:
        """Clamp-read: never exceeds source length, never returns short
        silently when data exists."""
        if offset < 0 or size < 0:
            raise ValueError("read(): negative offset/size")
        size = min(size, max(0, self.info.size - offset))
        if size <= 0:
            return b""
        return self._device_read(offset, size)

    def read_sector(self, sector: int, count: int = 1) -> bytes:
        bps = self.info.bytes_per_sector
        return self.read(sector * bps, count * bps)

    def ioctl(self, code: int, out_size: int, in_buf=None, in_len: int = 0) -> bytes:
        assert self._handle is not None
        out = ctypes.create_string_buffer(out_size)
        returned = wt.DWORD(0)
        ok = _kernel32.DeviceIoControl(
            self._handle, code,
            in_buf, in_len, out, out_size, ctypes.byref(returned), None,
        )
        if not ok:
            raise DiskError(
                f"IOCTL 0x{code:x} failed on {self.info.device_path} "
                f"({self._describe_error(ctypes.get_last_error())})."
            )
        return out.raw[: returned.value]

    def close(self) -> None:
        if self.info.kind == "image":
            try:
                self._f.close()
            except Exception:
                pass
            return
        if self._handle is not None:
            try:
                _kernel32.CloseHandle(self._handle)
            except Exception:
                pass
            self._handle = None

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()


# ---------------------------------------------------------------------------
# Enumeration helpers
# ---------------------------------------------------------------------------
def _get_volume_info(root: str):
    """Returns (label, serial_hex, fs_name, flags) for a root path like 'C:\\'."""
    label = ctypes.create_unicode_buffer(MAX_PATH)
    fs = ctypes.create_unicode_buffer(50)
    serial = wt.DWORD(0)
    flags = wt.DWORD(0)
    ok = _kernel32.GetVolumeInformationW(
        root, label, MAX_PATH, ctypes.byref(serial),
        ctypes.POINTER(wt.DWORD)(), ctypes.byref(flags), fs, 50,
    )
    if not ok:
        return "", "", "", 0
    return label.value, f"{serial.value:08X}", fs.value, flags.value


_kernel32.GetDiskFreeSpaceExW.argtypes = [
    ctypes.c_wchar_p, ctypes.POINTER(ctypes.c_ulonglong),
    ctypes.POINTER(ctypes.c_ulonglong), ctypes.POINTER(ctypes.c_ulonglong),
]


def _get_volume_size(root: str):
    free, total, avail = ctypes.c_ulonglong(0), ctypes.c_ulonglong(0), ctypes.c_ulonglong(0)
    ok = _kernel32.GetDiskFreeSpaceExW(root, ctypes.byref(free), ctypes.byref(total), ctypes.byref(avail))
    if not ok:
        return 0
    return total.value


def enumerate_logical_volumes() -> List[SourceInfo]:
    """Enumerate accessible drive letters with labels, sizes and FS types."""
    drives = []
    mask = _kernel32.GetLogicalDrives()
    for i in range(26):
        if not (mask & (1 << i)):
            continue
        letter = chr(ord("A") + i)
        root = f"{letter}:\\"
        label, serial, fs, _ = _get_volume_info(root)
        size = _get_volume_size(root)
        drives.append(
            SourceInfo(
                kind="volume",
                label=f"{letter}:  {label}",
                device_path=f"\\\\.\\{letter}:",
                size=size,
                fs_type=fs,
                serial=serial,
            )
        )
    drives.sort(key=lambda d: d.label)
    return drives


def probe_physical_drives(max_drives: int = 32) -> List[SourceInfo]:
    """Probe \\\\.\\PhysicalDrive0..N.  Returns entries even when access is
    denied so the UI can explain that elevation is required."""
    drives: List[SourceInfo] = []
    for i in range(max_drives):
        path = f"\\\\.\\PhysicalDrive{i}"
        try:
            src = ReadOnlySource(SourceInfo(kind="physical", label=f"PhysicalDrive{i}", device_path=path))
        except DiskError as e:
            if e.winerror == ERROR_ACCESS_DENIED:
                drives.append(SourceInfo(kind="physical", label=f"PhysicalDrive{i} (elevation required)",
                                         device_path=path, size=0))
            continue
        try:
            geo_bytes = src.ioctl(IOCTL_DISK_GET_DRIVE_GEOMETRY, ctypes.sizeof(_DISK_GEOMETRY))
            bps = struct.unpack_from("<I", geo_bytes, 24)[0]
        except DiskError:
            bps = 0
        try:
            len_bytes = src.ioctl(IOCTL_DISK_GET_LENGTH_INFO, 8)
            size = struct.unpack("<Q", len_bytes)[0]
        except DiskError:
            size = 0
        src.close()
        src.info.bytes_per_sector = bps
        src.info.size = size
        drives.append(src.info)
    return drives


def volume_disk_extents(device_path: str) -> Optional[int]:
    """Return the hosting physical disk number for a volume, if available."""
    try:
        with ReadOnlySource(SourceInfo(kind="volume", label="", device_path=device_path)) as src:
            raw = src.ioctl(IOCTL_VOLUME_GET_VOLUME_DISK_EXTENTS, ctypes.sizeof(_VOLUME_DISK_EXTENTS))
        n, = struct.unpack_from("<I", raw, 0)
        if n == 0:
            return None
        return struct.unpack_from("<I", raw, 8)[0]
    except (DiskError, struct.error):
        return None


def is_elevated() -> bool:
    """Checks whether the process holds an elevated (admin) token."""
    import ctypes.wintypes as _wt
    _advapi32.OpenProcessToken.argtypes = [_wt.HANDLE, wt.DWORD, ctypes.POINTER(_wt.HANDLE)]
    _advapi32.GetTokenInformation.argtypes = [_wt.HANDLE, wt.DWORD, ctypes.c_void_p, wt.DWORD,
                                              ctypes.POINTER(wt.DWORD)]
    TOKEN_QUERY = 0x0008
    TokenElevation = 20
    htok = _wt.HANDLE(0)
    if not _advapi32.OpenProcessToken(_kernel32.GetCurrentProcess(), TOKEN_QUERY, ctypes.byref(htok)):
        return False
    try:
        elev = ctypes.c_ulong(0)
        size = wt.DWORD(0)
        _advapi32.GetTokenInformation(htok, TokenElevation, ctypes.byref(elev), ctypes.sizeof(elev), ctypes.byref(size))
        return bool(elev.value)
    finally:
        _kernel32.CloseHandle(htok)