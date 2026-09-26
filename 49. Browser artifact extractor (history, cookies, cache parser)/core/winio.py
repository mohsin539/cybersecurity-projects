"""Windows-aware file I/O for locked browser evidence.

Live browsers (notably Chromium's ``Cookies`` database) frequently hold an
*exclusive* ``dwShareMode = 0`` lock, which ordinary reads -- and even
``robocopy /B`` -- cannot bypass. This module layers increasingly capable
acquisition strategies:

1. **Shared read** - ``CreateFileW`` requesting ``FILE_SHARE_READ|WRITE|DELETE``.
2. **Backup semantics** - enable ``SeBackupPrivilege`` and open with
   ``FILE_FLAG_BACKUP_SEMANTICS`` (works for ACL/permission denials).
3. **Volume Shadow Copy** - snapshot the volume via WMI (requires elevation),
   then read the file from the read-only shadow device.

The correct strategy is auto-selected; when every option fails the caller gets
an :class:`EvidenceLocked` with operator-friendly remediation text.
"""
from __future__ import annotations

import ctypes
import os
import shutil
import subprocess
import sys
import tempfile
from ctypes import wintypes

IS_WINDOWS = sys.platform.startswith("win")

ERROR_SHARING_VIOLATION = 32
ERROR_ACCESS_DENIED = 5

GENERIC_READ = 0x80000000
FILE_SHARE_READ, FILE_SHARE_WRITE, FILE_SHARE_DELETE = 1, 2, 4
OPEN_EXISTING = 3
FILE_ATTRIBUTE_NORMAL = 0x80
FILE_FLAG_BACKUP_SEMANTICS = 0x02000000
INVALID_HANDLE_VALUE = ctypes.c_void_p(-1).value


class EvidenceLocked(OSError):
    """Raised when a live artifact cannot be acquired by any strategy."""

    def __init__(self, path: str, reason: str = ""):
        self.path = path
        self.reason = reason
        super().__init__(
            f"{os.path.basename(path)} is exclusively locked by a running process"
            + (f" ({reason})" if reason else "")
            + ". Close the browser (or run the extractor elevated for VSS snapshot) "
              "and retry to collect this artifact."
        )


# ---------------------------------------------------------------------------
# Privilege helpers
# ---------------------------------------------------------------------------
def is_admin() -> bool:
    if not IS_WINDOWS:
        return os.geteuid() == 0 if hasattr(os, "geteuid") else False
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except Exception:  # noqa: BLE001
        return False


def _enable_backup_privilege() -> bool:
    """Enable SeBackupPrivilege for the current process (best effort)."""
    if not IS_WINDOWS:
        return False
    try:
        advapi32 = ctypes.windll.advapi32
        kernel32 = ctypes.windll.kernel32

        class LUID(ctypes.Structure):
            _fields_ = [("LowPart", wintypes.DWORD), ("HighPart", wintypes.LONG)]

        class LUID_AND_ATTRIBUTES(ctypes.Structure):
            _fields_ = [("Luid", LUID), ("Attributes", wintypes.DWORD)]

        class TOKEN_PRIVILEGES(ctypes.Structure):
            _fields_ = [("PrivilegeCount", wintypes.DWORD),
                        ("Privileges", LUID_AND_ATTRIBUTES * 1)]

        SE_PRIVILEGE_ENABLED = 0x00000002
        TOKEN_ADJUST_PRIVILEGES = 0x0020
        TOKEN_QUERY = 0x0008

        token = wintypes.HANDLE()
        if not advapi32.OpenProcessToken(kernel32.GetCurrentProcess(),
                                         TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY,
                                         ctypes.byref(token)):
            return False
        luid = LUID()
        if not advapi32.LookupPrivilegeValueW(None, "SeBackupPrivilege", ctypes.byref(luid)):
            return False
        tp = TOKEN_PRIVILEGES()
        tp.PrivilegeCount = 1
        tp.Privileges[0].Luid = luid
        tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED
        res = advapi32.AdjustTokenPrivileges(token, False, ctypes.byref(tp), 0, None, None)
        return bool(res)
    except Exception:  # noqa: BLE001
        return False


# ---------------------------------------------------------------------------
# Acquisition strategies
# ---------------------------------------------------------------------------
def _open_handle(path: str, flags: int = FILE_ATTRIBUTE_NORMAL):
    k32 = ctypes.windll.kernel32
    k32.CreateFileW.restype = wintypes.HANDLE
    k32.CreateFileW.argtypes = [wintypes.LPCWSTR, wintypes.DWORD, wintypes.DWORD,
                                ctypes.c_void_p, wintypes.DWORD, wintypes.DWORD,
                                wintypes.HANDLE]
    handle = k32.CreateFileW(
        str(path), GENERIC_READ,
        FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
        None, OPEN_EXISTING, flags, None,
    )
    if not handle or handle == INVALID_HANDLE_VALUE:
        return None, ctypes.GetLastError()
    return handle, 0


def _read_handle_to_file(handle, dst: str) -> None:
    k32 = ctypes.windll.kernel32
    k32.ReadFile.argtypes = [wintypes.HANDLE, ctypes.c_void_p, wintypes.DWORD,
                             ctypes.POINTER(wintypes.DWORD), ctypes.c_void_p]
    buf = ctypes.create_string_buffer(1 << 20)
    read = wintypes.DWORD()
    with open(dst, "wb") as out:
        while True:
            ok = k32.ReadFile(handle, buf, len(buf), ctypes.byref(read), None)
            if not ok or read.value == 0:
                break
            out.write(buf.raw[:read.value])


def copy_shared(src: str, dst: str) -> None:
    handle, err = _open_handle(src)
    if handle is None:
        raise OSError(err, f"CreateFileW failed (error {err})")
    try:
        _read_handle_to_file(handle, dst)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def copy_backup(src: str, dst: str) -> None:
    """Backup-semantics open; bypasses ACL-based access denials."""
    handle, err = _open_handle(src, FILE_FLAG_BACKUP_SEMANTICS)
    if handle is None:
        raise OSError(err, f"backup-mode open failed (error {err})")
    try:
        _read_handle_to_file(handle, dst)
    finally:
        ctypes.windll.kernel32.CloseHandle(handle)


def copy_plain(src: str, dst: str) -> None:
    with open(src, "rb") as fh, open(dst, "wb") as out:
        shutil.copyfileobj(fh, out, 1 << 20)


_VSS_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$src = $args[0]
$dst = $args[1]
$vol = ([System.IO.Path]::GetPathRoot($src))
$cls = (Get-CimInstance -ClassName Win32_ShadowCopy -List)
$res = $cls.Create($vol, 'ClientAccessible')
if ($res.ReturnValue -ne 0) { Write-Error "shadow create failed $($res.ReturnValue)"; exit 3 }
$id = $res.ShadowID
$shadow = Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $id }
$dev = $shadow.DeviceObject
try {
    $rel = $src.Substring($vol.Length).TrimStart('\')
    $from = Join-Path $dev $rel
    Copy-Item -LiteralPath $from -Destination $dst -Force
    Write-Output "OK"
} finally {
    Get-CimInstance Win32_ShadowCopy | Where-Object { $_.ID -eq $id } | Remove-CimInstance -ErrorAction SilentlyContinue
}
"""


def copy_vss(src: str, dst: str, timeout: int = 180) -> None:
    """Create a volume shadow copy, read the file from it, then remove it.

    Requires administrative rights. Raises :class:`EvidenceLocked` on failure.
    """
    if not (IS_WINDOWS and is_admin()):
        raise EvidenceLocked(src, "VSS requires elevation")
    script = os.path.join(tempfile.gettempdir(), "bae_vss.ps1")
    if not os.path.isfile(script):
        with open(script, "w", encoding="utf-8") as fh:
            fh.write(_VSS_SCRIPT)
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive",
             "-ExecutionPolicy", "Bypass", "-File", script, src, dst],
            capture_output=True, text=True, timeout=timeout,
        )
        if proc.returncode != 0 or "OK" not in proc.stdout:
            raise EvidenceLocked(src, (proc.stderr or "VSS snapshot failed")[:160])
    except subprocess.TimeoutExpired:
        raise EvidenceLocked(src, "VSS snapshot timed out")
    except FileNotFoundError:
        raise EvidenceLocked(src, "PowerShell unavailable for VSS")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def copy_any(src: str, dst: str, allow_vss: bool = True) -> str:
    """Copy *src* to *dst* using the strongest available strategy.

    Returns the strategy name. Raises :class:`EvidenceLocked` when the file
    cannot be acquired at all.
    """
    if not IS_WINDOWS:
        copy_plain(src, dst)
        return "plain"

    errors = []
    for name, fn in (("shared", copy_shared),
                     ("backup", copy_backup),
                     ("plain", copy_plain)):
        try:
            fn(src, dst)
            if os.path.getsize(dst) > 0:
                return name
            errors.append(f"{name}: produced empty file")
        except OSError as exc:
            errors.append(f"{name}: {exc}")

    if allow_vss and is_admin():
        try:
            _enable_backup_privilege()
            copy_vss(src, dst)
            return "vss"
        except EvidenceLocked as exc:
            errors.append(f"vss: {exc.reason}")
        except OSError as exc:
            errors.append(f"vss: {exc}")

    if not is_admin():
        errors.append("hint: run elevated for VSS snapshot")
    raise EvidenceLocked(src, "; ".join(errors)[:240])
