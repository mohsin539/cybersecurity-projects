"""Process monitor: snapshot diffing + cmdline/hash checks.

Portable: uses `psutil`-free approaches:
  - Linux: /proc scan
  - Windows: PowerShell `Get-CimInstance Win32_Process` (wmic is deprecated
    on Windows 11 / Server 2022+ and removed on newer builds).
This stays dependency-free and hide the OS specifics behind process_list().
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class ProcessInfo:
    pid: int
    ppid: int
    name: str
    exe: str
    cmdline: str
    user: str = ""
    started: float = 0.0
    rss_kb: int = 0


def _linux_procs() -> List[ProcessInfo]:
    from pathlib import Path
    out: List[ProcessInfo] = []
    for pd in sorted(Path("/proc").glob("[0-9]*")):
        try:
            pid = int(pd.name)
            with (pd / "cmdline").open("rb") as fh:
                argv = fh.read().decode("utf-8", errors="replace").replace("\x00", " ").strip()
            with (pd / "stat").open("r") as fh:
                parts = fh.read().split()
            # comm may contain spaces; field 2 onwards after ')' of pid
            comm = parts[1] if len(parts) > 1 else "?"
            ppid = int(parts[3]) if len(parts) > 3 else 0
            rss_kb = 0
            try:
                with (pd / "statm").open("r") as fh:
                    rss_kb = int(fh.read().split()[1]) * 4  # pages (4KB) -> KB
            except (OSError, ValueError, IndexError):
                pass
            exe = ""
            try:
                exe = str((pd / "exe").resolve())
            except OSError:
                pass
            out.append(ProcessInfo(pid, ppid, comm.strip("()"), exe, argv, rss_kb=rss_kb))
        except (OSError, ValueError):
            continue
    return out


def _win_procs() -> List[ProcessInfo]:
    """Enumerate processes on Windows without psutil.

    Primary: PowerShell `Get-CimInstance Win32_Process`. CIM query is CSV to
    keep parsing simple and avoids PowerShell object formatting overhead.
    Falls back to `Get-Process` (less metadata) on failure.
    """
    out: List[ProcessInfo] = []
    ps_cmd = (
        "$sep=[char]0x1f;"
        "$props='ProcessId,ParentProcessId,Name,ExecutablePath';"
        "Get-CimInstance Win32_Process "
        "-Filter 'ParentProcessId != 0' "
        "| ForEach-Object {"
        ' "{0}{1}{2}{3}{4}{5}{6}{7}{8}{9}{10}" -f '
        "$_.ProcessId,$sep,$_.ParentProcessId,$sep,$_.Name,$sep,$_.ExecutablePath,$sep,$_.CommandLine,$sep,$_.WorkingSetSize"
        "}"
    )
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", ps_cmd],
            capture_output=True, text=True, timeout=45, check=False,
        )
        lines = (res.stdout or "").splitlines()
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        lines = []

    for line in lines:
        line = line.strip()
        if not line or "\x1f" not in line:
            continue
        parts = line.split("\x1f")
        if len(parts) < 5:
            continue
        pid = _safe_int(parts[0])
        ppid = _safe_int(parts[1])
        name = parts[2] or "?"
        exe = parts[3] or ""
        cmdline = parts[4] if len(parts) > 4 else ""
        rss_kb = (_safe_int(parts[5]) if len(parts) > 5 else 0) // 1024
        if pid <= 0:
            continue
        out.append(ProcessInfo(pid=pid, ppid=ppid, name=name, exe=exe, cmdline=cmdline, rss_kb=rss_kb))

    if out:
        return out

    # Fallback: Get-Process with a plain tab-separated dump.
    gps_cmd = (
        "$sep=[char]0x1f;"
        "Get-Process | ForEach-Object {"
        ' "{0}{1}{2}{3}{4}" -f '
        "$_.Id,$sep,'0',$sep,$_.ProcessName,$sep,$_.Path"
        "}"
    )
    try:
        res = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", gps_cmd],
            capture_output=True, text=True, timeout=30, check=False,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return out
    for line in (res.stdout or "").splitlines():
        line = line.strip()
        if not line or "\x1f" not in line:
            continue
        parts = line.split("\x1f")
        if len(parts) < 4:
            continue
        pid = _safe_int(parts[0])
        if pid <= 0:
            continue
        out.append(ProcessInfo(pid=pid, ppid=0, name=parts[2] or "?",
                               exe=parts[3] or "", cmdline=""))
    return out


def _safe_int(s: str) -> int:
    try:
        return int(s)
    except (TypeError, ValueError):
        return 0


def process_list() -> List[ProcessInfo]:
    if sys.platform.startswith("linux"):
        return _linux_procs()
    if sys.platform.startswith("win"):
        return _win_procs()
    return []


DANGER_TOKENS = ["-enc", "-encodedcommand", "base64", "wget", "curl ", "nc -e",
                 "ncat -e", "mkfifo", "/bin/bash -i", "cmd.exe /c"]


def flag_cmdline(proc: ProcessInfo) -> Optional[str]:
    """Returns a reason string if the cmdline is suspicious, else None."""
    low = proc.cmdline.lower()
    hits = [t for t in DANGER_TOKENS if t in low]
    return ";".join(hits) if hits else None


def hash_exe(proc: ProcessInfo) -> str:
    from pathlib import Path
    p = Path(proc.exe) if proc.exe else None
    if not p or not p.is_file():
        return ""
    h = hashlib.sha256()
    try:
        with p.open("rb") as fh:
            while True:
                blk = fh.read(1 << 20)
                if not blk:
                    break
                h.update(blk)
        return h.hexdigest()
    except OSError:
        return ""


class ProcMonitor:
    """Diff of process list between cycles: new pids, cmdline flags, hash match."""

    def __init__(self, known_hashes: set[str], emit):
        self.known_hashes = known_hashes or set()
        self._seen: dict[int, ProcessInfo] = {}
        self._procs: List[ProcessInfo] = []
        self.emit = emit

    @property
    def procs(self) -> List[ProcessInfo]:
        return self._procs

    def scan(self, warmup: bool = False) -> int:
        findings = 0
        procs = process_list()
        current_ids = set()
        for p in procs:
            current_ids.add(p.pid)
            is_new = p.pid not in self._seen
            self._seen[p.pid] = p
            if not is_new:
                continue
            if warmup:
                # first run: record the process landscape, no findings
                continue
            reason = flag_cmdline(p)
            h = hash_exe(p)
            sig = "known" if h and h in self.known_hashes else ("unknown_binary" if h else "no_exe")
            if reason or sig == "unknown_binary":
                findings += 1
                self.emit({
                    "type": "proc_new",
                    "pid": p.pid, "ppid": p.ppid, "name": p.name,
                    "exe": p.exe, "cmdline": p.cmdline,
                    "reason": reason or "", "binary": sig,
                })
        # Terminated processes
        for pid in list(self._seen):
            if pid not in current_ids:
                self._seen.pop(pid)
        self._procs = procs
        return findings