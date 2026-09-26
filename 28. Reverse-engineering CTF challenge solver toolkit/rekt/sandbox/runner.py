"""Host-side job execution: disposable child + Windows Job Object caps + watchdog.

Windows hard caps (ARCHITECTURE.md §3.5): memory limit, CPU time limit,
active-process limit, UI restrictions, kill-on-job-close — via ctypes, no
third-party deps. Other platforms: POSIX soft caps inside the child + watchdog
terminate (documented honestly in STATE.md §"Sandbox limits").

Fail-closed: any inability to enforce a policy makes the job refuse to run.

Child protocol (works in frozen/windowed builds where stdio is unavailable):
  argv[1] = JSON {scratch, policy, task, payload, reply}
  payload file = artifact bytes; reply file = JSON result
  stdin/stdout remain the dev-mode fallback channel.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import threading
import time
from pathlib import Path
from typing import Any

from rekt.sandbox.policy import JobKind, Policy

_CHILD = Path(__file__).with_name("child.py")


def _child_argv(cfg: str) -> list[str]:
    """Spawn command for the sandbox child.

    Dev/source mode: python.exe child.py <cfg>
    Frozen mode: the .exe cannot run scripts; the bundled app recognizes the
    --rekt-sandbox-child flag (handled first in __main__) and dispatches to
    rekt.sandbox.child with the same JSON config.
    """
    if getattr(sys, "frozen", False):
        return [sys.executable, "--rekt-sandbox-child", cfg]
    return [sys.executable, str(_CHILD), cfg]


# --------------------------------------------------------------- Windows Job Object
class _JobObject:
    """ctypes wrapper: hard caps + kill-on-close. Only on win32."""

    def __init__(self, max_memory_mb: int, max_cpu_seconds: int) -> None:
        import ctypes

        self.kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        self.handle = self.kernel32.CreateJobObjectW(None, None)
        if not self.handle:
            raise OSError("CreateJobObjectW failed — cannot enforce caps, refusing job")

        class IO_COUNTERS(ctypes.Structure):
            _fields_ = [(n, ctypes.c_uint64) for n in (
                "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
                "ReadTransferCount", "WriteTransferCount", "OtherTransferCount")]

        class JOBOBJECT_BASIC_LIMIT_INFORMATION(ctypes.Structure):
            _fields_ = [
                ("PerProcessUserTimeLimit", ctypes.c_int64),
                ("PerJobUserTimeLimit", ctypes.c_int64),
                ("LimitFlags", ctypes.c_uint32),
                ("MinimumWorkingSetSize", ctypes.c_size_t),
                ("MaximumWorkingSetSize", ctypes.c_size_t),
                ("ActiveProcessLimit", ctypes.c_uint32),
                ("Affinity", ctypes.c_size_t),
                ("PriorityClass", ctypes.c_uint32),
                ("SchedulingClass", ctypes.c_uint32),
            ]

        class JOBOBJECT_EXTENDED_LIMIT_INFO(ctypes.Structure):
            _fields_ = [
                ("BasicLimitInformation", JOBOBJECT_BASIC_LIMIT_INFORMATION),
                ("IoInfo", IO_COUNTERS),
                ("ProcessMemoryLimit", ctypes.c_size_t),
                ("JobMemoryLimit", ctypes.c_size_t),
                ("PeakProcessMemoryUsed", ctypes.c_size_t),
                ("PeakJobMemoryUsed", ctypes.c_size_t),
            ]

        JOB_OBJECT_LIMIT_PROCESS_MEMORY = 0x00000100
        JOB_OBJECT_LIMIT_JOB_TIME = 0x00000004
        JOB_OBJECT_LIMIT_ACTIVE_PROCESS = 0x00000008
        JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE = 0x00002000
        JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION = 0x00000400

        info = JOBOBJECT_EXTENDED_LIMIT_INFO()
        info.BasicLimitInformation.LimitFlags = (
            JOB_OBJECT_LIMIT_PROCESS_MEMORY | JOB_OBJECT_LIMIT_JOB_TIME
            | JOB_OBJECT_LIMIT_ACTIVE_PROCESS | JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
            | JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION
        )
        info.ProcessMemoryLimit = max_memory_mb * 1024 * 1024
        info.BasicLimitInformation.PerJobUserTimeLimit = max_cpu_seconds * 10_000_000  # 100ns
        info.BasicLimitInformation.ActiveProcessLimit = 8

        self.kernel32.SetInformationJobObject(
            self.handle, 9,  # JobObjectExtendedLimitInformation
            ctypes.byref(info), ctypes.sizeof(info))
        self._ui_restrict()

    def _ui_restrict(self) -> None:
        import ctypes

        class JOBOBJECT_BASIC_UI_RESTRICTIONS(ctypes.Structure):
            _fields_ = [("UIRestrictionsClass", ctypes.c_uint32)]

        JOB_OBJECT_UILIMIT_HANDLES = 0x1
        ui = JOBOBJECT_BASIC_UI_RESTRICTIONS(JOB_OBJECT_UILIMIT_HANDLES)
        self.kernel32.SetInformationJobObject(
            self.handle, 10,  # JobObjectBasicUIRestrictions
            ctypes.byref(ui), ctypes.sizeof(ui))

    def assign(self, proc: subprocess.Popen) -> None:
        import ctypes

        if not self.kernel32.AssignProcessToJobObject(self.handle, int(proc._handle)):  # noqa: SLF001
            raise OSError("AssignProcessToJobObject failed — refusing unsandboxed run")

    def kill(self) -> None:
        self.kernel32.TerminateJobObject(self.handle, 1)

    def close(self) -> None:
        self.kernel32.CloseHandle(self.handle)


# ------------------------------------------------------------------------- runner
class JobResult:
    def __init__(self, ok: bool, detail: str, result: Any = None, killed: bool = False,
                 duration_s: float = 0.0) -> None:
        self.ok = ok
        self.detail = detail
        self.result = result
        self.killed = killed
        self.duration_s = duration_s

    def to_dict(self) -> dict:
        return {"ok": self.ok, "detail": self.detail, "result": self.result,
                "killed": self.killed, "duration_s": round(self.duration_s, 3)}


def _child_env(scratch_dir: Path) -> dict:
    """Minimal environment for the child: no user paths, no shell reach."""
    return {
        "PYTHONPATH": str(Path(__file__).resolve().parents[2]),  # package root only
        "SYSTEMROOT": os.environ.get("SYSTEMROOT", r"C:\Windows"),
        "PATH": os.environ.get("PATH", ""),
        "TEMP": str(scratch_dir),
        "TMP": str(scratch_dir),
    }


def run_job(policy: Policy, task: dict, payload: bytes, scratch_dir: Path) -> JobResult:
    """Run one task in a fresh, capped, disposable child process."""
    # CRITICAL: absolute paths — the child runs with cwd=scratch_dir, so any
    # relative path in the cfg would resolve against the child's own scratch
    # dir and silently fall back to empty stdin (observed in GUI sessions).
    scratch_dir = Path(scratch_dir).resolve()
    scratch_dir.mkdir(parents=True, exist_ok=True)
    # Unique per-run filenames: a stale reply from any previous run must never
    # be mistaken for this run's result (defense against transient FS weirdness).
    token = f"{os.getpid()}-{time.monotonic_ns()}"
    payload_path = scratch_dir / f"payload-{token}.bin"
    reply_path = scratch_dir / f"reply-{token}.json"
    payload_path.write_bytes(payload)
    cfg = json.dumps({"scratch": str(scratch_dir), "policy": policy.to_json(),
                      "task": task, "payload": str(payload_path),
                      "reply": str(reply_path)})
    start = time.monotonic()
    argv = _child_argv(cfg)
    killed = False
    out, err = b"", b""

    try:
        if sys.platform == "win32":
            proc = subprocess.Popen(  # noqa: S603 — argv list, no shell (A03)
                argv,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE, creationflags=subprocess.CREATE_NO_WINDOW,
                cwd=str(scratch_dir), env=_child_env(scratch_dir),
            )
            try:
                job = _JobObject(policy.max_memory_mb, policy.max_cpu_seconds)
            except OSError as e:
                proc.kill()
                return JobResult(False, f"sandbox enforcement failed: {e}",
                                 duration_s=time.monotonic() - start)
            try:
                job.assign(proc)   # fail-closed: refuse if the job object can't attach
            except OSError as e:
                proc.kill()
                job.close()
                return JobResult(False, f"sandbox enforcement failed: {e}",
                                 duration_s=time.monotonic() - start)
            try:
                out, err = proc.communicate(timeout=policy.timeout_s)
                killed = False
            except subprocess.TimeoutExpired:
                job.kill()
                try:
                    out, err = proc.communicate(timeout=5)
                except subprocess.TimeoutExpired:
                    proc.kill()
                    out, err = b"", b""
                killed = True
            finally:
                job.close()
        else:
            proc = subprocess.Popen(  # noqa: S603
                argv,
                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                cwd=str(scratch_dir), env=_child_env(scratch_dir),
            )
            try:
                out, err = proc.communicate(timeout=policy.timeout_s)
                killed = False
            except subprocess.TimeoutExpired:
                proc.kill()
                out, err = proc.communicate()
                killed = True
    except OSError as e:
        return JobResult(False, f"job launch failed: {e}",
                         duration_s=time.monotonic() - start)

    duration = time.monotonic() - start
    if killed:
        return JobResult(False, f"job exceeded {policy.timeout_s}s — killed", killed=True,
                         duration_s=duration)
    # Reply files beat pipes for windowed/frozen builds (no stdio there).
    if reply_path.exists():
        out = reply_path.read_bytes()
    # Output cap (A04: DoS guard)
    if len(out) > policy.max_output_bytes:
        return JobResult(False, "output exceeded policy cap", duration_s=duration)
    try:
        reply = json.loads(out.decode("utf-8", "replace"))
    except json.JSONDecodeError:
        return JobResult(False, f"child crashed: {err[:500]!r}", duration_s=duration)
    return JobResult(reply.get("ok", False),
                     reply.get("error", "completed"),
                     result=reply.get("result"), duration_s=duration)


class Watchdog:
    """Belt-and-braces watchdog: cancels jobs whose deadline has passed."""

    def __init__(self) -> None:
        self._timers: dict[str, threading.Timer] = {}

    def arm(self, job_id: str, timeout_s: int, on_breach) -> None:
        t = threading.Timer(timeout_s, on_breach)
        t.daemon = True
        self._timers[job_id] = t
        t.start()

    def disarm(self, job_id: str) -> None:
        t = self._timers.pop(job_id, None)
        if t:
            t.cancel()
