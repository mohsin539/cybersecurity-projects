"""Deterministic synthetic API-trace generator (benign corpus, ISO A.8.33).

Produces repeatable behavioral sequences (file copy, registry read, network
resolve, process spawn chain, memory ops) used for demos, tests and golden
files. Seeded by the SHA-256 of the sample so the same sample always yields
the same trace.
"""

from __future__ import annotations

import hashlib
import random

from .runner import TraceEvent


def _seed_for(sha256: str) -> int:
    return int(hashlib.sha256(sha256.encode()).hexdigest()[:12], 16)


def _path_t(y, name):
    pid = 2000 + y
    return pid


def build_trace(sha256: str, count: int = 600) -> list[TraceEvent]:
    rng = random.Random(_seed_for(sha256))
    events: list[TraceEvent] = []
    tid = {1: 1, 2: 1}
    y = list(range(1, 4))
    for i in range(count):
        pid = 1000 + rng.choice(y)
        t = tid.setdefault(pid, 0)
        tid[pid] += 1
        kind = i % 7
        if kind == 0:
            events.append(TraceEvent(
                api="NtCreateFile", category="File", tid=t, pid=pid, module="ntdll.dll",
                args={"ObjectName": f"\\\\??\\\\C:\\\\tmp\\\\obj{i}.bin", "DesiredAccess": "0x12019f"},
                ret="0x0", tags=["OWASP-A03"],
            ))
            events.append(TraceEvent(
                api="NtWriteFile", category="File", tid=t, pid=pid, module="ntdll.dll",
                args={"Length": rng.randint(64, 4096)}, ret="0x0",
                parent_seq=len(events) - 1,
            ))
            events.append(TraceEvent(
                api="NtClose", category="File", tid=t, pid=pid, module="ntdll.dll",
                args={}, ret="0x0", parent_seq=len(events) - 2,
            ))
        elif kind == 1:
            events.append(TraceEvent(
                api="RegOpenKeyExW", category="Registry", tid=t, pid=pid, module="advapi32.dll",
                args={"SubKey": r"SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run",
                      "DesiredAccess": "KEY_READ"}, ret="0x0",
            ))
            events.append(TraceEvent(
                api="RegQueryValueExW", category="Registry", tid=t, pid=pid, module="advapi32.dll",
                args={"Name": "Update", "Type": "REG_SZ"}, ret="0x0",
                parent_seq=len(events) - 1,
            ))
        elif kind == 2:
            events.append(TraceEvent(
                api="GetAddrInfoW", category="Network", tid=t, pid=pid, module="ws2_32.dll",
                args={"NodeName": rng.choice(["update.telemetry.example", "cdn.svc.example",
                                              "api.stats.example"])}, ret="0x0",
                tags=["OWASP-A10"],
            ))
            events.append(TraceEvent(
                api="WSAConnect", category="Network", tid=t, pid=pid, module="ws2_32.dll",
                args={"Port": rng.choice([80, 443, 8080]), "Addr": "10.0.0.12"}, ret="0x2f",
                status="FAIL", parent_seq=len(events) - 1,
            ))
        elif kind == 3:
            events.append(TraceEvent(
                api="CreateProcessW", category="Process", tid=t, pid=pid, module="kernel32.dll",
                args={"ApplicationName": "C:\\\\Windows\\\\System32\\\\cmd.exe",
                      "CommandLine": "/c whoami"}, ret="0x1",
                tags=["CWE-787"],
            ))
        elif kind == 4:
            events.append(TraceEvent(
                api="OpenProcess", category="Process", tid=t, pid=pid, module="kernel32.dll",
                args={"ProcessId": 3320, "DesiredAccess": "PROCESS_ALL_ACCESS"}, ret="0x1",
                tags=["CWE-787"],
            ))
            events.append(TraceEvent(
                api="VirtualAllocEx", category="Memory", tid=t, pid=pid, module="kernel32.dll",
                args={"RegionalSize": "0x1000", "Type": "MEM_COMMIT",
                      "Protection": "PAGE_EXECUTE_READWRITE"}, ret="0x000001A0",
                parent_seq=len(events) - 1, tags=["CWE-787"],
            ))
            events.append(TraceEvent(
                api="WriteProcessMemory", category="Memory", tid=t, pid=pid, module="kernel32.dll",
                args={"Length": 256}, ret="0x1", parent_seq=len(events) - 2,
                tags=["CWE-787"],
            ))
            events.append(TraceEvent(
                api="CreateRemoteThread", category="Thread", tid=t, pid=pid, module="kernel32.dll",
                args={"StartAddress": "0x000001A0"}, ret="0x1",
                parent_seq=len(events) - 3, tags=["CWE-787"],
            ))
        elif kind == 5:
            events.append(TraceEvent(
                api="CryptHashData", category="Crypto", tid=t, pid=pid, module="advapi32.dll",
                args={"AlgId": "CALG_SHA_256"}, ret="0x0",
            ))
        elif kind == 6:
            events.append(TraceEvent(
                api="CreateFileW", category="IPC", tid=t, pid=pid, module="kernel32.dll",
                args={"PipeName": "\\\\\\\\.\\\\pipe\\\\agent_svc"}, ret="0x1",
                status="TIMEOUT",
            ))
    return events