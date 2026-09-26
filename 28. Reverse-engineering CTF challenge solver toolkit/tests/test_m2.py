"""Tests: M2 — disassembly + Ghidra bridge."""
from __future__ import annotations

import struct
from pathlib import Path

import pytest

from rekt.core.disasm import entry_disasm, linear_disasm, pe_entry_rva, recursive_disasm


def _x64_code() -> bytes:
    """push rbp; mov rbp,rsp; mov eax, 0x2a; pop rbp; ret (+ garbage after)."""
    return bytes.fromhex("554889e5b82a0000005dc3") + b"\x90" * 8 + b"\x00" * 16


def test_linear_disasm_x64():
    rows = linear_disasm(_x64_code(), "x86-64", 64)
    assert rows, "capstone produced no rows"
    mnemonics = [r["mnemonic"] for r in rows[:5]]
    assert "push" in mnemonics and "ret" in mnemonics
    assert all({"addr", "size", "bytes", "mnemonic", "op_str", "text"} <= set(r) for r in rows)


def test_recursive_disasm_x64():
    rows = recursive_disasm(_x64_code(), "x86-64", 64)
    assert rows
    text = " | ".join(r["text"] for r in rows)
    assert "ret" in text


def test_disasm_bounded_on_garbage():
    rows = entry_disasm(b"\xcc" * 100_000, "x86-64", 64, mode="linear")
    assert len(rows) <= 20_000  # budget respected (A04)


def test_pe_entry_rva():
    d = bytearray(_x64_code())
    struct.pack_into("<I", d, 0, 0)  # not a PE -> None path
    assert pe_entry_rva(bytes(d)) is None


def test_child_disasm_task(tmp_path):
    """The disasm task runs inside the sandboxed child like analyze/recipe."""
    from rekt.sandbox.policy import Policy
    from rekt.sandbox.runner import run_job

    res = run_job(Policy(timeout_s=60),
                  {"task": "disasm", "arch": "x86-64", "bits": 64, "mode": "linear"},
                  _x64_code(), tmp_path / "s")
    assert res.ok, res.detail
    assert res.result["count"] > 0
    assert any(r["mnemonic"] == "ret" for r in res.result["rows"])


def test_run_job_survives_relative_scratch_root(tmp_path, monkeypatch):
    """Regression: a RELATIVE scratch root used to break the child (it runs with
    cwd=scratch, so relative cfg paths resolved inside the child and the payload
    'vanished'). run_job must resolve paths absolutely."""
    import os
    from rekt.sandbox.policy import Policy
    from rekt.sandbox.runner import run_job

    work = tmp_path / "proj"
    work.mkdir()
    monkeypatch.chdir(work)  # simulate a GUI launched with a relative data dir
    res = run_job(Policy(timeout_s=60),
                  {"task": "disasm", "arch": "x86-64", "bits": 64, "mode": "linear"},
                  _x64_code(), Path("scratch/relative"))
    assert res.ok, res.detail
    assert res.result["payload_len"] == len(_x64_code())  # bytes actually arrived
    assert res.result["count"] > 0


# ------------------------------------------------------------------ ghidra bridge
def test_ghidra_command_is_argv_list(tmp_path):
    from rekt.application import ghidra

    home = ghidra.GhidraHome(root=tmp_path)
    (tmp_path / "support").mkdir()
    cmd = ghidra.build_command(home, tmp_path / "proj", tmp_path / "s.bin",
                               tmp_path / "out.c")
    assert isinstance(cmd, list) and "analyzeHeadless" in cmd[0]
    assert "-postScript" in cmd and "ExportDecomp.java" in cmd
    assert all(not c.startswith("|") for c in cmd)  # no shell metachar pipeline


def test_ghidra_consent_required(tmp_path):
    from rekt.application.jobs import JobService
    from rekt.platform.audit import AuditLog
    from rekt.platform.store import ProjectStore

    store = ProjectStore(tmp_path / "p")
    jobs = JobService(store, AuditLog(tmp_path / "a.log"), tmp_path / "scratch")
    res = jobs.run_ghidra("sha", b"data", "C:/nonexistent", session_consents=set())
    assert not res.ok
    assert "confirmation" in res.detail


def test_ghidra_missing_home_raises(tmp_path):
    from rekt.application.jobs import GhidraUnavailable, JobService
    from rekt.platform.audit import AuditLog
    from rekt.platform.store import ProjectStore

    store = ProjectStore(tmp_path / "p")
    jobs = JobService(store, AuditLog(tmp_path / "a.log"), tmp_path / "scratch")
    with pytest.raises(GhidraUnavailable):
        jobs.run_ghidra("sha", b"data", "C:/nonexistent", session_consents={"GHIDRA"})
