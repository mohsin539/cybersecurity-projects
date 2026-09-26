"""Child-side sandbox runner — executes INSIDE the disposable analysis process.

Guards installed before any task runs (OWASP A01):
  * socket.socket -> PermissionError       (network null-route, deny-by-default)
  * subprocess spawn -> PermissionError    (no process tree from the child)
  * builtins.open write-mode outside scratch -> PermissionError
  * POSIX: RLIMIT_AS / RLIMIT_CPU soft caps when the resource module exists

Protocol: config JSON in argv[1]; task JSON on stdin; result JSON on stdout.
The child never sees file paths from the host except its own scratch dir.
"""
from __future__ import annotations

import builtins
import json
import os
import socket
import subprocess  # noqa: F401  (imported to be neutered)
import sys
from pathlib import Path

try:
    import resource  # noqa: F401  (POSIX-only; guarded for Windows below)
    _HAS_RESOURCE = True
except ImportError:  # Windows: hard caps come from the host's Job Object instead
    _HAS_RESOURCE = False

_sdk = None  # host passes the artifact bytes via stdin; child works in memory


def install_guards(scratch: Path) -> None:
    scratch = scratch.resolve()

    # --- network null-route (A01: deny-by-default) ---
    class _Blocked(socket.socket):
        def __init__(self, *a, **k):
            raise PermissionError("network access is blocked by sandbox policy")

    socket.socket = _Blocked  # type: ignore[misc]
    socket.create_connection = _Blocked  # type: ignore[assignment]

    # --- no process spawning from the child ---
    subprocess.Popen = _Blocked  # type: ignore[assignment]
    subprocess.run = _Blocked  # type: ignore[assignment]
    os.system = lambda *a, **k: (_ for _ in ()).throw(
        PermissionError("os.system is blocked by sandbox policy"))
    os.execv = lambda *a, **k: (_ for _ in ()).throw(
        PermissionError("os.exec* is blocked by sandbox policy"))

    # --- filesystem write guard: writes only inside scratch ---
    _real_open = builtins.open

    def _guarded_open(file, mode="r", *args, **kwargs):  # noqa: ANN001
        if any(m in mode for m in ("w", "a", "x", "+")):
            p = Path(str(file)).resolve()
            try:
                p.relative_to(scratch)
            except ValueError:
                raise PermissionError(
                    f"write outside job scratch is blocked: {p}") from None
        return _real_open(file, mode, *args, **kwargs)

    builtins.open = _guarded_open  # type: ignore[assignment]

    # --- POSIX soft resource caps (best effort; Windows enforced by Job Objects) ---
    if _HAS_RESOURCE:
        try:
            resource.setrlimit(resource.RLIMIT_AS, (1 << 30, 1 << 30))      # 1 GiB
            resource.setrlimit(resource.RLIMIT_CPU, (60, 65))               # 60s CPU
            resource.setrlimit(resource.RLIMIT_FSIZE, (256 << 20, 256 << 20))
            resource.setrlimit(resource.RLIMIT_NPROC, (16, 16))
        except (ValueError, OSError, AttributeError):
            pass  # hardened environment: fall back to host-side enforcement only


# ---------------------------------------------------------------- task handlers
def _task_analyze(data: bytes, task: dict) -> dict:
    """Run pure REkt analyzers over the artifact bytes passed in."""
    import rekt.core.analyzer as analyzer
    import rekt.core.flagfinder as flagfinder

    out: dict = analyzer.quick_identify(data)
    if data[:2] == b"MZ":
        pe = analyzer.parse_pe(data)
        if pe:
            out["format"] = "PE"
            out["arch"] = pe["machine"]
            out["sections"] = pe["sections"]
            out["imports"] = pe["imports"]
            out["packer_hints"] = analyzer.detect_packer_heuristic(data, pe)
    elif data[:4] == b"\x7fELF":
        elf = analyzer.parse_elf(data)
        if elf:
            out.update(format="ELF", arch=elf["machine"], nsections=elf["nsections"])
    out["flags"] = flagfinder.find_flags(data)
    out["interesting"] = flagfinder.find_interesting_strings(data)
    out["entropy_series"] = analyzer.entropy_profile(data)
    return out


def _task_recipe(data: bytes, task: dict) -> dict:
    """Run a recipe pipeline (list of op specs) over the input bytes."""
    import rekt.core.encodings as enc

    steps = task.get("steps", [])
    if len(steps) > 100:
        raise ValueError("recipe too long (max 100 steps)")
    log = []
    for i, step in enumerate(steps):
        name = step.get("op", "")
        if step.get("risk") == "EXEC":
            raise PermissionError(f"step {i} ({name}): EXEC-class ops are refused")
        fn = enc.OPS.get(name) or enc.KEYED_OPS.get(name)
        if fn is None:
            raise ValueError(f"step {i}: unknown op {name!r}")
        if name in enc.KEYED_OPS:
            key = step["key"]
            if isinstance(key, str):
                key = key.encode("utf-8")
            data = fn(data, key)
        else:
            data = fn(data)
        log.append({"step": i, "op": name, "size": len(data)})
    return {"result": data.decode("utf-8", "replace") if len(data) < 1_000_000
            else f"<{len(data)} bytes>", "log": log}


def _task_disasm(data: bytes, task: dict) -> dict:
    """Disassemble inside the sandbox (Capstone; hostile bytes never parse in the GUI)."""
    import rekt.core.disasm as disasm

    arch = task.get("arch") or "x86-64"
    bits = int(task.get("bits") or 64)
    mode = task.get("mode", "recursive")
    rows = disasm.entry_disasm(data, arch, bits, mode)
    return {"rows": rows[:10_000], "entry_rva": disasm.pe_entry_rva(data),
            "arch": arch, "mode": mode, "count": len(rows),
            "payload_len": len(data), "capstone": disasm._HAS_CAPSTONE}


def _task_yara(data: bytes, task: dict) -> dict:
    """Match yaralite rule sources (passed inline, validated) over the payload."""
    import rekt.core.yaralite as yl

    matches = []
    rule_errors = []
    for i, src in enumerate(task.get("rules", [])[:64]):
        try:
            rules = yl.parse_rules(src[:256 * 1024], f"<source {i}>")
        except yl.RuleError as e:
            rule_errors.append(str(e)[:200])
            continue
        matches.extend(yl.scan_bytes(rules, data))
    return {"matches": matches[:256], "rule_errors": rule_errors[:32]}


_TASKS = {"analyze": _task_analyze, "recipe": _task_recipe, "disasm": _task_disasm,
          "yara": _task_yara}


def run(cfg_json: str) -> int:
    """Execute one sandbox task from a JSON config. Used directly when frozen."""
    cfg = json.loads(cfg_json)
    scratch = Path(cfg["scratch"])
    scratch.mkdir(parents=True, exist_ok=True)
    install_guards(scratch)

    # Frozen/windowed executables have no usable stdio: reply + payload go via
    # files in the job scratch dir. Dev mode additionally uses stdout.
    reply_path = Path(cfg["reply"]) if cfg.get("reply") else None
    payload_path = Path(cfg["payload"]) if cfg.get("payload") else None

    def _reply(obj: dict) -> None:
        blob = json.dumps(obj)
        if reply_path is not None:
            try:
                reply_path.write_text(blob, encoding="utf-8")
            except OSError:
                pass
        if sys.stdout is not None:  # None in windowed/frozen builds
            sys.stdout.write(blob)

    try:
        task = cfg.get("task") or {}
        handler = _TASKS.get(task.get("task"))
        if handler is None:
            raise ValueError(f"unknown task {task.get('task')!r}")
        if payload_path is not None and payload_path.exists():
            data = payload_path.read_bytes()
        else:
            data = sys.stdin.buffer.read()  # dev-mode fallback (DEVNULL => empty)
        result = handler(data, task)
        _reply({"ok": True, "result": result})
        return 0
    except Exception as e:  # noqa: BLE001 — child must always answer with JSON
        _reply({"ok": False, "error": f"{type(e).__name__}: {e}"})
        return 1


def main() -> int:
    return run(sys.argv[1])


if __name__ == "__main__":
    sys.exit(main())
