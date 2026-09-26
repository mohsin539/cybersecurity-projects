"""Job service: the only path from the GUI to untrusted content (ARCHITECTURE.md §3.2).

Every job: mandatory Policy -> disposable sandboxed child -> store + audit record.
The GUI never touches sample bytes directly; it exchanges job ids and results.
"""
from __future__ import annotations

import json
import uuid
from pathlib import Path

from rekt.sandbox.policy import check_consent

from rekt.platform.audit import AuditLog
from rekt.platform.store import ProjectStore
from rekt.sandbox.policy import JobKind, Policy, RiskClass
from rekt.sandbox.runner import JobResult, run_job

MAX_ANALYZE_BYTES = 64 * 1024 * 1024  # matches config max_file_mb cap (A04)


class GhidraUnavailable(RuntimeError):
    pass


class JobService:
    def __init__(self, store: ProjectStore, audit: AuditLog, scratch_root: Path) -> None:
        self.store = store
        self.audit = audit
        self.scratch_root = scratch_root

    # ---------------------------------------------------------------- analysis
    def run_analysis(self, sha: str, data: bytes) -> JobResult:
        """Static analysis of one artifact inside the sandbox."""
        if len(data) > MAX_ANALYZE_BYTES:
            return JobResult(False, "artifact exceeds analysis cap (64 MiB)")
        policy = Policy(kind=JobKind.ANALYSIS, timeout_s=120)
        job_id = self.store.job_start("ANALYSIS", sha, policy.to_json())
        result = run_job(policy, {"task": "analyze"}, data,
                         self.scratch_root / job_id)
        self.store.job_end(job_id, "ok" if result.ok else result.detail[:120])
        self._record_findings(sha, result)
        self.audit.append("job.analysis", job_id=job_id, artifact=sha,
                          ok=result.ok, killed=result.killed,
                          duration_s=result.duration_s)
        return result

    # ---------------------------------------------------------------- recipes
    def run_recipe(self, data: bytes, steps: list[dict], label: str = "recipe") -> JobResult:
        """Run a validated recipe pipeline inside the sandbox (never in the GUI)."""
        steps = self.validate_steps(steps)
        if isinstance(steps, str):
            return JobResult(False, steps)
        policy = Policy(kind=JobKind.ANALYSIS, timeout_s=60)
        sha = self.store.sha256(b"recipe:" + json.dumps(steps, sort_keys=True).encode())
        job_id = self.store.job_start("RECIPE", sha, policy.to_json())
        result = run_job(policy, {"task": "recipe", "steps": steps}, data,
                         self.scratch_root / job_id)
        self.store.job_end(job_id, "ok" if result.ok else result.detail[:120])
        self.audit.append("job.recipe", job_id=job_id, label=label,
                          steps=len(steps), ok=result.ok)
        return result

    @staticmethod
    def validate_steps(steps: list[dict]) -> list[dict] | str:
        """Strict step validation at the trust boundary (OWASP A03)."""
        if not isinstance(steps, list) or not steps:
            return "recipe must be a non-empty list of steps"
        if len(steps) > 100:
            return "recipe too long (max 100 steps)"
        import rekt.core.encodings as enc

        clean: list[dict] = []
        for i, s in enumerate(steps):
            if not isinstance(s, dict) or "op" not in s:
                return f"step {i}: malformed"
            name = s["op"]
            if name in enc.KEYED_OPS:
                key = s.get("key", "")
                if not isinstance(key, str) or not key:
                    return f"step {i}: {name} requires a key"
                clean.append({"op": name, "key": key, "risk": RiskClass.PURE.value})
            elif name in enc.OPS:
                clean.append({"op": name, "risk": RiskClass.PURE.value})
            else:
                return f"step {i}: unknown op {name!r}"
        return clean

    # ---------------------------------------------------------------- disasm
    def run_disasm(self, sha: str, data: bytes, arch: str = "x86-64", bits: int = 64,
                   mode: str = "recursive") -> JobResult:
        """Disassemble in the sandboxed child; rows returned to the GUI pane."""
        if len(data) > MAX_ANALYZE_BYTES:
            return JobResult(False, "artifact exceeds analysis cap (64 MiB)")
        if not data:
            return JobResult(False, "empty artifact — nothing to disassemble")
        policy = Policy(kind=JobKind.ANALYSIS, timeout_s=120)
        job_id = self.store.job_start("DISASM", sha, policy.to_json())
        task = {"task": "disasm", "arch": arch, "bits": bits, "mode": mode}
        result = run_job(policy, task, data, self.scratch_root / job_id)
        if result.ok and isinstance(result.result, dict) and result.result.get("count") == 0:
            diag = result.result
            result = JobResult(False,
                               "disassembler produced 0 rows "
                               f"(capstone_in_child={diag.get('capstone')}, "
                               f"payload_len={diag.get('payload_len')}, "
                               f"arch={diag.get('arch')}, mode={diag.get('mode')})",
                               duration_s=result.duration_s)
        self.store.job_end(job_id, "ok" if result.ok else result.detail[:120])
        self.audit.append("job.disasm", job_id=job_id, artifact=sha, mode=mode,
                          arch=arch, ok=result.ok)
        return result

    # ---------------------------------------------------------------- ghidra
    def run_ghidra(self, sha: str, data: bytes, ghidra_home: str,
                   session_consents: set[str], timeout_s: int = 600) -> JobResult:
        """Consent-gated Ghidra headless decompilation of a scratch COPY.

        Runs OUTSIDE the sandbox child (Ghidra is a trusted JVM tool) but still:
        consent -> audit -> scratch copy -> hard timeout -> bounded output.
        """
        from rekt.application import ghidra

        policy = Policy(kind=JobKind.GHIDRA, timeout_s=timeout_s)
        reason = check_consent(policy, developer_mode=True, session_consents=session_consents)
        if reason:
            return JobResult(False, reason)
        home = ghidra.find_ghidra_from_path(ghidra_home)
        if home is None:
            raise GhidraUnavailable("Ghidra not found (set REKT_GHIDRA_HOME or pick the install root)")
        job_id = self.store.job_start("GHIDRA", sha, policy.to_json())
        scratch = self.scratch_root / job_id
        scratch.mkdir(parents=True, exist_ok=True)
        copy = scratch / "sample_copy.bin"   # never hand Ghidra the original
        copy.write_bytes(data)
        ok, text, index = ghidra.run_headless(home, copy, scratch, timeout_s)
        self.store.job_end(job_id, "ok" if ok else "failed")
        self.audit.append("job.ghidra", job_id=job_id, artifact=sha, ok=ok)
        if not ok:
            return JobResult(False, text)
        return JobResult(True, "decompiled", result={"text": text, "functions": index},
                         duration_s=0.0)

    # ---------------------------------------------------------------- yara
    def run_yara(self, sha: str, data: bytes, rule_sources: list[str] | None = None,
                 use_bundled: bool = True) -> JobResult:
        """Yara-lite scan inside the sandbox. Sources: bundled rules/rekt.yar
        (from the frozen bundle) + any user-provided rule texts."""
        from pathlib import Path
        import sys

        sources: list[str] = []
        if use_bundled:
            if getattr(sys, "frozen", False):
                base = Path(getattr(sys, "_MEIPASS", "")) / "rules"
            else:
                base = Path(__file__).resolve().parents[2] / "rules"
            p = base / "rekt.yar"
            if p.exists():
                sources.append(p.read_text(encoding="utf-8"))
        sources.extend((rule_sources or [])[:16])
        policy = Policy(kind=JobKind.ANALYSIS, timeout_s=60)
        job_id = self.store.job_start("YARA", sha, policy.to_json())
        result = run_job(policy, {"task": "yara", "rules": sources}, data,
                         self.scratch_root / job_id)
        self.store.job_end(job_id, "ok" if result.ok else result.detail[:120])
        if result.ok:
            for m in (result.result or {}).get("matches", [])[:32]:
                self.store.add_finding(sha, "yara", m["rule"],
                                       "; ".join(f"{x['string']}@{x['offsets'][:3]}"
                                                 for x in m["matches"])[:300])
        self.audit.append("job.yara", job_id=job_id, artifact=sha, ok=result.ok,
                          matches=len((result.result or {}).get("matches", [])))
        return result

    # ---------------------------------------------------------------- unpack
    def run_unpack(self, sha: str, data: bytes, tool: str = "upx") -> JobResult:
        """Static unpack attempt via a trusted external tool on a scratch COPY."""
        from rekt.application import trusted_tools

        policy = Policy(kind=JobKind.ANALYSIS, timeout_s=120)
        job_id = self.store.job_start("UNPACK", sha, policy.to_json())
        scratch = self.scratch_root / job_id
        scratch.mkdir(parents=True, exist_ok=True)
        copy = scratch / "sample_copy.bin"
        copy.write_bytes(data)
        if tool == "upx":
            out_bytes, log = trusted_tools.upx_decompress(copy, scratch)
        else:
            out_bytes, log = b"", f"unknown tool {tool!r}"
        result = JobResult(bool(out_bytes), log or ("unpacked" if out_bytes else "no output"),
                           result={"log": log,
                                   "unpacked_sha256": self.store.sha256(out_bytes)
                                   if out_bytes else None})
        if out_bytes:
            new_sha = result.result["unpacked_sha256"]
            self.store.put_blob(new_sha, out_bytes)
            self.store.add_artifact(out_bytes, note=f"unpacked({tool}) of {sha[:12]}")
        self.store.job_end(job_id, "ok" if result.ok else result.detail[:120])
        self.audit.append("job.unpack", job_id=job_id, artifact=sha, tool=tool,
                          ok=result.ok)
        return result

    # ---------------------------------------------------------------- helpers
    def _record_findings(self, sha: str, result: JobResult) -> None:
        if not result.ok or not result.result:
            return
        for flag in result.result.get("flags", [])[:50]:
            self.store.add_finding(sha, "static", "flag",
                                   f"{flag['rule']} @0x{flag['offset']:x}: {flag['value']}")
        for kind, items in (("hint", result.result.get("packer_hints", [])),
                            ("interesting", result.result.get("interesting", []))):
            for item in items[:50]:
                detail = item if isinstance(item, str) else json.dumps(item)[:300]
                self.store.add_finding(sha, "static", kind, detail)
