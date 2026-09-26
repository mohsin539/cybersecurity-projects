# MEMORY.md — Durable Engineering Memory

> Read this first in any future session working on REkt. It encodes decisions,
> protocol contracts, and platform traps that are NOT obvious from the code.

## 1. Identity & doctrine

- **Product:** REkt — portable, GUI, single-operator RE/CTF solver (Windows-first).
- **Doctrine:** deny-by-default everything; fail-closed on enforcement errors; honest about sandbox limits; analysis-first (never execute samples in v1.x).
- **Layer rule (import-linter someday):** presentation → application → core/sandbox → platform. No upward imports. The GUI never touches sample bytes — only the JobService does.
- **Compliance is code:** every OWASP/NIST/ISO control in ARCHITECTURE.md §6 maps to a concrete module; when you touch those modules, re-check the mapping.

## 2. Protocol contracts (do not break silently)

### 2.1 Host ↔ child (sandbox) protocol
- `runner.run_job()` → argv: `rekt.exe --rekt-sandbox-child <json>` (frozen) or `python child.py <json>` (source).
- JSON keys: `scratch`, `policy` (Policy.to_json), `task`, `payload` (path), `reply` (path).
- Payload bytes go via **file** (`scratch/payload.bin`); result via **file** (`scratch/reply.json`). Rationale: windowed/frozen builds have **no stdio** (`sys.stdout is None`, `CREATE_NO_WINDOW`, pipes unreliable). stdin/stdout remains the dev fallback only.
- Child must ALWAYS write a reply, even on exception (`_reply()` in child.py). Host treats missing/invalid JSON as `child crashed`.

### 2.2 Job kinds & consent
- `ANALYSIS` — allowed freely; `SAMPLE_EXEC` — requires `allow_exec=True` + Developer Mode + per-session consent (`check_consent`); `GHIDRA` — requires per-session consent only (user-confirmed dialog, audited `job.ghidra`). Adding a new JobKind? Extend `check_consent` too.
- Child disasm task replies carry `payload_len` + `capstone` diagnostics — if `payload_len` ≠ input size, suspect path/cwd issues (§3 first bullet) before doubting the analyzers.
- `Policy` invariants raise on: `allow_network=True`, `allow_write_outside_scratch=True`, `timeout_s` out of [5,3600], `max_memory_mb` out of [64,8192]. These are deliberate tripwires — do not relax without updating SECURITY.md §3.

### 2.3 Audit records
- Actions used so far: `session.start`, `session.end`, `session.dev_mode`, `sample.added`, `sample.viewed`, `job.analysis`, `job.recipe`, `plugin.unsigned_loaded`, `plugin.op`, `consent.sample_exec`. Keep them grep-able; hash-chained via `AuditLog`.

## 3. Platform traps (Windows) — read before touching sandbox/spawn code

- **ABSOLUTE scratch paths are mandatory** (hard-won regression): the child runs with `cwd=scratch_dir`; any RELATIVE path inside the child cfg (payload/reply) resolves against the child's cwd and silently falls back to empty stdin (`payload_len=0`, ok=true, count=0). `run_job()` now calls `Path(scratch_dir).resolve()` — keep it. Pytest never caught it because `tmp_path` is absolute; only a GUI session with a relative `--data-dir` reproduced it.
- **from-imports defeat monkeypatch spies**: `jobs.py` does `from rekt.sandbox.runner import run_job`, so patching `rekt.sandbox.runner.run_job` does nothing for jobs.py. To observe, patch `rekt.application.jobs.run_job`.
- **QMessageBox in offscreen tests blocks forever** — auto-answer via class-level staticmethod patches in any GUI test harness.
- **Windows path names reject trailing spaces** — `mkdir("tag ")` strips them and later `open` fails with FileNotFoundError; don't pad test tags used as dir names.
- **No `resource` module** on Windows — child.py imports it inside try/except; Job Objects provide the hard caps.
- **Job Object assignment must happen immediately** after `Popen`, before `communicate()`; else a fast child could finish unsandboxed. We fail closed on assignment failure.
- **`Affinity` field** in JOBOBJECT_BASIC_LIMIT_INFORMATION must be `c_size_t` on 64-bit — using `POINTER` corrupts struct size and `SetInformationJobObject` fails silently.
- **`subprocess.CREATE_NO_WINDOW`** + `stdin=DEVNULL` for children; never `shell=True` (OWASP A03; bandit S-rules enforce).
- **PyInstaller frozen mode:** `sys.executable` is `rekt.exe`, NOT python — that's why the `--rekt-sandbox-child` self-dispatch exists in `__main__`. Any new frozen child type must follow the same pattern.
- **`QFont("Consolas")`** exists on Windows; keep `setStyleHint(Monospace)` fallback for other OSes.

## 4. Build & test recipes

- Tests: `python -m pytest tests/ -q` (41 green as of snapshot; e2e sandbox tests spawn real children — keep them fast, they're the security regression net).
- Headless GUI: `QT_QPA_PLATFORM=offscreen` (verified working on this box).
- Build: `python scripts/build_exe.py` → `dist/rekt-portable/` (onedir, windowed, no UPX, bundles `rules/`, `plugins/`, empty `trust.pub`).
- **After changing child.py or runner.py:** rerun the frozen-child test pattern from STATE.md §2 (spawn `dist/rekt-portable/rekt.exe --rekt-sandbox-child` with a flag payload) — a rebuild is required since the exe embeds the old code.

## 4b. Trust workflow (current state)

- `scripts/sign_plugin.py keygen` → `trust.pub` (public, ship it) + `trust.key` (private, git-ignored, never ship).
- `scripts/sign_plugin.py sign plugins/<name>` → `plugin.sig` (Ed25519 over plugin.toml+plugin.py bytes).
- `plugins/suspicious_strings` is SIGNED and loads without Developer Mode.
- `build_exe.py` copies `trust.pub` into `dist/rekt-portable/_internal/trust.pub`; frozen trust lookup is `_internal/trust.pub` (parents[2] of the frozen module). Env `REKT_TRUST_ED25519` overrides.
- Rule: any change to `plugin.toml` or `plugin.py` INVALIDATES `plugin.sig` — re-run `sign` after edits.

## 5. Deliberate non-decisions (don't "fix" without discussion)

- **No telemetry, ever** — `Config.validate()` hard-raises. Don't add collectors.
- **No `shell=True`, no `eval/exec`, no yaml.load** anywhere — ruff S-rules in pyproject enforce; exceptions need an ADR.
- **No network fetch** in v1.x — Ghidra bridge (M2) will need one: design it as explicit, pinned, signed, consent-gated per ARCHITECTURE.md §3.4.
- **UPX deliberately NOT used on the build** (AV false positives, §9.4) even though UPX-detection is a feature.
- **SQLite, not JSON files**, for findings — WAL mode, thread-locked; keep parameterized queries only.

## 6. Pointers

- Architecture & control mappings: `ARCHITECTURE.md`
- Security invariants & disclosure: `SECURITY.md`
- Current state & verified facts: `STATE.md` (refresh this file + STATE.md at the end of any significant session)
- Threat model (STRIDE): ARCHITECTURE.md §7 · Roadmap: §13
