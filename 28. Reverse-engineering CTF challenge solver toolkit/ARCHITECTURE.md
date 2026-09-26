# CTF Reverse-Engineering Solver Toolkit — Architecture

**Product:** REkt (working name) — a GUI-based, portable, single-file Windows `.exe` toolkit for solving reverse-engineering CTF challenges.
**Version:** Architecture v1.0 (September 2026)
**Status:** Design / pre-implementation

---

## 1. Purpose & Scope

### 1.1 Problem Statement
CTF reverse-engineering challenges require juggling 6–10 disjoint tools (Ghidra, IDA Free, x64dbg, Detect It Easy, UPX, CyberChef, zsteg, strings, etc.). Each has its own UX, install burden, and update cycle. REkt consolidates the **80% workflow common to 90% of RE challenges** into one portable executable that runs from a USB stick with zero installation and zero admin rights.

### 1.2 In Scope (v1.0)
| Capability | Description |
|---|---|
| Static analysis | File identification, hash/fuzzy hashing, strings, entropy, imports, structure carving |
| Disassembly / decompilation | Bundled Capstone + Ghidra headless (via extension) |
| Dynamic analysis | Sandboxed execution, API tracing, strace-style logging |
| Unpacking / deobfuscation | UPX/PE-pack detection + auto-unwrap, script deobfuscation |
| Crypto detection | Entropy scan, magic detection of common ciphers/encodings, known-CTF cipher helpers |
| Encoding toolbox | Base16/32/64/85, XOR, ROT, charset transforms (CyberChef-style recipe chains) |
| Forensics / stego | PNG/JPEG/ZIP carving, LSB tools, metadata dump |
| Pwn helpers | Format-string scanner, ROP gadget finder (static), shellcode templates |
| Project files | Save/load analysis state (`*.rekt` archive) |
| Plugin system | Python scripts + signed native plugins |

### 1.3 Out of Scope (v1.0)
- Mobile (APK/IPA) RE — planned v2.x
- Kernel driver analysis / kernel debugging
- Multi-user / networked operation — the tool is strictly local, single-operator
- Any use as an EDR-evasion or offensive platform; see §11 Acceptable Use & Hardening

### 1.4 Non-Functional Requirements
| ID | Requirement | Target |
|---|---|---|
| NFR-1 | Portability | Single `.exe` ≤ 250 MB, runs from `%TEMP%`/USB, **no admin rights**, no registry writes, no services |
| NFR-2 | Cold start | UI interactive < 3 s on mid-range laptop (heavy backends lazy-loaded) |
| NFR-3 | Offline | 100% functionality offline; network calls opt-in only (update check) |
| NFR-4 | Safety | Untrusted sample execution only inside mandatory sandbox; deny-by-default |
| NFR-5 | Auditability | Every action logged to tamper-evident local audit log |
| NFR-6 | Clean removal | Exit removes all temp artifacts; documented forensic footprint |
| NFR-7 | Accessibility | Full keyboard operation, WCAG 2.1 AA contrast in shipped themes |
| NFR-8 | Licensing | All bundled components compatible (GPLv3 w/ exception caveats, BSD, MIT, Apache-2.0) — see §12 |

---

## 2. High-Level Architecture

```
┌─────────────────────────────────────────────────────────────────────────┐
│                        rekt.exe (portable host)                         │
│                                                                         │
│  ┌───────────────────────────────┐   ┌───────────────────────────────┐  │
│  │        PRESENTATION           │   │      APPLICATION SERVICES     │  │
│  │  Qt 6 / PySide6 desktop GUI   │◄─►│  Command Bus (signed cmds)    │  │
│  │  • Challenge dashboard        │   │  Job scheduler (QThreadPool)  │  │
│  │  • Analysis workbench (tabs)  │   │  Project/session store        │  │
│  │  • Hex/asm/decompiler panes   │   │  Recipe pipeline engine       │  │
│  │  • Recipe builder (CyberChef) │   │  Plugin manager (signed)      │  │
│  │  • Settings / policy UI       │   │  Policy engine (sandbox ACLs) │  │
│  └───────────────┬───────────────┘   └──────────────┬────────────────┘  │
│                  │ signals/slots (typed)            │ jobs              │
│  ┌───────────────▼──────────────────────────────────▼────────────────┐  │
│  │                       CORE ENGINE LAYER                           │  │
│  │  static_analyzer │ disasm (Capstone) │ decompiler (Ghidra bridge) │  │
│  │  dynamic_runner  │ unpacker │ crypto_detector │ stego │ carver    │  │
│  │  encoding_toolbox │ rop_finder │ report_builder                  │  │
│  └───────────────┬───────────────────────────────────────────────────┘  │
│                  │ isolated subprocesses (job process per sample)       │
│  ┌───────────────▼───────────────────────────────────────────────────┐  │
│  │                       SANDBOX LAYER (mandatory)                   │  │
│  │  Restricted token │ Job objects │ AppContainer fallback           │  │
│  │  Watchdog │ rsrc/CPU/net caps │ snapshot-restore (prjFS)          │  │
│  └───────────────┬───────────────────────────────────────────────────┘  │
│  ┌───────────────▼───────────────────────────────────────────────────┐  │
│  │                     PLATFORM / DATA LAYER                         │  │
│  │  Embedded CPython runtime │ stdlib-only bootstrap                 │  │
│  │  SQLite (projects, findings, audit) │ FS scratch (encrypted opt)  │  │
│  │  YARA rules engine │ sigstore/Trust-store for plugin verify       │  │
│  └───────────────────────────────────────────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────────────┘
```

**Layer rules (enforced by import-linter in CI):**
- Presentation → Application → Core → Sandbox → Platform. No upward imports.
- GUI never touches the sandbox or raw file APIs for untrusted content — it only exchanges typed job objects over the command bus.
- Every untrusted-artifact operation is a **job** in a **disposable process** with a **policy**.

---

## 3. Component Design

### 3.1 Portable Host & Bootstrap
```
rekt.exe  (PyInstaller --onedir zipped into a self-extractor, or Nuitka standalone)
├─ bootloader.exe        tiny C stub: integrity self-check → drops runtime to
│                        %LOCALAPPDATA%\rekt\runtime (AES-GCM-verified) → launches
├─ runtime/              embedded CPython 3.12 + stdlib (frozen, versioned)
├─ site-packages/        PySide6, capstone, pefile, yara-python, pyzipper, ...
├─ backends/
│   ├─ ghidra/           Ghidra headless (extension, downloaded on first use)
│   └─ gdb-server/       remote debug stub (opt-in)
├─ app/                  REkt python code (bytecode-frozen)
├─ rules/                YARA + magic + Heuristics (signed manifest)
└─ manifest.json         per-file SHA-256 + sigstore bundle (cosign)
```
- **Self-verification:** bootloader computes SHA-256 over `manifest.json` entries, verifies cosign signatures against a pinned trust root, aborts on mismatch (supply-chain control → NIST SSDF PW.4, ISO A.8.9).
- **No admin:** writes only to `%LOCALAPPDATA%\rekt` and per-project scratch dirs. A portable-mode flag redirects everything to `<usb>:\rekt-data` (NFR-1).

### 3.2 Command Bus & Job Model
```python
@dataclass(frozen=True, slots=True)
class Job:
    id: UUID
    kind: JobKind            # STATIC_SCAN | DYN_RUN | DECOMPILE | RECIPE | ...
    target: ArtifactRef      # sha256-addr in content store, never a raw path
    policy: PolicyRef        # mandatory; sandbox config resolved from this
    timeout_s: int           # hard cap, default 120
    resource_caps: Caps      # cpu_s, mem_mb, net: NONE, file_writes: scratch_only
```
- **Content-addressed artifact store** (`sha256 → blob`): dedup, tamper detection, and guarantees the sandbox operates on immutable copies.
- **Scheduler:** QThreadPool of N workers; one subprocess per dynamic job (process isolation; GUI crash-free even if the sample crashes the runner).
- All cross-layer messages are validated with `pydantic` (schema = trust boundary).

### 3.3 Static Analysis
- **Identify:** `libmagic` DB + custom YARA pack + entropy profile → type, packer, compiler, language guesses.
- **Strings/regex:** n-gram filter for flags (`flag{`, `CTF{`, base64/hex blobs), configurable per-event rule sets.
- **PE/ELF/Mach-O parsing:** pefile/lief — imports, TLS callbacks, sections, anomalies (high entropy `.text`, overlay data, weird entrypoints).
- **Disassembly:** Capstone (x86/x64/ARM/ARM64/MIPS) with recursive-descent traversal + CFG reconstruction.
- **Fuzzy diffing:** TLSH/ssdeep to compare sample variants across a CTF event.

### 3.4 Decompiler Bridge
- Ghidra headless runs in a **separate JVM process**, invoked via `analyzeHeadless` with a scripted post-processor exporting pseudo-C + call graph JSON.
- Lifecycle: lazy-download on first use (sigstore-verified zip), cached in `backends/ghidra`, killed on job timeout, JVM sandboxed by the same policy engine.
- Fallback (no-Java path): built-in pattern lifter producing "structured assembly" summaries.

### 3.5 Dynamic Runner (Sandbox) — the security core
Defense-in-depth, **all mandatory** for `DYN_RUN` jobs:
1. **Restricted process token** — `CreateProcessAsUser` with a stripped token (no `SeDebug`, no backup/restore privileges, low integrity).
2. **Job Object** — hard caps: CPU seconds, working-set MB, active-process count, UI restrictions (`JOB_OBJECT_UILIMIT_*`), kill-on-job-close.
3. **Filesystem virtualization** — copy-on-write overlay: writes land in per-job scratch; on job end, scratch is hashed, reported, and shredded. Real user files invisible via ACL deny-ACEs.
4. **Network deny-by-default** — Windows Filtering Platform (WFP) block filter scoped to the job's process ID; option to allow a fake/proxy DNS+HTTP sink for challenges that "call home" (emulated by in-proc mock server).
5. **AppContainer / WinTcb fallback** — where restricted tokens are insufficient (win11 AppContainer LPAC) as second isolation tier.
6. **Watchdog thread** in the host: heartbeats, deadline enforcement, CPU spike alarms; SIGKILL-equivalent `TerminateJobObject` on breach.
7. **Honest limitation** (documented in UI): user-mode sandbox ≠ VM. High-evasion malware is out of threat model for CTF use, but the doc + UI must say so (§11). Future: optional QEMU microVM runner behind the same `Policy` interface.

### 3.6 Recipe Pipeline Engine (CyberChef-like)
- DAG of named ops with typed inputs/outputs; ops implemented in pure Python, side-effect free, each op declaring a `RiskClass` (PURE / FS_READ / EXEC).
- `EXEC` ops require an explicit user confirmation modal + policy override recorded in the audit log (OWASP A01 misuse control).

### 3.7 Plugin System
```
plugin.toml (metadata) ──┐
plugin.py  (entry)     ──┼─► PluginManager ──► signature verify (sigstore) ──► load
plugin.sigbundle       ──┘
```
- **Allow-list model:** only signed plugins by trusted identities run by default; unsigned plugins require Developer Mode + per-session consent + banner.
- Plugins run **in-process** for pure ops, or as a job subprocess for anything touching samples (same sandbox).
- API surface is versioned (`rekt.plugin.api.v1`); semver-checked at load.

### 3.8 Persistence
- **SQLite** (WAL mode) for projects, findings, notes, audit log. Encrypted (SQLCipher) if user sets a project passphrase (AES-256-GCM, Argon2id KDF).
- **Project export** `.rekt` = zip of blobs + manifest, signed with the same trust root for team sharing.
- **Audit log**: append-only JSONL, each record `prev_hash` chained (tamper-evident), flushed to disk on every event; exportable for incident reports.

---

## 4. GUI Architecture

- **Framework:** PySide6 (Qt 6, LGPLv3 — dynamically linked, complies with LGPL for commercial/closed use).
- **Pattern:** MVVM. `ViewModel`s own state; `View`s are dumb; `Model` = Application Services via the command bus.
- **Layout:**
  - Challenge Dashboard (samples, tags, auto-findings, progress)
  - Workbench: tabbed panes — Hex (QHexView), Disassembly (custom QAbstractItemModel over Capstone), Decompiler (QPlainTextEdit w/ syntax theme), Strings, Entropy graph, Imports
  - Recipe Builder: op palette + pipeline canvas + live preview
  - Console / Job inspector (shows sandbox policy + stdout)
- **Threading:** Qt main thread never blocks; jobs emit `progress`/`done` signals. Long renders chunked.
- **i18n:** `gettext`; **L10N note:** language selection changes UI text only — technical enums and log formats stay English (mirrors conversation-language conventions).

---

## 5. Data Flow (sample lifecycle)

```
User drops file
   │ hash → artifact store (immutable copy)
   ▼
STATIC_SCAN job ──► findings (type, packer, strings, entropy, imports)
   │ user clicks "Run"
   ▼
DYN_RUN job (policy: sandbox) ──► API trace, dumps, scratch diff, net attempts
   │
   ▼
Findings pane ──► one-click recipes (XOR-brute, base-detect, zsteg)
   │
   ▼
Flag candidate detected ──► highlighted, hashed, logged
```

Every arrow writes an audit record: `{ts, actor=local_user, job_id, action, artifact_sha256, policy_id, outcome}`.

---

## 6. Compliance Mapping

> Compliance is engineered-in from day one, not bolted on. Each control cites the artifact that proves it.

### 6.1 OWASP Top 10 (2021) — application-security posture
| OWASP | Risk | Controls in REkt |
|---|---|---|
| **A01** Broken Access Control | Plugin/local privesc, sandbox escape | Deny-by-default policy engine; AppContainer + restricted token; no privileged APIs; plugins can't elevate (runs as low-IL); explicit consent modal for EXEC-class ops (§3.6, §3.7) |
| **A02** Cryptographic Failures | Weak crypto in project files / updates | AES-256-GCM for project encryption; Argon2id for passphrase KDF; TLS 1.3 only for update channel; cert pinning; no custom crypto (§3.8) |
| **A03** Injection | Command/file injection via sample names, recipe strings, plugin args | Parameterized SQL only; `shlex`-free process spawn (`CreateProcess` argv list, never a shell); strict pydantic schemas at every trust boundary; no `eval`/`exec` anywhere; lint-enforced (`bandit` B307/B602 rules in CI) |
| **A04** Insecure Design | Missing threat model | STRIDE doc (§7); mandatory-sandbox invariant tested in CI with "malicious challenge" test corpus |
| **A05** Security Misconfiguration | Insecure defaults | Secure-by-default policy profile; insecure flags require `--i-know-what-im-doing` CLI + persistent banner; config file signed; no debug endpoints in release build |
| **A06** Vulnerable Components | Supply chain | SBOM (CycloneDX) emitted per release; `pip-audit` + `osv-scanner` in CI; 30-day SLA to patch `HIGH+` transitive deps; pinned + hash-checked deps |
| **A07** Auth Failures | N/A (local tool) | Local project passphrase only; OS keychain (Credential Manager) for optional plugin-source tokens; auto-lock project after 15 min idle |
| **A08** Integrity Failures | Tampered updates/plugins | sigstore/cosign verification of runtime, backends, plugins; signed `.rekt` projects; SHA-256 manifest enforced by bootloader (§3.1) |
| **A09** Logging Failures | Missing forensic trail | Chained audit log (§3.8); log integrity self-check on startup; no PII/sample-content in logs by default — only hashes |
| **A10** SSRF | Update/plugin endpoints | Update URL pinned + allow-listed; no user-supplied URLs fetched; plugin registry is a local index, network fetch requires explicit consent |

### 6.2 NIST
| Framework | Controls |
|---|---|
| **SP 800-218 (SSDF)** | PO.1 threat model (§7); PW.4 integrity verification (§3.1); PW.7 compiler/options hardening (`/GS`, `DYNAMICBASE`, `CFG` on any C; Python `PYTHONSAFEPATH`, frozen bytecode); PS.1 SBOM + dependency scanning (§6.1 A06); PS.2 signed releases + reproducible-build target; RV.1 disclosed-vuln intake (`security.md` + GitHub Private Vulnerability Reporting) |
| **SP 800-53 Rev.5 (selected, relevant-to-tool)** | AC-3 (sandbox ACLs), AC-6 (least privilege — no admin), AU-2/AU-9 (audit log + integrity), CM-5 (signed plugins), CM-7 (least functionality — disabled unused subsystems), SC-3 (process isolation), SC-8 (TLS 1.3), SC-13 (FIPS-validated primitives preferred where available: AES-GCM, SHA-256, Argon2id), SI-2 (patch SLA), SI-7 (integrity verification) |
| **CSF 2.0** | GOVERN (threat model, acceptable-use policy §11), IDENTIFY (SBOM, asset inventory of bundled components), PROTECT (sandbox, signed code, least privilege), DETECT (audit log, watchdog, anomaly telemetry opt-in), RESPOND (vuln disclosure process, kill-switch update channel), RECOVER (portable → no state to recover; re-download verified runtime) |

### 6.3 ISO/IEC 27001:2022 — Annex A (relevant subset for a shipped tool)
| Annex A | Control | Implementation |
|---|---|---|
| A.5.23 | Cloud/service security | N/A — no backend; documented "no telemetry by default" |
| A.8.9 | Configuration management | Signed config, manifest verification |
| A.8.16 | Monitoring | Watchdog + audit log; local anomaly visibility |
| A.8.24 | Use of cryptography | §3.8, §6.1 A02; algorithm allow-list in `crypto_policy.toml` |
| A.8.25 | Secure development lifecycle | SSDF-aligned CI gates (lint, SAST, SCA, sandbox tests) |
| A.8.28 | Secure coding | Bandit/ruff security ruleset, code-review requirement, CODEOWNERS on sandbox/* |
| A.8.29 | Security testing | Adversarial test corpus + fuzzing (§8) |
| A.8.30 | Outsourced development | Plugin ecosystem governance: signing, review queue, registry takedown process |
| A.8.31 | Separation of test/prod | Separate signing keys for dev/release; dev builds visually watermarked |

### 6.4 OWASP ASVS 4.0 (targeting L2 for the local-app sections)
Mapped in `compliance/asvs-mapping.csv` — auto-generated in CI; failing rows block release.

---

## 7. Threat Model (STRIDE, abbreviated)

| Element | Threat | Mitigation |
|---|---|---|
| Sample (untrusted) | Sandbox escape, host compromise | Multi-tier sandbox §3.5, watchdog, honest-limitation UI warning, optional VM backend |
| Sample | Exploit GUI parser (path, name, crafted archive) | Content-addressed store, fuzzed parsers, `zip-bomb`/`png-bomb` guards (size/depth caps), pydantic on every boundary |
| Update channel | Malicious runtime drop | sigstore pinning, TLS 1.3 + pinning, staged rollout, rollback signature |
| Plugin | Malicious plugin | Signed allow-list, API surface versioning, job-sandbox for sample-touching ops, review queue |
| Local attacker | Steal project secrets / flags | SQLCipher optional, OS keychain, auto-lock, scratch shredding |
| Insider/CI | Compromised build | Reproducible builds, cosign attestation in CI, protected release branch, 2-person review on `sandbox/*` |
| User misuse | Running REkt against production/unknown-malware | Prominent scope warning on first run, EULA, telemetry-free but opt-in "sample class" prompt that tightens sandbox |

---

## 8. Testing & Verification Strategy
| Layer | Technique |
|---|---|
| Unit | pytest, ≥85% line coverage on `core/`, 100% on `sandbox/policy.py` |
| Property-based | hypothesis for recipe ops (round-trip encode/decode) |
| Fuzzing | AFL++-style harness (via `atheris` for Python parsers) on PE/ELF/PNG/ZIP parsers — 24h soak pre-release |
| Adversarial corpus | 30 curated "naughty" challenges (zip bombs, path-traversal archives, Unicode-name files, crafted PE headers, sandbox-probe binaries) — CI must contain, never crash, never write outside scratch |
| Sandbox regression | Automated tests assert: network blocked, file writes land in scratch, CPU cap enforced, process tree killed on timeout |
| E2E | PyTest-QT driving the GUI against a fixed challenge pack, golden findings |
| Security review | Pre-release: `bandit`, `pip-audit`, `osv-scanner`, `semgrep` custom rules for `eval/exec/subprocess-shell/yaml.load` |
| Supply chain | SBOM diff on every PR; new dep requires a signed ADR |

---

## 9. Packaging & Distribution

1. **Build:** `pyinstaller --onedir` (NOT `--onefile` — avoids AV-flagged self-extract temps and speeds cold start) inside a pinned Docker image → **reproducible build**; zip the dir with the manifest; ship `.zip` + a tiny `rekt.exe` stub that self-extracts to `%LOCALAPPDATA%` on first run (portable mode: `--portable` keeps everything on the stick).
2. **Signing:** Authenticode EV certificate (SmartScreen reputation); cosign attestation of the zip; GitHub Release with SHA-256SUMS file.
3. **Updates:** Sparkle-style delta updater; opt-in check; signatures verified before swap; atomic replace via rename.
4. **AV false-positive plan:** publish SBOM + reproducible-build instructions + VirusTotal signed-submitter program; document in `docs/av-whitelisting.md`.

---

## 10. Repository Layout

```
rekt/
├─ bootloader/          C stub (integrity check, launcher)
├─ app/
│  ├─ presentation/     Qt views, themes, i18n
│  ├─ application/      command bus, jobs, recipes, plugins, policy engine
│  ├─ core/             analyzers, disasm, crypto, stego, carver
│  ├─ sandbox/          token/job/wfp/appcontainer, watchdog  ← CODEOWNERS-protected
│  └─ platform/         store, audit, crypto, updater
├─ backends/            ghidra bridge, vm-runner (future)
├─ rules/               yara, magic, heuristics (signed)
├─ plugins/             first-party signed plugins
├─ tests/               unit, adversarial corpus, e2e, fuzz harnesses
├─ compliance/          asvs-mapping.csv, SSDF evidence, ISO SoA-lite, SBOM templates
├─ docs/                threat-model.md, acceptable-use.md, av-whitelisting.md, ADRs/
└─ .github/workflows/   ci.yml (lint+SAST+SCA), release.yml (sign+SBOM+repro)
```

---

## 11. Acceptable Use & Hardening Statement
REkt is dual-use. The design takes these positions:
1. **Scope warning** on first launch + in docs: intended for **authorized** CTF/education use.
2. No bundled capability exists to obfuscate, pack, or evade defenses (i.e., it is analysis-only, not a packer).
3. Sandbox defaults are the **strictest safe profile**; loosening requires per-session, logged consent.
4. Vulnerability disclosure: `SECURITY.md`, 90-day coordinated timeline, Private Vulnerability Reporting enabled.
5. Honest documentation of sandbox limits (user-mode ≠ VM) with a pointer to the optional VM backend.

---

## 12. Licensing Matrix (excerpt)
| Component | License | Bundling note |
|---|---|---|
| PySide6 / Qt 6 | LGPLv3 | Dynamic link, provide relink instructions + license text in `licenses/` |
| Ghidra | Apache-2.0 | Clean |
| Capstone | BSD-3 | Clean |
| pefile, yara-python | MIT/Apache-2.0 | Clean |
| UPX | GPLv2+ | Invoked as separate binary, not linked — OK |
| Embedded CPython | PSF | Clean |

`licenses/` ships the full texts + a generated `THIRD-PARTY-NOTICES.md` (CI-enforced on dependency change).

---

## 13. Roadmap
| Milestone | Scope |
|---|---|
| M0 (4 wk) | Skeleton host, command bus, static analyzer, hex view, project store |
| M1 (6 wk) | Sandbox v1 (token+job), dynamic runner, strings/entropy, recipe engine |
| M2 (6 wk) | Ghidra bridge, decompiler pane, unpacker, YARA rules, plugin API v1 |
| M3 (4 wk) | Compliance hardening sprint — ASVS L2 audit, fuzz soak, reproducible build, signed release 1.0 |
| v2.x | VM backend, mobile RE, collaborative `.rekt` sharing, LLM hint engine (opt-in, local model) |

---

*Owner: Architecture WG · Review cadence: quarterly · Next review: 2026-12-19*
