# Architecture: API Call Sequence Visualizer for a Sample's Behavior

**Document ID:** ACSV-ARCH-001
**Version:** 1.0
**Classification:** Internal — Security Sensitive
**Status:** Draft for Review
**Date:** 2026-09-22

---

## 1. Executive Summary

A **portable, standalone Windows executable (.exe)** that executes or observes a target sample in an isolated runtime, captures its **API call sequence** (user-mode Win32/NT API, system calls, network and file I/O events), and renders the behavior as an **interactive, colorful timeline/graph visualization**. The solution ships with:

- A **modern, colorful GUI** (timeline swimlanes, call graph, heatmaps, dependency tree).
- **Comprehensive report generation & download** (PDF, HTML, JSON, CSV, STIX 2.1).
- **Audit-ready architecture** — tamper-evident logging and pluggable audit subsystem reserved for future multi-user/SOC integration.
- Security controls aligned with **ISO/IEC 27001:2022**, **NIST CSF 2.0 / SP 800-53**, and **OWASP Top 10 (2021)**.

---

## 2. Goals & Non-Goals

### 2.1 Goals
| # | Goal | Priority |
|---|------|----------|
| G1 | Portable single-file `.exe` (no installer, no admin required for UI layer) | P0 |
| G2 | Capture ordered API call sequences with timestamps, thread IDs, args, return values | P0 |
| G3 | Interactive visualization: timeline, sequence graph, swimlanes, heatmap | P0 |
| G4 | One-click comprehensive report download (multi-format) | P0 |
| G5 | Security-framework control mapping baked into design | P0 |
| G6 | Audit subsystem scaffolding (append-only, hash-chained logs) ready for future RBAC/SIEM | P1 |
| G7 | Offline-first operation (no cloud dependency; air-gap capable) | P0 |
| G8 | Safe handling of untrusted samples (isolation, hashing, no accidental execution) | P0 |

### 2.2 Non-Goals
- Full kernel driver development (v1 uses user-mode hooking + ETW + sandbox orchestration).
- Malware classification/AV verdicts (behavior visualization only; verdict fields are pluggable).
- Cross-platform capture (Windows host target in v1; UI/report engine is portable).

---

## 3. Solution Overview

```
┌─────────────────────────────────────────────────────────────────────────┐
│                     PORTABLE PACKAGE (ACSV.exe)                        │
│  ┌───────────────────────────────────────────────────────────────────┐  │
│  │                    PRESENTATION LAYER (GUI)                      │  │
│  │   Dashboard · Timeline · Sequence Graph · Heatmap · Reports ·    │  │
│  │   Audit Viewer · Settings · Framework Compliance Console         │  │
│  └────────────────────────────▲──────────────────────────────────────┘  │
│                               │ IPC (in-proc / named pipe + schema)    │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │                      APPLICATION LAYER                           │  │
│  │  Session Orchestrator · Analysis Engine · Report Engine ·        │  │
│  │  Audit Service · Compliance Mapping Service · Config/Policy      │  │
│  └────────────────────────────▲──────────────────────────────────────┘  │
│                               │                                        │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │                        DATA LAYER                                │  │
│  │  Event Store (SQLite WAL) · Artifact Vault · Audit Log (append)  │  │
│  │  Report Cache · Schema Registry · Secret/Key Store (DPAPI)       │  │
│  └────────────────────────────▲──────────────────────────────────────┘  │
│                               │                                        │
│  ┌────────────────────────────┴──────────────────────────────────────┐  │
│  │                    CAPTURE / INGEST LAYER                        │  │
│  │  ETW Consumer · User-mode Hook Engine · Sandbox Runner ·        │  │
│  │  Procmon/API-Monitor Importer · Sample Intake & Hashing         │  │
│  └────────────────────────────▲──────────────────────────────────────┘  │
└───────────────────────────────┼─────────────────────────────────────────┘
                                │ events (ordered, timestamped)
                    ┌───────────┴───────────┐
                    │   TARGET SAMPLE (in   │
                    │  isolated execution   │
                    │   container / VM)     │
                    └───────────────────────┘
```

---

## 4. Technology Stack (Recommended)

| Layer | Choice | Rationale |
|-------|--------|-----------|
| GUI framework | **Tauri 2 (Rust) + React/TypeScript frontend** OR **Python + PySide6** | Tauri → tiny portable .exe (~5–10 MB), web-quality colorful UI, low attack surface. PySide6 → fastest path to rich native widgets. |
| Visualization | **vis-network / vis-timeline** or **Sigma.js** (graph) + **D3.js** (heatmap) inside webview; or **pyqtgraph** if PySide6 | High-performance interactive rendering of 10⁵–10⁶ events. |
| Capture engine (native) | **Rust/C++ DLL**: ETW (Microsoft-Windows-Threat-Tracking, kernel process/thread/file/net providers) + user-mode IAT/EAT hooking (MinHook-style) injected into sandboxed child | Deterministic ordering, low overhead, no kernel driver needed in v1. |
| Orchestration / isolation | **Windows Sandbox** profile, or **Hyper-V isolated runner VM**, or restricted token + Job Object + AppContainer for low-risk triage | Sample never runs on host integrity level of the analyst UI. |
| Event store | **SQLite** (WAL mode) with batched inserts; Parquet export for large captures | Single-file portable DB, ACID, FTS5 for search. |
| Report engine | **Typst or LaTeX → PDF**, **Jinja2 → HTML**, plus JSON/CSV/STIX exporters | Offline, deterministic, pixel-stable reports. |
| Integrity | SHA-256 per artifact; HMAC/hash-chain on audit log; optional Ed25519 signing of reports | Non-repudiation for audit & compliance evidence. |
| Packaging | Tauri → single `.exe` + embedded resources; PyInstaller `--onefile` alternative; optional `resources/` sidecar folder for capture DLLs | Portable, no install, code-signable (Authenticode). |
| Config/policy | TOML/YAML policy file, validated with JSON Schema | Admin-controlled hardening (allowed APIs retention, redaction rules). |

**Portability contract:** the app must run from any path (USB/network drive), store data under `%LOCALAPPDATA%\ACSV` (or `./data` in portable mode), and require **no admin rights for UI/reporting** (admin/sandbox rights requested only when launching a capture session).

---

## 5. Module Architecture

### 5.1 Capture / Ingest Layer

```
Sample Intake ──► SHA-256/SSDEEP ──► Metadata DB ──► Sandbox Profile Selector
                                                        │
                    ┌───────────────────────────────────┘
                    ▼
        Session Orchestrator (start/stop/timeout/kill)
                    │
        ┌───────────┼──────────────┬──────────────────┐
        ▼           ▼              ▼                  ▼
   ETW Consumer  Hook Engine   Network Tap        Importers
   (kernel+user  (IAT/EAT/     (WinDivert/        (Procmon PML,
    providers)    inline hook   ETW DNS/TCPIP)      API Monitor XML,
                in child)                           JSON traces)
        └───────────┴──────────────┴──────────────────┘
                            │
                    Normalizer & Sequencer
                    (monotonic seq #, clock sync, thread merge)
                            │
                    Event Enricher
                    (API catalog: params, severity, OWASP/CWE tags)
                            │
                    Event Store (SQLite WAL, batched)
```

**Core event schema (normalized):**

```json
{
  "seq": 10482,
  "ts_ns": 1768901234567890123,
  "tid": 4712,
  "pid": 3320,
  "category": "File|Registry|Network|Process|Thread|Crypto|Memory|IPC|Exception",
  "api": "NtCreateFile",
  "module": "ntdll.dll",
  "args": { "ObjectName": "\\\\.\\pipe\\evil", "DesiredAccess": "0x12019f" },
  "ret": "0x0",
  "status": "SUCCESS",
  "caller_stack_hash": "sha256:...",
  "tags": ["OWASP-A05", "CWE-787"],
  "parent_seq": 10479
}
```

**Sequencing guarantees:**
- Global monotonic `seq` assigned at ingest (single-writer queue).
- Cross-source timestamp reconciliation via QPC baseline at session start.
- Parent/child correlation (`parent_seq`) for nested calls (e.g., `CreateFile` → `WriteFile` → `CloseHandle`).

### 5.2 Application Layer

| Service | Responsibility |
|---------|----------------|
| **Session Orchestrator** | Lifecycle of capture runs; timeouts; abort; sandbox provisioning; resource quotas. |
| **Analysis Engine** | Sequence pattern mining (TTP sequences, allowlist/denylist API chains), anomaly scoring, call-graph aggregation, thread interleaving analysis, statistics (top APIs, entropy of sequence). |
| **Report Engine** | Composes findings → templated reports; multi-format export; report hash + signature. |
| **Audit Service** | Append-only, hash-chained audit events (who/what/when/from-where); retention; export for SIEM (CEF/LEEF/JSON). **Scaffolded now, full UI in v1.1.** |
| **Compliance Mapping Service** | Maps each control/finding to ISO 27001 Annex A IDs, NIST CSF/SP 800-53 control IDs, OWASP Top 10 categories; produces coverage matrix. |
| **Policy/Config Service** | Loads hardening policy; validates against schema; enforces redaction, retention, allowed actions. |
| **Crypto/Integrity Service** | Hashing, HMAC chaining, optional signing, DPAPI-protected secrets. |

### 5.3 Data Layer

- **Event Store:** SQLite WAL; tables `samples`, `sessions`, `events`, `call_graph_edges`, `artifacts`, `reports`, `audit_log`, `policy_snapshots`.
- **Artifact Vault:** raw capture files, dumps, screenshots — content-addressed (`sha256/aa/bb/...`), ACL-restricted.
- **Audit Log:** append-only table + optional mirrored `.jsonl` with chain: `entry_hash = SHA256(prev_hash || entry_payload)`.
- **Report Cache:** rendered reports keyed by `report_id + template_version + filter_hash`.
- **Schema Registry:** JSON Schema for events, reports, audit entries — versioned migrations.

### 5.4 Presentation Layer (GUI Design)

**Design language:** dark cyber-theme with vibrant accents (cyan `#22d3ee`, violet `#a78bfa`, amber `#fbbf24`, rose `#fb7185`, emerald `#34d399`); glassmorphism cards; smooth transitions; accessible contrast (WCAG 2.1 AA).

**Screens:**

1. **Dashboard** — session cards, sample hashes, live event counter, quick-start capture wizard, recent reports.
2. **Sample Intake** — drag-drop sample, hash verification, metadata enrichment, risk banner.
3. **Timeline View (core)** — horizontal time axis; **swimlanes per thread/process**; color-coded events by category; zoom/pan; brush-select range → filtered detail; playhead animation of sequence playback.
4. **Sequence Graph** — directed call-graph (`CreateProcess → VirtualAllocEx → WriteProcessThread → CreateRemoteThread`), node = API, edge = temporal adjacency; thickness = frequency; Community detection for grouping.
5. **Heatmap** — API-category × time-bucket matrix; thread × API frequency grid.
6. **Detail Inspector** — full args, return status, stack (if captured), enrichment tags, related events.
7. **Report Studio** — template picker, section toggles, framework scope (ISO/NIST/OWASP), preview, **Download** (PDF/HTML/JSON/CSV/STIX), report history.
8. **Compliance Console** — coverage matrix heatmap: rows = controls, cols = evidence findings; gaps highlighted.
9. **Audit Viewer** *(scaffold v1, full in v1.1)* — audit chain viewer, integrity verification button, export.
10. **Settings** — retention, redaction, sandbox profile, theme accent color, portable-mode data location.

**Interaction principles:** keyboard shortcuts, command palette (Ctrl+K), filter chips, virtualized lists for 10⁶ events, WebGL canvas for large graphs.

---

## 6. Data Flow (Sequence Diagram)

```
Analyst        GUI          Orchestrator      Capture Engine     Event Store     Report Engine
  │  drop sample │              │                   │                │               │
  │─────────────►│  intake req  │                   │                │               │
  │              │─────────────►│  hash+policy      │                │               │
  │              │              │──────────────────►│ (hash sample)  │               │
  │              │              │◄── sample_meta ───│                │               │
  │  start run   │              │                   │                │               │
  │─────────────►│─────────────►│  provision sandbox│                │               │
  │              │              │──────────────────►│  spawn+hook    │               │
  │  live events │              │                   │──events───────►│ (seq, WAL)    │
  │◄─────────────│◄── subscribe ─│◄── stream ────────│                │               │
  │  stop/timeout│              │  teardown+seal    │                │               │
  │─────────────►│─────────────►│──────────────────►│                │               │
  │              │              │  finalize session │                │──commit──────►│
  │  open report │              │                   │                │               │
  │─────────────►│─────────────►│──────────────────────────────────────────────────►│
  │              │              │                   │    build from filters + templates
  │  download    │              │                   │                │  ◄─ report blob+hash
  │◄─────────────│◄─ file save ─│                   │                │               │
  │              │  audit(ACTION_REPORT_DOWNLOAD) ──►│ Audit Service │               │
```

---

## 7. Comprehensive Report & Download Function

### 7.1 Report Contents (template sections)

1. **Cover** — title, report ID, classification banner, generation time, tool version.
2. **Executive Summary** — sample metadata (name, SHA-256, size, type, first/last seen), session context, top findings, risk score.
3. **Methodology** — capture method (ETW/hook), duration, environment, limitations.
4. **API Call Statistics** — counts by category/module, unique APIs, calls/sec, top-20 tables.
5. **Sequence Narrative** — ordered highlighted behavior chain with timestamps; thread swimlane snapshots.
6. **Call Graph Appendix** — rendered graph image + edge list.
7. **Detailed Event Table** — filterable appendix (paginated; full JSON attachment).
8. **Findings & Anomalies** — each finding: description, severity, evidence `seq` ranges, mapped controls.
9. **Compliance Mapping** — ISO 27001 Annex A / NIST / OWASP coverage matrix + gap list.
10. **Integrity & Provenance** — SHA-256 of report, hash of event-set snapshot, policy snapshot ID, signer info (if signed).
11. **Appendices** — raw artifacts index, glossary, control references.

### 7.2 Export Formats

| Format | Use | Notes |
|--------|-----|-------|
| **PDF** | Formal audit evidence | Typst/LaTeX, embedded fonts, classification header/footer, optional digital signature. |
| **HTML** | Interactive offline review | Self-contained single file with embedded JSON + JS viewer. |
| **JSON** | Machine integration / SOAR | Full schema-versioned dump incl. events + findings. |
| **CSV** | Analyst spreadsheet work | Flat event table, RFC 4180. |
| **STIX 2.1** | Threat intel sharing | Observables + behavior patterns as `observed-data` / `pattern`. |
| **SARIF** (optional) | Tool pipeline findings | For CI/SOC integration. |

### 7.3 Download Flow (security controls)

- Render → compute `report_sha256` → store in `reports` table → write to user-chosen path (Save dialog, path canonicalized, zip-slip/path-traversal guarded).
- **Audit event** written for every generate/preview/download action (actor, filters, format, hash).
- Optional: sign report with Ed25519 key from DPAPI-protected keystore → detached `.sig` sidecar.
- Large exports streamed (chunked) to avoid memory spikes; ZIP bundling for attachments.

---

## 8. Audit Functions (Current Scaffold + Future Roadmap)

### 8.1 Built-in from Day 1 (scaffold)
- **Append-only `audit_log`** with hash chain: `entry_hash = SHA256(prev_hash || canonical_json(entry))`.
- **Events audited:** login/session start (local), sample intake, capture start/stop/abort, policy change, report generate/download/delete, config change, integrity verification run, failed access attempts.
- **Integrity self-check** command: recompute chain, report tampering.
- **Export** audit slice to `audit-YYYYMM.jsonl` + manifest hash.

### 8.2 Future (v1.1+, architecture already supports)
- **RBAC** (Analyst / Reviewer / Admin roles), multi-user local accounts or LDAP/OIDC when networked.
- **SIEM streaming** — syslog/CEF/JSON over TLS to Splunk/Elastic/QRadar.
- **Retention & legal hold** policies per ISO 27001 A.5.33/A.8.15 (tamper protection, disposal).
- **Peer review workflow** — report sign-off states (Draft → Reviewed → Approved) with e-signature.
- **Time-synced audit + event correlation** view (shared clock domain, join on `ts_ns`).
- **Case management linkage** (ticket IDs on sessions/reports).

---

## 9. Security & Compliance Framework Integration

### 9.1 ISO/IEC 27001:2022 Mapping (Annex A controls — primary)

| Control ID | Control Name | How this architecture addresses it |
|------------|--------------|-----------------------------------|
| A.5.1 | Policies for information security | Central Policy/Config Service; policy snapshot per session embedded in reports. |
| A.5.7 | Threat intelligence | STIX export; behavior pattern sharing. |
| A.5.9 | Inventory of information and assets | Sample & artifact vault registry with hashes/metadata. |
| A.5.10 | Acceptable use of information and assets | Sample handling policy; no-execute-by-default; isolation requirement. |
| A.5.11 | Return of assets | Portable-mode data purge / secure wipe function. |
| A.5.12 | Classification of information | Report classification banners; sample sensitivity labels. |
| A.5.13 | Labelling of information | Embedded labels in report headers/footers and file metadata. |
| A.5.15 | Access control | Local RBAC scaffold; DPAPI secrets; least-privilege split (UI no-admin; capture elevated only in sandbox). |
| A.5.16 | Identity management | Future local accounts/OIDC; current session identity recorded in audit. |
| A.5.18 | Access rights | Role-based feature gating designed (reports vs. audit vs. settings). |
| A.5.20 | Information security in supplier relationships | Offline/air-gap operation; no third-party telemetry by default. |
| A.5.23 | Information security for cloud services | Cloud disabled by default; explicit opt-in only (out of scope for portable core). |
| A.5.24 | Information security incident management planning | Findings/severity model; incident-ready report format. |
| A.5.26 | Response to information security incidents | Behavior evidence as incident response input; export to IR tickets. |
| A.5.28 | Collection of evidence | Ordered, timestamped, hash-sealed event store; report provenance section; chain of custody fields. |
| A.5.29 | Information security during disruption | Portable exe on removable media; graceful degradation offline. |
| A.5.31 | Legal, statutory, regulatory and contractual | Dependency SBOM; license inventory in About dialog. |
| A.5.33 | Protection of records | Append-only audit + hash chain; retention policy config. |
| A.5.34 | Privacy and PII protection | Arg redaction rules (passwords, tokens, PII patterns) before persist. |
| A.5.36 | Compliance with policies | Compliance Console shows policy conformance per session. |
| A.5.37 | Documented operating procedures | This architecture document + user handbook section. |
| A.7.1 | Physical security (via media) | Portable media guidance; encryption-at-rest recommendation for data dir. |
| A.8.1 | User endpoint devices | Runs on analyst endpoint; no server dependency. |
| A.8.2 | Privileged access rights | Admin token requested only for capture provisioning (just-in-time). |
| A.8.5 | Secure authentication | Future RBAC; OS-level session binding now. |
| A.8.9 | Configuration management | Versioned schema + policy snapshots; reproducible builds. |
| A.8.15 | Logging | Dual logging: app audit log + capture events; separate stores, separate integrity. |
| A.8.16 | Monitoring activities | The product *is* a monitoring tool; self-monitoring via audit. |
| A.8.24 | Use of cryptography | SHA-256, HMAC chain, optional Ed25519, DPAPI at rest. |
| A.8.25 | Secure development lifecycle | Threat-model-driven design (§10); OWASP ASVS-aligned coding; SAST/DAST in CI. |
| A.8.26 | Application security requirements | Input validation via JSON Schema; no dynamic code eval; sandboxed renderer. |
| A.8.28 | Secure coding | Memory-safe Rust (or strict C++ hardening: CFG, ASLR, DEP, CET); banned unsafe patterns. |
| A.8.31 | Separation of development, test and production | Build profiles; capture engine vs. UI artifact separation. |
| A.8.32 | Change management | Semantic versioning; signed releases; changelog. |
| A.8.33 | Test information | Test fixtures are non-malicious corpora only. |
| A.8.34 | Protection of information systems during audit | Audit Viewer is read-only for Analyst role. |
| A.8.35 | Security audit testing | Integrity self-check; future pen-test hooks. |
| A.8.51 | Secure transfer of information | Report export uses local FS; future network transfer must use TLS 1.3. |

### 9.2 NIST Mapping

**NIST CSF 2.0 functions:**

| CSF Function | Implementation |
|--------------|----------------|
| **GOVERN** | Policy snapshots, role design, compliance matrix, documented ownership in report header. |
| **IDENTIFY** | Sample inventory, artifact registry, API surface enumeration of target behavior. |
| **PROTECT** | Isolation (sandbox), least privilege, DPAPI, redaction, secure coding (Rust/hardening). |
| **DETECT** | Core product: API sequence anomaly & TTP detection; self-audit chain verification. |
| **RESPOND** | Severity-rated findings, STIX/SARIF export, IR-ready evidence packages. |
| **RECOVER** | Portable re-deploy from single exe; data-dir re-init; report regeneration from sealed store. |

**NIST SP 800-53 Rev.5 selected controls:** AC-2/AC-3/AC-6, AU-2/AU-3/AU-9/AU-11, CM-2/CM-6, CP-9, IA-2, IR-4/IR-5, RA-5, SA-11/SA-15, SC-28 (encryption at rest for vault), SI-4, SR-3/SR-4 (supply chain/SBOM).

**NISTIR 8259 (IoT/device):** not directly applicable; device-facing capture adapters out of scope.

### 9.3 OWASP Top 10 (2021) — Application Risk Mapping

Applicable because the tool renders untrusted-derived data, embeds an HTML report viewer, and (future) may expose a local UI API.

| OWASP ID | Risk | Mitigation in architecture |
|----------|------|----------------------------|
| **A01 Broken Access Control** | Future multi-user / local HTTP debug endpoint | Deny-by-default RBAC; no unauthenticated IPC; capability tokens for internal API; path canonicalization on all file ops. |
| **A02 Cryptographic Failures** | Weak hashing, plaintext secrets | SHA-256/HMAC minimum; DPAPI keystore; TLS 1.3 mandated for any future network; no MD5/SHA1 as sole integrity. |
| **A03 Injection** | API args / sample strings injected into report HTML, SQL, shell | Parameterized SQL (SQLite prepared stmts only); HTML auto-escape + strict CSP in report viewer; never pass sample-derived strings to shell (use structured APIs); template sandboxing (no arbitrary Jinja from data). |
| **A04 Insecure Design** | Sample executed with host privileges | Default-deny execution; sandbox/AppContainer/VM isolation; threat model (§10) gates design reviews. |
| **A05 Security Misconfiguration** | Debug mode in release, permissive IPC ACL | Hardened defaults; release builds strip debug endpoints; schema-validated config; fail-closed. |
| **A06 Vulnerable Components** | Third-party libs in GUI stack | SBOM (CycloneDX) per release; dependency scanning (cargo-audit/npm audit) in CI; pinned lockfiles. |
| **A07 Identification & Auth Failures** | Shared workstation misuse | OS session binding in v1; future MFA-ready OIDC; session timeout on UI lock. |
| **A08 Software & Data Integrity Failures** | Tampered reports, poisoned captures | Hash-chain audit; report hashes + optional signature; signed release binaries; content-addressed vault. |
| **A09 Security Logging Failures** | Missing audit trails | Mandatory audit hooks on sensitive actions; separate, append-only, hash-chained store; SIEM export ready. |
| **A10 SSRF** | Future URL fetch features (e.g., module lookup) | Deny-by-default egress; URL allowlist; no server-side fetch of sample-controlled URLs. |

**Additional OWASP-aligned practices:** OWASP ASVS L2 target for local API; OWASP Top 10 for LLM not applicable (no LLM in v1); Cheat Sheet Series applied (secure headers, crypto, logging).

### 9.4 Threat Model Snapshot (STRIDE)

| Threat | Asset | Countermeasure |
|--------|-------|----------------|
| Tampering | Event store / audit log | Hash chain, WAL integrity, optional file ACL lock |
| Repudiation | Analyst actions | Append-only audit with actor identity + report hashes |
| Information disclosure | Sample contents, PII in args | Redaction policy, DPAPI vault, classification banners |
| Denial of service | Capture runaway | Timeouts, event caps, disk quotas, kill-switch |
| Elevation of privilege | Sample escaping sandbox | VM/Windows Sandbox isolation, no shared clipboard/folders, just-in-time admin |
| Spoofing | Forged report / IPC peer | Ed25519 signing, named-pipe ACL + peer PID verification |

---

## 10. Security Engineering Practices (SDL)

- Threat modeling per feature (STRIDE) before implementation; this document is the baseline.
- Code: Rust preferred for capture/UI shell; C++ only in hook shim with fuzzing + ASAN builds.
- CI gates: SAST (Semgrep/CodeQL), dependency audit, license check, SBOM generation, unit + integration tests with benign behavior corpora.
- Release: reproducible build, Authenticode signing, SHA-256 published alongside exe.
- Secure defaults: no auto-network, no telemetry, no auto-execution of dropped files.

---

## 11. Deployment & Portability Model

```
ACSV.exe                  # main portable binary (UI + app layer)
├── capture/              # sidecar DLLs/EXEs (hook engine, etw consumer)
├── templates/            # report templates (PDF/HTML)
├── schemas/              # JSON Schemas (events, reports, audit)
├── policies/default.toml # default hardened policy
└── README.txt            # portable usage

Data (portable mode):   ./data/           (writable dir next to exe)
Data (installed mode):  %LOCALAPPDATA%\ACSV\
```

- **Modes:** *Portable* (all state beside exe) vs *Managed* (`%LOCALAPPDATA%`).
- Elevate **only** when starting a capture (UAC just-in-time); UI/reporting runs unelevated.
- Single-instance mutex; file-association optional (`.acsvtrace`).

---

## 12. Performance & Scalability Targets

| Metric | Target |
|--------|--------|
| Event throughput (ingest) | ≥ 50,000 events/s sustained |
| GUI render (timeline) | 60 fps with 100k visible events (virtualized/WebGL) |
| Full capture size | Up to 5M events / 2 GB DB before forced segment rollover |
| Report generation (100k events) | ≤ 15 s to PDF preview |
| Cold start to dashboard | ≤ 2 s on reference hardware |

---

## 13. Testing Strategy

1. **Unit** — sequencer ordering invariants, hash-chain verification, redaction rules, path sanitization.
2. **Integration** — benign behavior corpus (known API scripts) → expected sequence snapshots (golden files).
3. **Fuzzing** — event parser (imported PML/XML/JSON), config loader, report template data binding.
4. **Security tests** — SQLi payloads in sample paths, HTML/script injection in API args, zip-slip on export, IPC spoofing attempt.
5. **Compliance tests** — control-mapping coverage tests (every finding maps to ≥1 ISO/NIST/OWASP tag).
6. **UI/UX** — accessibility checks (contrast, keyboard nav), large-dataset stress.

---

## 14. Roadmap

| Version | Scope |
|---------|-------|
| **v1.0** | Capture (ETW+hook), timeline/graph/heatmap GUI, event store, report engine (PDF/HTML/JSON/CSV), audit scaffold (hash chain), compliance mapping tables, portable exe. |
| **v1.1** | Audit Viewer UI, RBAC, report sign-off workflow, STIX/SARIF export, SIEM streaming. |
| **v1.2** | Advanced sequence analytics (ML-assisted anomaly), multi-sample diffing, case management links. |
| **v2.0** | Optional networked deployment (TLS 1.3, OIDC SSO), team collaboration, API server mode. |

---

## 15. Deliverable Checklist (build order)

1. [ ] Repo scaffold: UI shell + app services + data layer + capture stubs.
2. [ ] Event schema + JSON Schema registry + SQLite migrations.
3. [ ] Capture pipeline (ETW consumer first; hook engine second).
4. [ ] Timeline swimlane + detail inspector (MVP visualization).
5. [ ] Sequence graph + heatmap.
6. [ ] Report engine + download flow + report hashes.
7. [ ] Audit chain service + integrity self-check.
8. [ ] Compliance mapping data (ISO/NIST/OWASP tables) + Compliance Console.
9. [ ] Hardening pass (OWASP checklist), SBOM, signing, packaging → `ACSV.exe`.
10. [ ] Golden-corpus tests + performance validation + this document's control matrix verification.

---

## 16. Document Control

| Field | Value |
|-------|-------|
| Owner | Security Engineering |
| Review cycle | Quarterly, or on major release |
| Related docs | Data Processing Inventory, Threat Model TM-ACSV-001, SDL Checklist |
| Distribution | Internal — need-to-know |

*End of architecture document.*
