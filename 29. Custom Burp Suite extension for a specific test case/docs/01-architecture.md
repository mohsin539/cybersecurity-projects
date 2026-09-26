# 01 — System Architecture

**Document status:** Baseline | **Owner:** Application Security Engineering
**Scope:** BurpTester — a custom Burp Suite extension for a *specific test case*,
packaged as a GUI-based, portable `.exe` solution.
**Compliance alignment:** ISO/IEC 27001:2022 · NIST SP 800-53 · OWASP Top 10 · OWASP WSTG

---

## 1. Goals & Non-Goals

### Goals
- Execute a **single, well-defined OWASP WSTG test case** (reference module: **WSTG-SESS-10 — JWT / Sessions**), with the architecture intentionally leaving room to add new test cases as pluggable modules.
- Deeply integrate with **Burp Suite Professional** via the **Montoya API** (Java 17+), driving Proxy intercepts, Repeater requests, and the scanner.
- Present a **portable `.exe`** GUI that bundles its own minimal runtime — zero client-side install; runs from a thumb drive on a locked-down analyst workstation if needed.
- Deliver **compliance-grade artifacts**: SBOM, signed binaries, audit logs, control mapping reports.
- **Fail closed:** never alter production traffic except inside the isolated Burp proxy where the operator chooses to forward requests.

### Non-Goals
- No multi-user server, no cloud sync, no exfiltration channel.
- No persistence of credentials or session secrets on disk.
- No generic full-scope scanner — the tool is deliberately *scoped to one test case at a time* (per acceptance criterion of the parent project).

---

## 2. System Context (C4 — Level 1)

```
                 ┌──────────────────────────────┐
    Analyst ───► │  BurpTester Portable .EXE    │
   (GUI user)    │  - JavaFX Dashboard          │──┐
                 │  - Config, results, reports  │  │ HTTPS/JSON-RPC (loopback only)
                 └──────────────────────────────┘  │ same process (embedded JRE)
                                                    ▼
                 ┌──────────────────────────────┐
    Target web   │  Burp Suite Professional     │
    application  │◄────────────────────────────►│
                 │  Proxy / Repeater / Scanner  │
                 └──────────────────────────────┘
                    ▲                            ▲
                    │ sendToBurpTester            │ reload config / broadcast findings
                    │ (context menu → test)      │
                 ┌──┴────────────────────────────┴──┐
                 │      BurpTester Extension        │
                 │  (loaded into Burp, Montoya API) │
                 └──────────────────────────────────┘
```

**Interaction rules**
- The `.exe` and Burp run on the **same host**. All IPC is **loopback** (`127.0.0.1`, no
  other interfaces bound) over a local JSON-RPC WebSocket with a per-session random token.
- The extension is **passive by default**; it only transforms a request when the analyst
  explicitly invokes a test (context menu, Repeater tab, or scanner-defined scope).
- Findings are never routed to the internet.

---

## 3. Component View (C4 — Level 2)

```
                        ┌───────────────────────── PORTABLE EXE ─────────────────────────┐
                        │  gui-launcher (JavaFX)                                        │
                        │  ┌──────────────┐ ┌──────────────┐ ┌───────────────────────┐  │
                        │  │ Dashboard UI │ │ Config Editor│ │ Report Viewer + Export│  │
                        │  └──────┬───────┘ └──────┬───────┘ └───────────┬───────────┘  │
                        │         │                 │                      │             │
                        │  ┌──────▼─────────────────▼──────────────────────▼──────────┐ │
                        │  │  Launcher Core  (JSON-RPC client · token · TLS)          │ │
                        │  └──────▲───────────────────────────────────────────────────┘ │
                        │         │ loopback WebSocket (127.0.0.1, per-run token)       │
                        └─────────┼─────────────────────────────────────────────────────┘
                                  │
┌─────────────────────────────────┼──────────────────── BURP SUITE ─────────────────────┐
│                                 ▼                                                      │
│  burp-extension (Montoya API)                                                          │
│  ┌─────────────────────────────────────────────────────────────────────────────────┐   │
│  │  ExtensionEntryPoint (register listeners)                                      │   │
│  │   ├─ ContextMenuProvider  ──► "Send to BurpTester"                             │   │
│  │   ├─ HttpRequestHandler    ──► scope filter (host, path, method)               │   │
│  │   ├─ ScannerCheck          ──► feeds test packs when scanner runs              │   │
│  │   └─ UiPanel (in-Burp minimal console for headless fact-check)                 │   │
│  └─────────────────────────────────────────────────────────────────────────────────┘   │
│  ┌───────────────┐   ┌──────────────────────┐   ┌──────────────────────────────────┐  │
│  │ TestCaseEngine│──►│ TestPack SPI         │──►│ Finding model + Severity         │  │
│  │ (frontier)    │   │ └ JwtTokenTestPack   │   │ (WSTG ID, cvss-style score,      │  │
│  └───────────────┘   │   └ checks/…         │   │  evidence, remediation)          │  │
│                      └──────────────────────┘   └──────────────────────────────────┘  │
│  ┌──────────────────────────────┐   ┌──────────────────────────────────────────────┐  │
│  │ SafeExecutionSandbox         │   │ ConfigStore + AuditLog (local, key-protected)│  │
│  │ (timeouts, payload allowlist,│   └──────────────────────────────────────────────┘  │
│  │  "dry-run mode" especially   │                                                      │
│  │  for destructive payloads)   │                                                      │
│  └──────────────────────────────┘                                                      │
└──────────────────────────────────────────────────────────────────────────────────────┘
```

### 3.1 Components — detail table

| # | Component | Responsibility | Key interface |
|---|---|---|---|
| C1 | **Launcher Core** (gui-launcher) | Process lifecycle, loopback IPC, config sync, report aggregation | `LauncherApi` (local) |
| C2 | **Dashboard UI** | Live status: test progress, findings stream, severity counters | JavaFX FXML |
| C3 | **Config Editor** | Profile editor (targets, payloads, thresholds) saved as signable file | JSON schema |
| C4 | **Report / Export** | JSON + HTML (OWASP-style) + CSV evidence export | `ReportBuilder` |
| C5 | **ExtensionEntryPoint** | Mounts Montoya listeners; defines extension metadata | `MontoyaApi` |
| C6 | **TestCaseEngine** | Orchestrates a test run; applies policy (scope, rate, dry-run) | `TestCase` SPI |
| C7 | **TestPack** SPI | Pluggable per-test-case unit; **JwtTokenTestPack** = reference implementation | `TestCase`, `TestStep` |
| C8 | **Finding model** | Normalized findings: WSTG ID, severity, CVSS–like score, evidence | `Finding` |
| C9 | **SafeExecutionSandbox** | Guards mutation: timeouts, delays, payload budget, dry-run flag | — |
| C10 | **ConfigStore + AuditLog** | Immutable audit trail (append-only, hash-chained) | `AuditLog` |

---

## 4. Architectural Styles

- **Plugin/SPI architecture** for test cases (open–closed principle): adding a new test
  case = implement `TestCase` + register in a manifest, no core changes.
- **Hexagonal (Ports & Adapters)** for the extension core: Burp is an *adapter* behind a
  `BurpPorts` seam so the engine is unit-testable outside Burp.
- **Event-driven** inside Burp: packets flow through listeners; findings published on an
  in-process event bus the GUI subscribes to via IPC.
- **Release-engineering:** portable `.exe` is a **jlink minimal runtime image +
  JavaFX app + bundled extension jar**, wrapped by launch4j/wix and code-signed.

---

## 5. Data Flow — Normal Test Execution

```
 Analyst selects target request in Burp Repeater
   │  Context menu → "BurpTester → Run: JWT WSTG-SESS-10"
   ▼
 C5 EntryPoint captures request (host/path/method/headers/body)
   │  policy gate: is host in scope? is dry-run set? token budget OK?
   ▼
 C6 TestCaseEngine → C7 JwtTokenTestPack
   │  1. If Authorization: Bearer detected → parse + structurally validate JWT
   │  2. Step chain (each bounded by sandbox timeouts):
   │       - alg: "none" injection
   │       - RS256→HS256 key-confusion
   │       - signature stripping / tampered payload
   │       - expiry & nbf boundary tests
   │       - token replay / swap across users (requires 2 supplied tokens)
   │  3. Each step sends mutated request via Burp.HttpTransport (isolated)
   │  4. Response analyzed by check adapters → confirm/disprove
   ▼
 C8 Finding normalization (wstgId=SESS-10, severity, evidence, remediation)
   │  ▓ audit entry written: {step, requestId, hash, result, ts}
   ▼
 EventBus → Launcher Core (loopback) → Dashboard stream + Report export
```

---

## 6. Configuration Model

- **Profiles** (`profile.json`) — signable: `id`, `name`, `targetScope`,
  `testCaseRefs[]`, `policy{dryRun, maxRate, payloadBudget, followRedirects}`,
  `auth{tokenPoolRef|null}`.
- **Schema-validated** (JSON Schema in `resources/schemas/`) on load at both ends; schema
  version drift is rejected (fail-closed).
- **Secrets never persist.** Tokens used for testing are held in memory only and can be
  flagged `ephemeral` → wiped at run end.

---

## 7. Reporting & Interop

| Artifact | Format | Consumer |
|---|---|---|
| Console findings | JSON Lines (`findings.ndjson`) | Splunk/QRadar/any SIEM via local forwarder |
| Executive report | HTML (OWASP Report Generator style) | Management |
| Evidence pack | ZIP (requests + responses w/ hashes) | Audit / legal |
| Compliance matrix | Markdown/CSV from docs/02 | Risk & compliance team |

Every finding carries the **WSTG test ID + evidence hash chain** so an auditor can
reproduce any claim.

---

## 8. Quality, Testability & CI/CD

- **Test pyramid:** unit (JUnit 5) → integration (embedded Burp API stubs) → E2E
  (spawns the `.exe`, drives a local `vuln-app` fixture with a deliberately
  misconfigured JWT endpoint).
- **CI (GitHub Actions):** build → unit+integration → vulnerability scan (Gradle
  dependency audit) → SBOM generation (CycloneDX) → Dockerized E2E against `vuln-app` →
  signing gate.
- **Sign-off gates** map to ISO 27001 A.8.28 (SDLC) and NIST SI-2/SI-10.

---

## 9. Key Architectural Decisions (ADR summary)

| ADR | Decision | Rationale |
|---|---|---|
| ADR-1 | Java 17 + Montoya API (not legacy `IBurpExtender`) | Supported, typed, active backlog; legacy API deprecated |
| ADR-2 | JavaFX + jlink for the `.exe` | One runtime for extension+GUI; small image; cryptographically signable; ISO-friendly SBOM |
| ADR-3 | Test cases as pluggable `TestCase` modules | One specific case today, extensible without core churn |
| ADR-4 | Loopback JSON-RPC, never a listening port | Minimal attack surface on the analyst host |
| ADR-5 | Append-only hash-chained audit log | Tamper-evidence required by ISO 27001 A.8.15 & NIST AU-3 |
| ADR-6 | Dry-run default for "active" payloads | OWASP Top 10 A03/ A05-safe: evidence of intent before mutation |

---

## 10. Runtime / Deployment Shapes

| Shape | Where | Contents |
|---|---|---|
| **A. Portable `.exe`** (primary) | Analyst workstation / thumb drive | jlink image + JavaFX GUI + signed extension jar + bundled JRE |
| **B. In-Burp jar** | Burp Suite Pro "Extensions" | Just `burp-extension-<ver>.jar` for teams without the GUI |
| **C. CI container** | GitLab/GitHub runner | Headless jar; results to market-level artifacts |

All shapes produce byte-identical findings logic (single source of truth: the engine).