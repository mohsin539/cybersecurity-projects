# VulnLab Sentinel — Custom Metasploit Module & Lab Console

> **A portable, web-based penetration-testing console for a lab-only deliberately vulnerable
> service, driven by a custom Metasploit module, with compliance-aligned reporting
> (OWASP Top 10, NIST CSF / SP 800-115, ISO/IEC 27001).**

```
┌──────────────────────────────────────────────────────────────────────────────┐
│                          LAB-ONLY  /  AIR-GAPPED USE                          │
└──────────────────────────────────────────────────────────────────────────────┘
```

---

## 1. Executive Overview

| Attribute          | Value                                                                  |
|--------------------|------------------------------------------------------------------------|
| Product name       | **VulnLab Sentinel**                                                    |
| Packaging          | **Single portable `.exe`** (web-based, self-hosted)                     |
| Interface          | Browser-based dashboard on `http://127.0.0.1:<port>`                     |
| Runtime            | Python backend + embedded web app, bundled via PyInstaller              |
| Target             | Deliberately vulnerable **lab-only** service (custom TCP/HTTP)          |
| Engine             | Metasploit Framework over **MSGRPC** (JSON-RPC)                          |
| Custom module      | `exploit/.../vulnlab_<service>.rb` — loaded from a custom module path   |
| Enforcements       | OWASP Top 10 (2021), NIST CSF v2.0 + SP 800-115, ISO/IEC 27001:2022     |
| Report formats     | `.xlsx`, `.csv`, `.html` (HTML = executive + technical single-file)      |
| Governance gates   | Scope gate, consent gate, lab eligibility gate (see §7)                 |

**Core value chain:**

```
ENTERPRISE LAB → VULNERABLE SERVICE → CUSTOM MODULE → METASPLOIT RPC →
ANALYSIS ENGINE → COMPLIANCE MAPPER → REPORT ENGINE → XLSX / CSV / HTML
```

---

## 2. High-Level Architecture

```
┌──────────────────────────────  PORTABLE .EXE  ───────────────────────────────┐
│                                                                               │
│  ┌─────────────────────────────────────────────────────────────────────┐      │
│  │  PRESENTATION LAYER  (Web UI — served locally, no internet needed)  │      │
│  │  Single-page dashboard: Dashboard · Targets · Run Module ·           │      │
│  │  Findings · Compliance Map · Reports · Module Console · Settings     │      │
│  └───────────────┬─────────────────────────────────────────────────────┘      │
│                  │ HTTP/REST over loopback (127.0.0.1)                       │
│  ┌───────────────▼─────────────────────────────────────────────────────┐      │
│  │  APPLICATION LAYER  (FastAPI / Flask + async orchestrator)          │      │
│  │  · Session manager          · Scope / consent governance gate       │      │
│  │  · Scan orchestration       · Finding normalizer                    │      │
│  │  · Compliance mapper (OWASP/NIST/ISO) · Runtime watchdog            │      │
│  └──────┬───────────────────────────────┬─────────────────────────────┘      │
│         │                               │                                     │
│  ┌──────▼───────────────┐      ┌────────▼──────────────────────────┐          │
│  │  INTEGRATION LAYER   │      │  DATA LAYER  (embedded SQLite)    │          │
│  │  MSGRPC JSON-RPC     │      │  · targets.db · findings.db       │          │
│  │  client (pymetasploit│      │  · modules.db · reports.db        │          │
│  │  3 / raw)            │      │  · compliance_evidence.db         │          │
│  └──────┬───────────────┘      └───────────────────────────────────┘          │
│         │ TCP 127.0.0.1:55553 (msgrpc)                                        │
│  ┌──────▼─────────────────────────────────────────────────────────────┐      │
│  │  METASPLOIT BRIDGE (daemon/console adapter)                        │      │
│  │  · Launch msfconsole -m ./modules (custom module path)             │      │
│  │  · load msgrpc ServerHost=127.0.0.1 ServerPort=55553               │      │
│  │  · Status probe, session listing, logs ingestion                   │      │
│  └──────┬─────────────────────────────────────────────────────────────┘      │
│         │                                                                RPC │
│  ┌──────▼─────────────────────────────────────────────────────────────┐      │
│  │  METASPLOIT FRAMEWORK  (bundled / system install)                  │      │
│  │  ┌─────────────────────┐  ┌─────────────────────────────────────┐  │      │
│  │  │ CUSTOM MODULE       │  │ CORE EXPLOIT / AUX / POST LIBRARY  │  │      │
│  │  │ exploit/lab/vulnlab │  │ encoders · payloads · evasions      │  │      │
│  │  └─────────────────────┘  └─────────────────────────────────────┘  │      │
│  └──────┬─────────────────────────────────────────────────────────────┘      │
│         │ network                                                             │
│  ┌──────▼─────────────────────────────────────────────────────────────┐      │
│  │  LAB TARGET  — deliberately vulnerable service                      │      │
│  │  TCP service w/ weak auth, injection, buffer overflow sink, ...     │      │
│  └─────────────────────────────────────────────────────────────────────┘      │
└──────────────────────────────────────────────────────────────────────────────┘

  REPORT PIPELINE (post run) ─────────────────────────────────────────────
  Raw findings → normalized Finding records → compliance mapper
  → templated export:  .xlsx (openpyxl, color-coded) · .csv (flat) · .html (Jinja2)
```

---

## 3. Component Breakdown

### 3.1 Presentation Layer — Single-Page Dashboard
- **Tech:** static Vue/React build (bundled, no CDN) + local REST client.
- **Views:**
  1. **Dashboard** — live stats, radar chart of OWASP categories, severity donut.
  2. **Targets** — add/edit lab hosts, mark **in-scope** with written justification.
  3. **Run Module** — configure module options RPORT/RHOST/SSL..., payload selection.
  4. **Module Console** — live streaming `print_status`/`print_good` output over WebSocket/SSE.
  5. **Findings** — severity-sorted table; drill-down to evidence payloads & remediations.
  6. **Compliance Map** — OWASP / NIST / ISO evidence grid (finding ⇄ control).
  7. **Reports** — generate `.xlsx` / `.csv` / `.html` and download.
  8. **Settings** — MSGRPC credentials, module path, audit log, lab guard (safe mode).
- **Security of the UI:** loopback-bound only, per-session bearer token, no remote content,
  all MIME types allow-listed (defense against browser-based SSRF / prototype pollution in the tool itself).

### 3.2 Application Layer — Orchestrator & Governance
| Module                 | Responsibility                                                                 |
|------------------------|--------------------------------------------------------------------------------|
| `ScopeGate`           | Blocks targets not tagged **lab-only**; refuses public/private-range IPs        |
| `ConsentGate`         | Requires explicit "authorized lab" attestation saved to an audit trail          |
| `ScanOrchestrator`    | Serial/parallel job queue, timeout caps, retry policy, session cleanup          |
| `FindingNormalizer`   | Dedupes + maps raw module output → structured `<Finding>` (CVSS v3.1 base)      |
| `ComplianceMapper`    | Tags each finding with OWASP:2021, NIST 800-115 / CSF, ISO 27001:2022 Annex A   |
| `RuntimeWatchdog`     | Kills orphan sessions, enforces max job duration, logs every RPC call           |
| `AuditLog`            | Immutable append-only log (integrity hashed) of all actions                      |

### 3.3 Integration Layer — MSGRPC
- Adapter supports **two transports**, auto-detected:
  1. `msfrpcd` standalone daemon (`-P <pass> -S` HTTPS), and
  2. In-console `load msgrpc ServerHost=127.0.0.1 ServerPort=55553 Pass=<pass>`.
- **Controls exercised:** `console.create`, `console.write/read` (streaming module output),
  `module.info`, `module.execute`, `session.list`, `session.meterpreter_*`, `db.*`.
- **Safety:** the adapter runs **without payloads by default** in `info`/`check`/`verify`
  modes; `exploit` (with payload) requires an explicit user confirmation in the UI.

### 3.4 Custom Metasploit Module (the deliverable)
Path: `modules/exploits/lab/vulnlab_<service>_x.py` → implement as `.rb`:

```ruby
class MetasploitModule < Msf::Exploit::Remote
  Rank = RankantManually
  include Msf::Exploit::Remote::Tcp

  def initialize(info = {})
    super(update_info(info,
      'Name'        => 'VulnLab Deliberate Service Exploit',
      'Description' => 'Lab-only proof-of-concept exploit against the deliberately
                        vulnerable VulnLab service. Never run outside an
                        isolated lab network.',
      'License'     => MSF_LICENSE,
      'Author'      => ['Lab Team'],
      'References'  => [['URL', 'https://owasp.org/www-project-top-ten/']],
      'DefaultOptions' => { 'SSL' => false },
      'Targets' => [['Windows x64 (DLL Injection)', {}],
                    ['Linux x64 (Execute)', {}]],
      'Payload' => { 'DefaultOptions' => { 'SRVHOST' => '127.0.0.1' } }))

    register_options([
      Opt::RPORT(1337),
      OptString.new('FLAG_MODE', [true, 'norm | auth | inject | overflow'])
    ])
  end
```

- Loaded with `msfconsole -m <exe_dir>/modules`.
- **Check method:** `check` must be implemented (never `exploit` blindly).
- Per `FLAG_MODE`, the module drives a distinct vulnerable sink of the lab service.

### 3.5 Lab-Only Vulnerable Service (bundle as companion `.exe` or container)
A deliberately vulnerable TCP/HTTP service exposing **sinks aligned to the module**:

| Sink ID   | Vulnerability flavor          | OWASP class     |
|-----------|-------------------------------|-----------------|
| `auth`    | Weak default credentials      | A07            |
| `inject`  | Command injection in header   | A03            |
| `sql`     | SQLi in query param           | A03            |
| `overflow`| Stack overflow on oversized length field | A03 / A04 |
| `trace`   | Verbose error + debug mode    | A05            |
| `ssrf`    | Blind URL fetch of GET /remote | A10           |

All sinks emit structured JSON logs (request, source IP, sink triggered) so findings can be
correlated with module output for **evidence-backed reporting**.

---

## 4. Compliance Frameworks — Mapped

### 4.1 OWASP Top 10 (2021)
| #   | Category                            | Where the tool addresses it                          | Lab sink  |
|-----|-------------------------------------|-----------------------------------------------------|-----------|
| A01 | Broken Access Control               | Findings export stamped with AC guidance            | `auth`    |
| A02 | Cryptographic Failures              | Ctrl coverage: weak protocol/plaintext flow         | `auth`    |
| A03 | Injection                           | POC sinks; evidence + remediations in report        | `inject`,`sql`,`overflow` |
| A04 | Insecure Design                     | Secure-by-design notes; overflow sink shows vetting | `overflow`|
| A05 | Security Misconfiguration           | Debug/trace sink detection                         | `trace`   |
| A06 | Vulnerable & Outdated Components    | BANNER/index version fingerprinting                 | banner    |
| A07 | Identification & Auth Failures      | Weak cred brute-force check + policy advice         | `auth`    |
| A08 | Software & Data Integrity Failures  | Supply-chain notes in module docs                   | n/a       |
| A09 | Security Logging & Monitoring       | Tool's own audit log + recommendation to enable     | `logs`    |
| A10 | SSRF                                | `ssrf` sink fetch detection                        | `ssrf`    |

### 4.2 NIST
| Reference                | Mapping                                                     |
|--------------------------|--------------------------------------------------------------|
| **NIST CSF 2.0** functions | **Govern** (policy/scope in tool), **Identify** (target registry, asset inventory), **Protect** (tool hardening, loopback), **Detect** (module check + sink logs), **Respond** (session kill, evidence capture), **Recover** (re-run, rollback module state) |
| **SP 800-115**           | Sections 4–5 (technical testing): discovery, probing, exploitation planning, POC execution, validation of findings — this tool implements the **SP 800-115 testing lifecycle** |
| **SP 800-53 Rev.5**      | CA-8 (Penetration Testing), SA-11 (Developer Testing), SI-2 (Flaw Remediation), AU-6 (Audit Review), RA-5 (Vulnerability Monitoring) |

### 4.3 ISO/IEC 27001:2022
| Clause / Annex A control | How satisfied                                              |
|--------------------------|------------------------------------------------------------|
| 8.1 / 8.2                | Operational plan: runs scoped scans, records acceptable results |
| **A.8.8**                | Vulnerability management — findings tied to remediation plan |
| **A.8.9**                | Configuration management — module/sink registry            |
| **A.8.28**               | Secure coding — the module follows MSF secure-by-design    |
| **A.5.15**               | Access control on results (role-gated report download)     |
| **A.5.24/5.25**          | Security event monitoring — audit log, evasion watchlist   |
| **A.7.10**               | Evidence: screenshots/JSON logs of POC preserved as artifacts |

### 4.4 Report Evidence Grid (per finding)
```
Finding #F-0012  Command Injection  severity=Critical  CVSS=9.8
  OWASP  : A03 Injection
  NIST   : SP 800-115 §5.2 · CSF DETECT.DE.CM-7 · 800-53 CA-8
  ISO    : A.8.8 + A.8.28
  Evidence: raw request, server 200 + "uid=0", module console log lines 12–18
  Remedy : input allow-list, parameterized handlers, WAF rule suggestion
  Artifact: evidence_0012.json  /  screenshot_0012.png
```

---

## 5. Reporting Engine

| Format | Library (bundled) | Characteristics                                                       |
|--------|-------------------|-----------------------------------------------------------------------|
| `.xlsx`| `openpyxl`        | Multi-sheet: Summary, Findings, OWASP map, NIST map, ISO map, Evidence log. Severity color fills (CRIT=#C62828, HIGH=#F57C00, MED=#FBC02D, LOW=#1E88E5, INFO=#90A4AE). Auto-filters, frozen header, chartsheet. |
| `.csv` | stdlib `csv`      | Flat normalized rows: `finding_id,severity,cvss,owasp,nist_800_115,iso,title,evidence,remediation,target,port,timestamp` |
| `.html`| `Jinja2`          | Single self-contained file (inline CSS+Chart.js): executive summary dashboard + technical appendix + compliance matrix + evidence attachments |

**Pipeline:** `DB → Query → ComplianceMapper → per-format renderer → artifact + hash manifest`.

---

## 6. Portable `.exe` Packaging & Runtime

### 6.1 Runtime topologies (choose one)
| Option            | Stack                             | .exe size | Notes                              |
|-------------------|-----------------------------------|-----------|-------------------------------------|
| **A (default)**   | PyInstaller `--onedir` + embedded FastAPI + compiled SPA | ~40–90 MB | fastest build, first-class logs     |
| B                 | PyInstaller `--onefile`           | ~60–120 MB| slower start (unpacks to temp)      |
| C                 | Electron / Tauri wrapping a local node host | large | heavier, JS-centric team            |

> Recommended: **Option A**, plus a launcher stub `VulnLabSentinel.exe` that
> starts the server, verifies MSGRPC reachability, opens the browser at
> `http://127.0.0.1:5XX5`, and installs a **tray icon** with "Stop & purge session" action.

### 6.2 Startup sequence
```
1. Port check          → 127.0.0.1:<port> free? else pick next
2. Config bootstrap    → load .ini/.env (loopback binds forced, no external listeners)
3. Governance gate     → consent dialog (attestation persisted)
4. MSRPC connect       → try msfrpcd → fallback to in-console msgrpc
5. Module mount        → verify <exe>/modules/exploits/lab/*.rb loads (module.info probe)
6. DB migrate          → SQLite tables + integrity hashes
7. Open browser        → login-safe bearer session
8. Ready state         → Dashboard live
```

### 6.3 Hardening baked into the .exe
- Only `127.0.0.1` binding; never `0.0.0.0`.
- No inbound connections except the local browser; **no cloud/telemetry**.
- Portable profile stored under the exe's own directory (no registry writes).
- Digital signature recommended + embedded SHA-256 manifest of all bundled libs.

---

## 7. Governance & Safety Gates (non-negotiable)

| Gate          | Enforced when        | Checks                                                                 |
|---------------|----------------------|------------------------------------------------------------------------|
| **LAB ONLY**  | target creation      | IP in lab ranges (RFC1918 + configured lab CIDRs), hostname ends `.lab` |
| **CONSENT**   | session start        | written attestation file, does not run in CI                      |
| **SCOPE**     | module run           | RHOST in-scope, RPORT allow-list, FLAG_MODE allowed                  |
| **NO-PAYLOAD**| default              | `check`/`info`/`verify` modes first; `exploit` needs explicit click     |
| **TIMEOUT**   | every job            | hard kill after max duration; orphan-session sweeper                   |
| **AUDIT**     | every action         | append-only hashed log exported with every report                      |

---

## 8. Database Schema (SQLite, embedded)

```sql
targets(id, host, port, label, scope_cidr, consent_hash, created_at)
findings(id, target_id, module, sink, title, severity, cvss, owasp, nist_csf,
         nist_800_115, iso_annex, evidence_json, remediation, artifact, ts)
runs(id, target_id, module, options_json, start_ts, end_ts, status, console_log)
compliance_evidence(id, finding_id, framework, control, assessed, notes)
audit_log(id, ts, actor, action, digest, prev_digest)
```

---

## 9. Deployment Checklist (lab topology)

```
┌─ ATTACKER HOST (Windows) ─────────────────────────────────────────────┐
│  VulnLabSentinel.exe · bundled Metasploit · bundled module           │
└───────────────┬──────────────────────────────────────────────────────┘
                │ 10.10.10.0/24 (isolated VLAN — NO internet route)
┌───────────────▼───────────────────┐      ┌──────────────────────────┐
│ LAB TARGET VM  (Linux)           │      │ MITM/OBS                │
│ vulnlab_service (sink service)   │      │ (optional Wireshark/log) │
└───────────────────────────────────┘      └──────────────────────────┘
```

1. Create isolated VLAN / air-gapped subnet.
2. Deploy lab service (Docker or portable).
3. Run `VulnLabSentinel.exe` on the attacker host.
4. Consent → add target → *Check* → *Verify* → *Exploit (lab POC)*.
5. Review findings → generate `.xlsx`/`.csv`/`.html` → archive with audit log.

---

## 10. Risks & Non-Risks

| Item                              | Assessment                                                        |
|-----------------------------------|-------------------------------------------------------------------|
| Malicious use of module           | Mitigated: lab-only gates, consent, loopback, no auto-payload      |
| Tool self-exploitation            | Hardened SPA/CDN-free, bearer tokens, MIME allow-list               |
| Escaping the lab                  | Port/IP gates + watchdog kill; explicit network warnings displayed |
| Output integrity                  | Hashed audit log + report hash manifest                            |
| Licensing                         | MSF is BSD/GPL; bundle licenses in `third-party-licenses.txt`      |

## 11. Directory Layout (proposed)

```
VulnLabSentinel/
├─ sentinel.exe                 # PyInstaller launcher
├─ web/                         # compiled SPA + assets
├─ backend/                     # FastAPI app, orchestrator, gates
├─ integration/                 # msgrpc adapter
├─ modules/exploits/lab/        # custom .rb module
├─ lab-service/                 # vulnerable service + Dockerfile
├─ reporting/                   # xlsx/csv/html renderers + templates
├─ data/profile.sqlite
├─ third-party-licenses.txt
└─ ARCHITECTURE.md
```

---

*Compliance framing: OWASP Top 10 2021, NIST CSF 2.0 & SP 800-115/800-53, ISO/IEC 27001:2022 Annex A.*