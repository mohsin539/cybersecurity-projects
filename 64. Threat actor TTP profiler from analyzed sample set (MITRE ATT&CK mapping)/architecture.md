<div align="center">

# 🛡️ THREAT ACTOR TTP PROFILER

### *Architecture Blueprint for a Portable GUI `.exe` Solution*

**MITRE ATT&CK™ Mapping · Threat Intelligence · Malware Sample Profiling**

| 🎯 **Status** | 🧱 **Design** | 🔒 **Security Baseline** |
|---|---|---|
| `▪️ Production-Ready Blueprint` | `▪️ Layered Hexagonal + Event-Driven` | `▪️ ISO 27001 · NIST CSF 2.0 · OWASP Top 10` |

</div>

---

## 📋 Table of Contents

1. [🎯 Executive Summary](#-executive-summary)
2. [🧩 Problem & Mission](#-problem--mission)
3. [🏗️ High-Level Architecture](#%EF%B8%8F-high-level-architecture)
4. [📚 Layered Architecture Detail](#-layered-architecture-detail)
5. [📦 Packaging & Deployment (Portable .exe)](#-packaging--deployment-portable-exe)
6. [🎨 GUI Design System — Colorful & Attractive](#-gui-design-system--colorful--attractive)
7. [🗃️ Data Model & Storage](#%EF%B8%8F-data-model--storage)
8. [🔬 MITRE ATT&CK Mapping Engine](#-mitre-attack-mapping-engine)
9. [📈 Reporting & Visualization](#-reporting--visualization)
10. [🔐 Security & Compliance](#-security--compliance)
    - [ISO/IEC 27001 Mapping](#-isoiec-27001-mapping)
    - [NIST CSF 2.0 & SP 800-53 Mapping](#-nist-csf-20--sp-800-53-mapping)
    - [OWASP Top 10 Mapping](#-owasp-top-10-mapping)
11. [⚔️ Threat Model](#%EF%B8%8F-threat-model)
12. [📊 Non-Functional Requirements](#-non-functional-requirements)
13. [🧭 Roadmap](#-roadmap)
14. [📚 References](#-references)

---

# 🎯 Executive Summary

The **Threat Actor TTP Profiler** is a **portable, single-file Windows `.exe`** with a **colorful, dark-cyber GUI** that consumes a **set of analyzed malware samples** (static, dynamic, network, YARA) and produces a **threat-actor behavioral profile** — mapping every observed artifact to **MITRE ATT&CK™ tactics, techniques, and procedures (TTPs)**, scoring confidence, and **attributing the likely threat actor / campaign**.

The system is architected as a **self-contained, offline-first, event-driven** application that keeps all intelligence local, honors `ISO 27001 / NIST / OWASP` controls at **every layer**, and emits **portable, signed outputs** (HTML, PDF, JSON, STIX 2.1, MITRE ATT&CK Navigator layer).

> **One command-to-conclusion pipeline:** *Samples In → Behavior Extracted → MITRE ATT&CK Mapped → Actor Profiled → Priority Report Out.*

---

# 🧩 Problem & Mission

| ❓ Problem | ✅ Solution |
|---|---|
| Analysts drown in raw sandbox/scan JSON | Aggregated evidence → **unified sample-set profile** |
| Techniques are scattered across tools | **One canonical MITRE ATT&CK mapping engine** |
| Attribution is guesswork | **Probabilistic actor clustering** against ATT&CK Group/Software datasets |
| Heavy, slow, install-dependent tooling | **Portable `.exe`, offline, < 200 MB, runs in 1 second** |
| Reports are dull wall-of-text | **Colorful heatmaps, kill-chain timelines, radar coverage charts** |

---

# 🏗️ High-Level Architecture

```
                    ┌─────────────────────────────────────────────────────────────────────┐
                    │                     🎨 PRESENTATION LAYER (GUI)                     │
                    │   Dashboard · ATT&CK Matrix Heatmap · Kill-Chain Timeline · Cards   │
                    │        Radar Charts · Sample Explorer · Report Previewer            │
                    └───────────────▲───────────────────────────▲────────────────────────┘
                                    │   Events / Commands       │   State (MVVM/Bindings)
                    ┌───────────────┴───────────────────────────┴────────────────────────┐
                    │                    ⚙️ APPLICATION / SERVICE LAYER                   │
                    │   Import Orchestrator · Profile Manager · Report Service · Query    │
                    └───────▲──────────────────────▲──────────────────────▲───────────────┘
                            │                      │                      │
     ┌──────────────────────┴───────┐   ┌──────────┴───────────┐   ┌───────┴────────────────────┐
     │ 📥 INGESTION DOMAIN          │   │ 🔬 ANALYTICS DOMAIN   │   │ 🔎 ATTRIBUTION DOMAIN       │
     │  Sample Set Intake            │   │  ATT&CK Mapper        │   │  Actor Clustering           │
     │  Parsers (Static/Dyn/Net)     │   │  Evidence Attacher    │   │  Confidence Scoring         │
     │  YARA / Signature Matching    │   │  Scoring & Weighting  │   │  Group / Software Linking   │
     └──────────┬───────────────────┘   └──────────┬──────────┘   └──────────┬──────────────────┘
                │                                  │                         │
     ┌──────────┴──────────┐              ┌─────────┴──────────┐    ┌─────────┴──────────┐
     │ 🗄️ DATA LAYER        │              │ 🧠 ENGINE LAYER     │    │ 🤝 INTEGRATIONS     │
     │ SQLite (encrypted)   │◄────────────►│ Rules & Weights    │    │ STIX 2.1 Import    │
     │ ATT&CK STIX Bundle   │              │ Clustering (k-NN)  │    │ ATT&CK Navigator   │
     │ Profile Store        │              │ Scoring Pipeline   │    │ HTML/PDF/JSON/CSV  │
     └──────────────────────┘              └────────────────────┘    └────────────────────┘
                    │
            ┌───────┴──────────────────────────────────────────────────────────┐
            │                     🔐 SECURITY & COMPLIANCE LAYER               │
            │  File integrity (SHA-256) · HSM/OS keychain crypto · Audit log  │
            │  Sandboxed parsing · Sanitization · TLS mTLS · Zero-Trust local │
            └──────────────────────────────────────────────────────────────────┘
```

---

# 📚 Layered Architecture Detail

## 1️⃣ Presentation Layer 🎨

| Concern | Design |
|---|---|
| Framework | **PySide6 (Qt6)** — rich, fast, single-exe friendly (or Avalonia/Tauri alternative) |
| Paradigm | **MVVM** with a reactive event bus; UI never touches analyzers directly |
| Theme | Dark-cyber **"Neon Sentinel"** design system (Section 6) |
| Widgets | ATT&CK Navigator heatmap grid, radar charts, Gantt-style kill-chain, donut metrics |
| Security | No raw artifact text rendered pre-sanitization (anti-XSS/HTML-injection); views bound via typed models |

## 2️⃣ Application / Service Layer ⚙️

- **Import Orchestrator** — watches a drop-folder or accepts multi-select drag & drop; validates schema & hashes.
- **Profile Manager** — lifecycle of a *Profile* (draft → mapping → attributed → reviewed → shipped).
- **Report Service** — renders HTML/PDF/JSON/STIX/Navigator layer; signs outputs.
- **Query Service** — FTS scoring of samples, techniques, actors.

## 3️⃣ Domain Layers 🔬

### 📥 Ingestion Domain
- Parsers for: **CAPE/Cuckoo JSON, Scanners` JSONL, YARA hits, VT/KAPE static data, PCAP session summaries, file metadata (PE/ELF/OLE).**
- Normalizes all evidence into a canonical `EvidenceRecord` DTO.
- Dedup + hash correlation (SHA-256) to count unique samples.

### 🔎 Analytics Domain (MITRE ATT&CK Mapping Engine Core)
- **Technique Extractor** — signature/YARA rule → ATT&CK mapping; behavioral hints → tactic candidates.
- **Evidence Attacher** — every mapped technique carries the supporting file/rule/timestamp.
- **Weighting Engine** — `w = baseWeight × evidenceStrength × sampleCoverage × recency`.
- **Tactic Aggregator** — rolls techniques up into ATT&CK tactics & kill-chain phases.

### 🔎 Attribution Domain
- **Actor Clustering** — compares technique-set + software + IOCs against bundled **ATT&CK Group (Gxxxx)** dataset.
- **Confidence Score** — `0–100` Bayesian-ish score combining similarity, coverage, and conflicting signals.
- Output: ranked actor candidates with *evidence delta* (matched vs unmatched techniques).

## 4️⃣ Data Layer 🗄️
- **SQLite** (single-file, encrypted at rest via SQLCipher) — portable-friendly.
- Bundled **ATT&CK STIX 2.1 bundle** (tactics, techniques, groups, software, mitigations, detections) refreshed at release build.
- **Profile Store** + **Audit Store** (append-only).

## 5️⃣ Engine / Integration Layer 🧠
- Clustering via scikit-learn (bundled, verified wheels).
- STIX 2.1 export, **MITRE ATT&CK Navigator layer JSON**, Sigma/Gamma detection snippets, HTML & PDF reports.

---

# 📦 Packaging & Deployment (Portable .exe)

| Attribute | Specification |
|---|---|
| Build toolchain | Nuitka (higher perfo) / PyInstaller + **UPX**; or **.NET 8 AOT / Avalonia** variant |
| Output | **Single self-contained `.exe`**, no runtime required (Windows 10/11 x64) |
| Size budget | ≤ 200 MB (compressed) |
| Data location | Sibling `data/` dir **or** `%LOCALAPPDATA%\TTPProfiler` when invoked with `--portable` absent |
| Config | `profile.config.json` (nullable: defaults embedded) |
| Authentiity / Trust | **Authenticode signing** (EV cert) + strong-name; SHA-256 published |
| Startup | Cold start < **1.5 s**; splash screen; self-integrity check (bundle hash) |
| Updates | Offline users: signed delta bundles; online: privacy-first (checksum-only) check |
| Side-loading | `--verify` self-audit mode (signature, hash, dependency manifest) |

> **Portability contract:** No registry writes, no installers, no admin rights required, no global hooks. All writes confined to `data/` dir.

---

# 🎨 GUI Design System — Colorful & Attractive

> **"Neon Sentinel"** — a functional cyber-dark theme that *makes* threat data beautiful without sacrificing readability.

## 🎨 Color Palette

| Token | Hex | Usage |
|---|---|---|
| 🕶️ **Abyss** | `#0B0F19` | App background |
| ⬛ **Panel** | `#111827` | Cards, sidebars, tables |
| 🌌 **Elevation** | `#1B2436` | Raised surfaces, modals |
| 🌊 **Cyan Byte** | `#00E5FF` | Primary accent, active nav, links |
| 🌸 **Magenta Pulse** | `#FF2E97` | High-severity, attribution highlights |
| 🟢 **Lime Surge** | `#A6FF00` | Matched / green light, confirmed |
| 🟡 **Amber Signal** | `#FFB800` | Medium confidence, warnings |
| 🔴 **Crimson Alert** | `#FF4D4D` | Critical severity, blockers |
| 🟣 **Violet Quantum** | `#7C4DFF` | Tactic-category grouping, badges |
| ⚪ **Ghost** | `#E8F0FE` | Primary text on dark |

## 🔤 Typography
- **Numbers / IOCs:** `JetBrains Mono` (tabular)
- **Body / Headers:** `Inter` / `Segoe UI Variable`
- **Weights:** 400 body · 600 labels · 800 metric counters

## 🧩 Signature Visual Elements
1. **ATT&CK Heatmap Matrix** — per-tactic columns, per-technique rows; cell color intensity = **weighted confidence**; hover = evidence tooltip; click = drill-down.
2. **Kill-Chain Timeline** — horizontal GV iterations with animated pulse dots per phase.
3. **TTP Radar** — 14-spoke tactic coverage polygon with area fill gradient.
4. **Metric Cards** — glowing stat tiles (Samples, Techniques, Tactics, Top Actor, Confidence) with delta slivers.
5. **Sample Explorer** — file-grid cards w/ hash, verdict badge, matched rule chips.
6. **Light & Dark** — dark default; light "Daylight Forensics" alt theme.
7. **Accessibility** — WCAG 2.1 AA contrast, reduced-motion mode, full keyboard nav.

> **GUI-to-engine flow:** *click 😈 Actor Profile → emits ProfileQueryEvent → Service returns ProfileViewModel → ViewModel diff-patches UI (no full re-render).*

---

# 🗃️ Data Model & Storage

```
┌─────────────┐  1..N ┌────────────────┐  1..N ┌──────────────────┐
│ SampleSet   │──────►│ Sample          │──────►│ EvidenceRecord   │
│ id          │       │ sha256, size    │       │ sourceType       │
│ name, desc  │       │ family, mime    │       │ raw(enc), hash   │
│ ingested_at │       │ verdict         │       │ captured_addrs   │
└─────────────┘       └────────────────┘       └──────────────────┘
       ▲  1                      │1..N                │1..N
       └──  Identity of          ▼                    ▼
┌─────────────────────┐   ┌──────────────────┐  ┌──────────────────┐
│ ActorProfile        │   │ TechniqueMapping │  │ MitigationMatch  │
│ id, actorList(rank) │◄──│ technique_id(T)  │  │ mitigation_id(M) │
│ confidence 0-100    │   │ tactic_id, score │  │ coverage_pct     │
│ intel_grade         │   │ evidence_fk      │  │ detections(built)│
└─────────────────────┘   └──────────────────┘  └──────────────────┘
```

- **Encryption:** SQLCipher AES-256-GCM at rest; attachments blob-encrypted with per-dataset keys.
- **Key custody:** Windows **DPAPI** / TPM-backed machine key (OS keychain), no hard-coded secrets.
- **Audit:** append-only `audit.log` (actor, action, ts, hash chain).

---

# 🔬 MITRE ATT&CK Mapping Engine

## Pipeline

```
 Raw Evidence ─► Normalize ─► EvidenceRecord
                   │
                   ▼
 ┌───────────────────────────────────────────────┐
 │ 1. TECHNIQUE EXTRACTION                       │
 │    - YARA/Sigma rule ⇄ Technique index        │
 │    - API/import table, PE strings, C2 beacon  │
 │      heuristics, sandbox behavior signatures  │
 └───────────────────┬───────────────────────────┘
                     ▼
 ┌───────────────────────────────────────────────┐
 │ 2. EVIDENCE ATTACH & VALIDATE                 │
 │    - multi-rule agree = ↑evidenceStrength     │
 │    - false-positive heuristics removed        │
 └───────────────────┬───────────────────────────┘
                     ▼
 ┌───────────────────────────────────────────────┐
 │ 3. WEIGHTING  w = base × strength × coverage  │
 ┌───────────────────────────────────────────────┐
 │ 4. TACTIC AGGREGATION (kill-chain phases)     │
 ┌───────────────────────────────────────────────┐
 │ 5. ACTOR CLUSTERING (k-NN vs Gxxxx dataset)   │
 ┌───────────────────────────────────────────────┐
 │ 6. CONFIDENCE (0–100) + intel grade (A–D)     │
 └───────────────────────────────────────────────┘
```

## Confidence Model
```
confidence = 100 × Σ(w_matched) / (Σ(w_matched) + Σ(w_unmatched) + penalty_conflicts)
```
- Penalty for contradictory evidence (e.g., both exfil AND no-network flags).
- Confidence tiers: 🟢 **High ≥ 80** · 🟡 **Medium 50–79** · 🔴 **Low < 50**.

## Outputs per profile
- **STIX 2.1 Bundle** (samples→indicator→infrastructure→threat-actor graph).
- **ATT&CK Navigator JSON** (heatmap layer, shareable).
- **HTML / PDF** executive report + analyst annex.
- **YARA/Sigma hunt snippets** for matched TTPs (defensive boomerang).

---

# 📈 Reporting & Visualization

| Report | Audience | Format | Visuals |
|---|---|---|---|
| **Executive Brief** | SOC Managers | HTML/PDF | Scorecards, kill-chain, radar |
| **Analyst Dossier** | Threat Analysts | PDF | Full evidence-to-technique traceability |
| **Navigator Layer** | All | JSON | Shareable ATT&CK heatmap |
| **STIX Bundle** | Intel platforms (CTI-TAXII) | JSON | Interop graph |
| **Hunt Pack** | Detection Engineers | YARA/Sigma/CSV | Actionable detections |

---

# 🔐 Security & Compliance

## Security-by-Design Principles
1. **Least privilege** — app requests no admin; runs as current user.
2. **Defense in depth** — layered parsing, validation, encryption, audit.
3. **Fail secure** — default-deny parsing; unparseable input quarantined.
4. **Privacy first** — everything local by default; telemetry opt-in & zero-PII.
5. **Immutable evidence** — hashes + append-only audit.

## 1️⃣ ISO/IEC 27001 Mapping 🏆

| ISO 27001:2022 Annex A | Appendix & Annex | Where Implemented |
|---|---|---|
| **A.8 Asset Management** | A.8.1–A.8.12 | Inventory of samples/intel artifacts; label & classification per sample set |
| **A.10 Cryptography** | A.10.1–A.10.2 | AES-256-GCM at rest, DPAPI/TPM keys, TLS mTLS for any sync |
| **A.11 Physical Security** | A.11.1–A.11.2 | Portable medium protection — device-encrypted dirs, tamper seals on builds |
| **A.12 Operations Security** | A.12.1–A.12.7 | Change-controlled builds; hardened release CI/CD; capacity planning |
| **A.13 Communications Security** | A.13.1–A.13.2 | Network segmentation guidance; encrypted sync channels; no cleartext |
| **A.14 System Acquisition & Dev** | A.14.1–A.14.2 | Secure SDL (threat-modeled, SAST/DAST, reproducibility) |
| **A.16 Incident Management** | A.16.1 | Incident playbook tied to alerts surfaced from profiles |
| **A.17 Business Continuity** | A.17.1–A.17.2 | Offline-capable core → survives connectivity loss |
| **A.18 Compliance** | A.18.1–A.18.2 | Audit-trail exports satisfy SD evidence requirements |

## 2️⃣ NIST CSF 2.0 & SP 800-53 Mapping 🏛️

| NIST CSF 2.0 Function | Control Family Examples | App Implementation |
|---|---|---|
| **Govern (GV)** | GV.SC, GV.RR | Policy in code: config profiles, asset/risk register for intel |
| **Identify (ID)** | ID.AM, ID.RA | Sample inventory, threat/technique risk scoring |
| **Protect (PR)** | PR.AT, PR.DS, PR.DS-1 | Encryption, signing, least privilege, training material |
| **Detect (DE)** | DE.AE, DE.CM | TTP heatmap flags novel/emergent patterns; integrity checks |
| **Respond (RS)** | RS.CO | Incident response context from attribution dossier |
| **Recover (RC)** | RC.RP | Restore from signed bundle backups; tamper detection |

**NIST SP 800-53 controls of note:** AC-6 (least privilege), AU-2/3 (audit), CM-8 (component inventory), SC-8/13 (transmission & cryptography), SI-10 (input validation), SI-7 (software integrity).

## 3️⃣ OWASP Top 10 Mapping 🚨

| OWASP Top 10 (2021) | Mitigation in Application |
|---|---|
| **A01 Broken Access Control** | Per-user permissions at profile level; capability gating |
| **A02 Cryptographic Failures** | AES-256-GCM/SQLCipher, key in OS keychain, no plaintext evid storage |
| **A03 Injection** | Parameterized queries (SQLite), strict schema validation on every parser |
| **A04 Insecure Design** | Threat-model-as-doc; fail-secure default-deny parsers |
| **A05 Security Misconfiguration** | Hardened defaults; `--verify` self-audit; no debug mode in release |
| **A06 Vulnerable Components** | SBOM (`CycloneDX`) generated per build; pinned verified deps |
| **A07 Identification & Auth Failures** | Strong ID/GUIDs; optional PIN/fingerprint gate for high-grade dirs |
| **A08 Software & Data Integrity** | Authenticode + SHA-256 release manifests; signed update deltas |
| **A09 Logging & Monitoring Failures** | Structured audit log; hash-chain; alerting hints to SIEM feed |
| **A10 SSRF** | All network callouts deny by default; allowlist + mTLS only |

## Security Toolchain
- **SAST:** Bandit / Semgrep — gated in CI.
- **DAST/Runtime:** OWASP ZAP for any web-based report preview origin; fuzzing on parsers.
- **SCA:** Trivy + CycloneDX SBOM each release.
- **Build:** SLSA L3 intent (hermetic, reproducible, signed provenance).
- **BoMS:** Threat modeling documented (STRIDE against each layer).

---

# ⚔️ Threat Model

| Asset | STRIDE Vector | Risk | Mitigation |
|---|---|---|---|
| Malicious artifact content | Tampering / Info disclosure / DoS (parser crashes) | High | Sandboxed, memory-safe parsing; size/count limits; quarantine parser failures |
| Bundled ATT&CK DB | Tampering | Med | Signed release bundles + hash verification |
| Encrypted SQLite store | Info disclosure | Med | SQLCipher + DPAPI/TPM keys, minimal privilege |
| Supplied report HTML | XSS (via artifact names/strings) | High | Output encoding + CSP on preview origin; disable scripting |
| CLI surface | Command injection | Low | Arg schema whitelist; no shell interpolation |
| Update channel | MITM / supply chain | High | mTLS, signed deltas, hash pinning, published fingerprints |

---

# 📊 Non-Functional Requirements

| Category | Requirement |
|---|---|
| ⚡ Performance | Profile of 10k evidence rows < **3 s**; GUI 60 fps; memory < 512 MB |
| 🧑‍🦯 Usability | Zero-training onboarding (< 10 min); wizard for first import |
| 🔁 Portability | Runs from USB/network share; no admin; no install |
| ♿ Accessibility | WCAG 2.1 AA; full keyboard nav; reduced motion |
| 🌐 Locale | EN/VN themes; RTL-ready layout tokens |
| 🔌 Extensibility | Parser plugin interface; custom rule bundles |
| 🧪 Reliability | Cold-start <1.5 s; zero data-corruption (WAL + integrity pragma) |
| 🔒 Resilience | Offline-first; graceful degradation on missing model/data |

---

# 🧭 Roadmap

| Phase | Deliverable |
|---|---|
| **M0** 🧱 | Skeleton app, theme system, drop-folder ingest, sample cards |
| **M1** 🔬 | ATT&CK index, technique extractor, evidence attach, heatmap v1 |
| **M2** 🧠 | Weighting + scorer, actor cluster v1, navigator JSON export |
| **M3** 📈 | Report suite (HTML/PDF), STIX export, hunt pack generation |
| **M4** 🔐 | Hardening: SBOM, signing, `--verify`, audit chain, compliance docs |
| **M5** 🚀 | Signed portable builds + pilot validation with a public sample set |

---

# 📚 References

- MITRE ATT&CK® — [attack.mitre.org](https://attack.mitre.org) · ATT&CK Navigator · STIX 2.1 bundle
- NIST CSF 2.0 — [nist.gov/cyberframework](https://www.nist.gov/cyberframework)
- NIST SP 800-53 Rev 5 — controls catalog
- ISO/IEC 27001:2022 — Information security management systems
- OWASP Top 10 (2021) — [owasp.org](https://owasp.org/Top10)
- SLSA — Supply-chain Levels for Software Artifacts · CycloneDX SBOM spec

---

<div align="center">

**🛡️ Threat Actor TTP Profiler — Architecture v1.0**

`Neon Sentinel` GUI · `Offline-First` Engine · `MITRE ATT&CK™` Native · `ISO 27001 / NIST / OWASP` Compliant

**"Turn a pile of samples into a story — with a confidence score, a heatmap, and a hunt plan."** ✨

</div>