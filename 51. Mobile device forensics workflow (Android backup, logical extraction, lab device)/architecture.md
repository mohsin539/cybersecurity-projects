# 📱 Mobile Device Forensics Workflow — Solution Architecture

> Android Backup · Logical Extraction · Forensic Lab Device · Evidence Management

![Workflow](https://img.shields.io/badge/Workflow-Forensics-blue) ![Compliance](https://img.shields.io/badge/Compliance-ISO%2027001%20%7C%20NIST%20%7C%20OWASP-green) ![Platform](https://img.shields.io/badge/Platform-Android%20%7C%20Lab%20Device-orange) ![Status](https://img.shields.io/badge/Status-Lab%20Approved-brightgreen)

---

## 1. Executive Overview

This architecture defines a **complete, lab-controlled mobile device forensics pipeline** for Android devices. It covers every phase from **secure intake → evidence preservation → Android backup → logical extraction → artifact analysis → court-ready reporting**, while embedding **ISO 27001** (ISMS), **NIST SP 800-101 / 800-124** (mobile forensics), **SWGDE / ACPO** (digital evidence integrity) and **OWASP Top 10** (application security) controls into every layer.

🎯 **Business Goals**

| Goal | How the Architecture Delivers |
|------|------------------------------|
| **Evidentiary Integrity** | SHA-256 chain-of-custody hashing at every step, write-blocked acquisition |
| **Defensible Process** | Full audit trail, timestamped actions, dual-review sign-off |
| **Operational Secrecy** | Air-gapped lab segment, keyed evidence storage, RBAC isolation |
| **Compliance** | Continuous control mapping to ISO 27001, NIST, OWASP |
| **Report Readability** | SDF-style evidence reports exportable as PDF / DOCX / XML / JSON |

---

## 2. 🗺️ System Architecture (Color Map)

```mermaid
flowchart LR
    subgraph ZONE0["🔒 Evidence Intake Zone"]
        A1["📦 Exhibit Intake<br/>Registration & Labeling"]
        A2["⚖️ Chain of Custody<br/>Start Record"]
    end

    subgraph ZONE1["🛡️ Acquisition Zone (Lab Device)"]
        B1["🔌 Faraday Enclosure<br/>Air-Gapped Network Isolated"]
        B2["🖥️ Forensic Workstation<br/>(Write-Blocked / EWF Image)"]
        B3["📲 Android Device<br/>(ADB-Enabled, USB Debug)"]
    end

    subgraph ZONE2["🧪 Examination & Extraction"]
        C1["🗃️ Android Backup<br/>adb backup / .ab parse"]
        C2["🔍 Logical Extraction<br/>SQLite, Media, Call/SMS, APK"]
        C3["📄 Artifact Normalization<br/>SDF / Cellebrite-UFED XML"]
    end

    subgraph ZONE3["🧠 Analysis & Correlation"]
        D1["⏱️ Timeline Reconstruction"]
        D2["👤 User Attribution"]
        D3["📈 Keyword & Pattern Search"]
    end

    subgraph ZONE4["📤 Reporting & Disclosure"]
        E1["📑 SDF Report Builder<br/>PDF · DOCX · XML · JSON"]
        E2["🔑 Evidence Handover<br/>Digital Signature + Hash"]
    end

    subgraph ZONE5["🔎 Audit & Compliance Vault"]
        F1["📋 Full Audit Log (WORM)"]
        F2["📜 ISO/NIST/OWASP Control Map"]
        F3["🏢 Case Management DB"]
    end

    A1 --> A2 --> B1 --> B2 <--> B3
    B2 --> C1 & C2
    C1 --> C3
    C2 --> C3
    C3 --> D1 & D2 & D3
    D1 & D2 & D3 --> E1
    E1 --> E2
    B2 --> F1
    C3 --> F2
    E1 --> F3

    classDef intake fill:#FFF3E0,stroke:#F57C00,stroke-width:2px,color:#4E342E
    classDef acq fill:#E3F2FD,stroke:#1565C0,stroke-width:2px,color:#0D47A1
    classDef extract fill:#E8F5E9,stroke:#2E7D32,stroke-width:2px,color:#1B5E20
    classDef analysis fill:#F3E5F5,stroke:#6A1B9A,stroke-width:2px,color:#4A148C
    classDef report fill:#FBE9E7,stroke:#D84315,stroke-width:2px,color:#BF360C
    classDef audit fill:#ECEFF1,stroke:#37474F,stroke-width:2px,color:#263238
    class A1,A2 intake
    class B1,B2,B3 acq
    class C1,C2,C3 extract
    class D1,D2,D3 analysis
    class E1,E2 report
    class F1,F2,F3 audit
```

---

## 3. 🧬 Architecture Building Blocks

### 3.1 Forensic Lab Device (Workstation)

```mermaid
graph TB
    subgraph HW["💻 Forensic Workstation Hardware"]
        H1["🖥️ CPU / RAM / NVMe<br/>High-throughput hash + parse"]
        H2["🔐 HSM / TPM 2.0<br/>Key storage, attestation"]
        H3["💿 Forensic Write Blocker<br/>Writes blocked at hardware level"]
        H4["🖧 Air-Gapped NIC<br/>No external network egress"]
        H5["🖨️ Signed Output Printer"]
    end

    subgraph SW["⚙️ Logical & OS Stack"]
        S1["🛡️ Hardened OS (RBAC, FDE)<br/>e.g. Ubuntu/Debian CIS baseline"]
        S2["🔧 forensics SDKs<br/>ABE · SQLite3 · apkeep · exiftool"]
        S3["🧩 ADB (Android Debug Bridge)<br/>Authenticated USB transport"]
        S4["🗄️ Evidence Vault Mount<br/>LUKS/FDE, immutability flags"]
    end

    subgraph APP["🧪 Application Tier"]
        A1["📋 Intake App"]
        A2["🗃️ Backup Engine (.ab parse)"]
        A3["🔍 Extraction Engine"]
        A4["📑 Report Builder"]
        A5["🔎 Audit Logger"]
    end

    H1 --> H2
    H3 --> H1
    H4 --> H1
    H5 --> H1
    S1 --> S2
    S1 --> S4
    S3 --> S2
    A1 & A2 & A3 & A4 & A5 --> S1

    classDef hw fill:#E3F2FD,stroke:#1565C0,color:#0D47A1
    classDef sw fill:#E8F5E9,stroke:#2E7D32,color:#1B5E20
    classDef app fill:#F3E5F5,stroke:#6A1B9A,color:#4A148C
    class H1,H2,H3,H4,H5 hw
    class S1,S2,S3,S4 sw
    class A1,A2,A3,A4,A5 app
```

### 3.2 Network Topology — Air-Gapped Lab Segment

```mermaid
flowchart TB
    subgraph EXT["🌍 Outside World"]
        X1["👮 Requester / Court / DPO"]
    end

    subgraph DMZ["🧱 DMZ — Controlled Export"]
        D1["📤 Export Gateway<br/>Only signed reports exit"]
        D2["🛑 Egress Firewall / DLP"]
    end

    subgraph LAB["🏭 Forensic Lab (Air-Gapped)"]
        L1["📲 Evidence Intake"]
        L2["💻 Forensic Workstation"]
        L3["🗄️ Evidence Vault (Offline NAS)"]
    end

    X1 --> D2 --> D1
    D1 -- "Signed PDF/DOCX only" --> LAB
    L1 --> L2 --> L3
    L3 -- "Restore for review only" --> L2

    classDef ext fill:#FFEBEE,stroke:#C62828,color:#B71C1C
    classDef dmz fill:#FFF8E1,stroke:#F9A825,color:#5D4037
    classDef lab fill:#E8F5E9,stroke:#2E7D32,color:#1B5E20
    class X1 ext
    class D1,D2 dmz
    class L1,L2,L3 lab
```

---

## 4. 🔄 Core Forensic Workflows

### 4.1 Android Backup Workflow (`adb backup` / `.ab` parse)

```mermaid
sequenceDiagram
    participant E as Examiner
    participant W as Workstation
    participant D as Android Device
    participant V as Evidence Vault

    E->>W: Authenticate (MFA) & unlock case
    W->>D: Enable USB Debugging (screen interaction)
    W->>D: adb backup -apk -shared -all -f case.ab
    D-->>W: Stream .ab container (AES-256 encrypted)
    W->>W: Decrypt/parse via Android Backup Extractor (password entry)
    W->>W: Normalize apps → app data SQLite → artifacts
    W->>V: Store .ab + parsed corpus (SHA-256 + WORM)
    W->>W: Write Audit Journal: case, timestamp, hash, examiner
```

**⚙️ Android Backup Engine — Key Stages**

| # | Stage | Tooling | Output |
|---|-------|---------|--------|
| 1 | Enable debug bridge | `adb devices` / USB auth | Token bound to device |
| 2 | Full backup capture | `adb backup` | `case_<id>.ab` |
| 3 | Container decrypt | Android Backup Extractor (ABE) | `apps.tar` + manifest |
| 4 | SQLite extraction | `sqlite3`, Python API | `*.db` dumps |
| 5 | Media / shared | `adb pull /sdcard/*` | Images, docs, chat media |
| 6 | Normalization | SDF / JSON schema | `artifacts/` unified corpus |

> ⚠️ **Backup limits** — On modern Android 12+, unrestricted `adb backup` is deprecated; production path must fall back to **logical extraction + OEM backup APIs** (see §4.2). The workflow below documents that fallback.

### 4.2 Logical Extraction Workflow

```mermaid
flowchart TD
    S["📲 Isolate Device<br/>Faraday bag + flight mode"]
    P1["✅ Device ID & OS Fingerprint<br/>(ADB serial, build.prop, kernel)"]
    P2["🗄️ App-by-app logical extraction<br/>(com.android providers, /data or app-private dirs when USB-debug granted)"]
    P3["🧩 Package inventory<br/>apk list, version, permissions"]
    P4["🛠️ Web history / browser DBs<br/>Chrome, Firefox, WebView cache"]
    P5["💬 Communications artifacts<br/>SMS, Call logs, Voicemail, IM clients"]
    P6["📸 Media & exif<br/>location tags, timestamps"]
    P7["🗺️ Geo traces<br/>Google maps history, WiFi/BT logs"]
    P8["👤 Contacts & accounts<br/>accounts.db, content providers"]
    P9["🔍 Live carve<br/>strings/carve of unallocated space - lab only"]
    C["🧹 Integrity Hashing + Signed Manifest"]
    R["📊 Analysis Ready Corpus"]
    S --> P1
    P1 --> P2
    P2 --> P3 & P4 & P5 & P6 & P7 & P8
    P8 --> P9
    P9 --> C
    C --> R

    classDef st fill:#FFF3E0,stroke:#F57C00,color:#4E342E
    classDef pl fill:#E8F5E9,stroke:#2E7D32,color:#1B5E20
    classDef en fill:#FBE9E7,stroke:#D84315,color:#BF360C
    class S st
    class P1,P2,P3,P4,P5,P6,P7,P8,P9 pl
    class C,R en
```

### 4.3 Evidence Lifecycle & Chain of Custody

```mermaid
stateDiagram-v2
    [*] --> Seized: Exhibit intake
    Seized --> SealedAndHashed: signed & hashed custody
    SealedAndHashed --> Acquired: adb backup / logical
    Acquired --> Verified: hash match + manifest
    Verified --> Analyzed: examiner opens case
    Analyzed --> Reported: report draft + peer review
    Reported --> Disclosed: approved export
    Disclosed --> Released: handover signed
    Released --> [*]

    note right of Seized: ISO 27037 evidence<br/>handling rules
    note right of Acquired: NIST SP 800-101<br/>order of volatility
    note right of Verified: write-blocked copy<br/>working on clone only
```

---

## 5. 📊 Compliance & Governance Framework

### 5.1 Control Mapping Matrix

| # | Domain | Control / Requirement | ISO 27001:2022 | NIST SP 800-101/124 | OWASP Top 10 | Where Implemented |
|---|--------|----------------------|----------------|---------------------|--------------|-------------------|
| 1 | Access Control | Least privilege, MFA, RBAC | A.5.15–A.5.18 | §800-124 Sec 4.3 | A01 (broken access) | §3.1, ZONE0–5 |
| 2 | Evidence Integrity | Acquisition hashing, WORM store | A.8.12 | §800-101 Sec 6.3 | — | §4.1/4.2, Vault |
| 3 | Event Logging | Immutable audit trail, no tamper | A.8.15 | §800-101 Sec 8.3 | A09 (logging fail) | ZONE5, §7 |
| 4 | Data Protection | Encryption at rest/in transit, keys HSM | A.8.24–A.8.25 | §800-124 Sec 4.4 | — | HSM/TPM, LUKS |
| 5 | Secure Comms | USB bound auth, no plaintext | A.8.26 | §800-101 Sec 4.5 | A02/A08 (crypto) | ADB auth, TLS |
| 6 | Vulnerability Mgmt | Patching, SBOM, scanning | A.8.8–A.8.10 | §800-124 Sec 5 | A06 (vuln. comps) | §3.1 SW layer |
| 7 | Input Validation | All artifact/file paths validated | — | — | A03 (injection) | §4 parser gate |
| 8 | Secure Config | Hardened OS, default-deny | A.8.9 | §800-124 Sec 4.6 | A05 (misconfig) | CIS baseline |
| 9 | Crypto Weaknesses | Strong ciphers enforced (AES-256+) | A.8.24 | — | A02 | ABE/HSM |
| 10 | Supply Chain | Tooling vetting, signed artifacts | A.5.19–A.5.22 | — | A06 | SW registry |
| 11 | Incident Response | Breach playbook, containment | A.5.24–A.5.28 | §800-124 Sec 5.3 | — | IR runbook |
| 12 | Physical Security | Access-controlled lab & custody | A.7.1–A.7.14 | §800-101 Sec 4.2 | — | Zone model |
| 13 | Business Continuity | Backup/restore & DR drills | A.5.30–A.5.31 | — | — | Vault replication |
| 14 | Regulatory Handover | Discovery-ready export | A.5.34 | §800-101 Sec 9 | — | §6 Report engine |

---

### 5.2 ISO 27001:2022 Clause & Annex A Adoption

```mermaid
graph LR
    subgraph ISMS["🛡️ ISO 27001:2022 ISMS"]
        C4["4 Context<br/>Forensic service scope"]
        C5["5 Leadership<br/>DPO + forensic mgmt"]
        C6["6 Planning<br/>Risk assessment (evidentiary)"]
        C7["7 Support<br/>Competency, awareness"]
        C8["8 Operation<br/>Evidence-handling procedures"]
        C9["9 Evaluation<br/>Control audits"]
        C10["10 Improvement<br/>Continual forensics maturity"]
    end
    subgraph ANNEXA["📚 Annex A Controls (93)"]
        A5["A.5 Organizational (37)"]
        A6["A.6 People (8)"]
        A7["A.7 Physical (14)"]
        A8["A.8 Technological (34)"]
    end
    C4 --> C8 & A5 & A6 & A7 & A8
    C5 --> C9
    C6 --> C10
    C8 --> C9 --> C10
    A5 & A8 --> C9
```

### 5.3 NIST Alignment — Mobile Forensics References

- **NIST SP 800-101 Rev. 1** — *Guidelines on Mobile Device Forensics* — governs acquisition (Step 1–3), preservation, examination, analysis, reporting, and order of volatility. Implemented in §4.1–§4.2.
- **NIST SP 800-124 Rev. 2** — *Mobile Device Security: Enterprise Use* — enforces device enrollment, encryption, remote wipe & breach containment mirrored in ZONE1–ZONE2.
- **NIST SP 800-86** — *Integrating Forensic Techniques into Incident Response* — informs the artifact-to-incident correlation in ZONE3.
- **SWGDE** — *Best Practice Manual for Mobile Phone Examinations* — codifies examiner independence + peer review (§6.2).
- **ISO 27037** — *Identification, collection, acquisition and preservation of digital evidence* — applied to intake and handling (ZONE0).
- **ISO 17025** — *Testing & calibration lab competence* — lab device qualification, method validation (Lab Device §3.1).

### 5.4 OWASP Top 10 (2021) — Security of the Lab Tooling & Evidence Portal

| Rank | OWASP Category | Mitigation in Architecture |
|------|----------------|----------------------------|
| A01 | Broken Access Control | RBAC + MFA + object-level ACL on case records (§3.1, ZONE5) |
| A02 | Cryptographic Failures | AES-256/GCM vault, ECDSA report signing, HSM keys (§3.1, §6.1) |
| A03 | Injection (SQLi/XSS) | Parameterized queries, artifact viewer encoding, no raw SQL in UI |
| A04 | Insecure Design | Threat modeling at intake; immutable evidence store (WORM) |
| A05 | Security Misconfiguration | CIS-hardened host, deny-by-default firewall, minimal services |
| A06 | Vulnerable Components | SBOM per lab image, CVE scanning, enforced patch SLA |
| A07 | Auth Failures | WebAuthn/TPM-bound examiner auth, session revocation on case close |
| A08 | Software/Data Integrity | Signed builds, signed reports, hash manifest on every export |
| A09 | Logging & Monitoring | Tamper-evident journal shipped to WORM audit vault (§7) |
| A10 | SSRF | Export gateway validates signed destinations only (DMZ) |

---

## 6. 📤 Reporting Subsystem

### 6.1 Downloadable Report Options

| Format | Use Case | Integrity | Download Path |
|--------|----------|-----------|---------------|
| **PDF (SDF-v1)** | Court-ready testimony | ECDSA signature + embedded SHA-256 manifest | `GET /reports/{case}/export.pdf` |
| **DOCX** | Editing redactions / counsel drafts | Versioned + watermark | `GET /reports/{case}/export.docx` |
| **XML (SDF)** | Machine intake into evidence mgmt | XML signature (XAdES) | `GET /reports/{case}/export.xml` |
| **JSON** | Analyst / tooling pipeline ingest | JWS-signed | `GET /reports/{case}/export.json` |
| **CSV / XLSX** | Timeline & keyword pivot tables | Row-level hash sheet | `GET /reports/{case}/tables.xlsx` |
| **HTML (interactive)** | Stakeholder drill-down | Static, no JS, offline-safe | `GET /reports/{case}/view.html` |

```
GET /reports/{caseId}/export.{pdf|docx|xml|json|csv|xlsx}
Authorization: Bearer <examiner JWT>
Response headers:
  Content-Disposition: attachment; filename="CSE-2026-0041_RPT.pdf"
  X-Content-Options-Tag: signed, sha256=<manifest-hash>
```

```mermaid
flowchart LR
    A["📑 Report Builder"] --> B{"Select Format"}
    B -->|PDF| C1["PDF Render"]
    B -->|DOCX| C2["DOCX Compose"]
    B -->|XML SDF| C3["XML Serialize"]
    B -->|JSON| C4["JSON Serialize"]
    B -->|XLSX| C5["Pivot Sheets"]
    C1 & C2 & C3 & C4 & C5 --> D["🔐 Sign + Manifest"]
    D --> E{"Approved by Peer?"}
    E -->|No| F["⛔ Hold / return to review"]
    E -->|Yes| G["📦 Signed Download Package"]
    G --> H["🖥️ Requester Portal<br/>(audited access)"]

    classDef fmt fill:#FBE9E7,stroke:#D84315,color:#BF360C
    classDef sec fill:#E8F5E9,stroke:#2E7D32,color:#1B5E20
    classDef sig fill:#FFF8E1,stroke:#F9A825,color:#5D4037
    class A,B,C1,C2,C3,C4,C5 fmt
    class D,G sig
    class E,F,H sec
```

### 6.2 Report Content & Quality Gates

| Gate | Owner | Criterion |
|------|-------|-----------|
| G1 — Completeness | Examiner | All artifacts categories present or explicitly N/A |
| G2 — Integrity | QA reviewer | Manifest hash matches vault copy |
| G3 — Independence | Peer reviewer | Findings reproducible from vault clone |
| G4 — Approval | Case manager (lead) | Signed release, G1–G3 green |

- **Examiner independence** (SWGDE): examiner who acquires ≠ solely decides conclusion; dual reviewer embedded in workflow.
- **Reproducibility**: every report cites artifact UUIDs mapped 1:1 to vault objects, so any auditor can re-run analysis.

---

## 7. 🔐 Audit & Compliance Subsystem

### 7.1 Immutable Audit Trail (WORM)

```mermaid
sequenceDiagram
    participant A as Any Component
    participant J as Audit Journal (in-memory)
    participant K as Integrity Chain (hash-linking)
    participant V as WORM Vault

    A->>J: Action event {case, actor, op, ts, ctx}
    J->>K: Compute SHA-256(prevHash + event)
    K->>V: Append to WORM bucket (no delete/update)
    V-->>J: Storage ack
```

- **Tamper-evidence**: every journal entry is hash-linked to the prior entry (blockchain-style append-only). Altering any record invalidates the entire chain.
- **Retention**: 7 years mandatory (GDPR/ISO 27037 evidence schedule) then cryptographically shredded with signed disposal log.
- **Events captured**: intake, acquisition, hash verification, parse run, analysis queries, report export, access to case files, key ceremonies, failures/timeouts.

### 7.2 Audit Options Matrix

| Option | Scope | Output | Frequency |
|--------|-------|--------|-----------|
| **A1 — Control Self-Assessment** | ISO 27001 Annex A map vs live setting | Scorecard per control | Quarterly |
| **A2 — Evidence Integrity Audit** | Random custody-copy re-hash vs vault | Exception report | Per case close |
| **A3 — Examiner Practice Audit** | Percentage of cases peer-reviewed, deviation log | Examiner scorecard | Quarterly |
| **A4 — Vulnerability Audit** | SBOM/CVE scan of lab images + tooling | PoC/Patch report | Weekly |
| **A5 — Access Reviews** | RBAC entitlements vs role model | Least-privilege delta | Monthly |
| **A6 — Penetration Test** | External/OWASP-scoped testing of portal/DMZ | Pentest report + retest | Yearly (or per major change) |
| **A7 — Disaster Recovery** | Restore drill of Vault from backup | RTO/RPO attestation | Semi-annual |
| **A8 — Incident Forensics** | IR playbook post-mortem (NIST SP 800-61) | Lessons-learned log | On demand |

---

## 8. 🛡️ Security Controls and Data Protection

### 8.1 Crypto & Key Management

| Asset | Cipher / Scheme | Key Mgmt |
|-------|-----------------|----------|
| `.ab` backup container | AES-256-CBC (device-held) → re-wrapped | HSM-held KEK |
| Evidence vault at rest | AES-256-XTS (LUKS / BitLocker) | HSM + TPM |
| Vault replication | TLS 1.3 + HKDF session keys | Ephemeral |
| Report signatures | ECDSA P-384 | HSM sign-only key |
| Audit journal | SHA-256 hash chains | —
| App tokens / APIs | OAuth2 + JWT (RS256) | Keycloak / short TTL |

### 8.2 Zero-Trust Zones

| Zone | Trust Level | Egress | Ingress |
|------|-------------|--------|---------|
| ZONE0 Intake | Physical, supervised | — | Registered exhibits |
| ZONE1 Acquisition | Air-gapped | — | ADB-bound device |
| ZONE2 Examination | Air-gapped | — | ZONE1 internal |
| ZONE3 Analysis | Isolated VLAN | Internal only | ZONE2 |
| ZONE4 Reporting | DMZ | Signed exports | Requester auth |
| ZONE5 Audit | WORM | Read-only | ZONE0–4 journals |

---

## 9. ⚠️ Failure Modes & Safeguards

| FMEA Item | Risk | Mitigation |
|-----------|------|------------|
| Failed ADB auth | Device rejects connection | USB debugging token bound pre-seizure; OEM unlock readiness check |
| `.ab` unsupported on Android 12+ | Empty/non-provisioned backup | Fallback to logical extraction §4.2 |
| Password-protected `.ab` | Cannot decrypt | Brute-force only on clone with counsel approval; documented risk record |
| Malware in extracted content | Analysis-time infection | Content executed only in disposable VM; signature scan pre-open |
| Vault corruption | Chain-of-custody breach | Redundant WORM copies + integrity sweep A2 |
| Exam room supply-chain tamper | Fake tooling | SBOM pinning + signed container images (A06) |

---

## 10. 📁 Directory & Repo Layout

```text
mobile-forensics-lab/
├── architecture.md               # this document
├── docs/
│   ├── sops/                     # standard operating procedures
│   ├── controls/                 # ISO/NIST/OWASP control mapping sheets
│   └── templates/                # SPDF templates (PDF/DOCX/XML)
├── acquire/                      # adb/ABE/UFED-driver scripts
│   ├── android_backup.sh
│   └── logical_only.sh
├── extract/                      # parsers (sqlite, apk, media, geo)
├── analyze/                      # timeline, correlation, search engine
├── report/                       # builder + signer + exporters
├── audit/                        # journal chain + self-assessment jobs
├── vault/                        # evidence mount points (LUKS)
└── vault_fs.md                   # evidence store schema
```

---

## 11. ✅ Architecture Decision Records (Summary)

| ADR | Decision | Rationale |
|-----|----------|-----------|
| ADR-01 | Air-gapped lab, no evidence on enterprise net | Custody integrity & ISO 27037 isolation |
| ADR-02 | Android backup first, logical extraction fallback | Backwards reachable devices; documented limits |
| ADR-03 | WORM + hash-linked audit journal | Tamper-evident proof for court |
| ADR-04 | SDF/XML as canonical evidence format | Industry interchange + machine readability |
| ADR-05 | Portal/DMZ only for signed reports | DLP boundary, OWASP A04/A10 |
| ADR-06 | HSM-sign-only keys for all outputs | Non-repudiation of examiner actions |

---

## 12. 🚀 Roadmap

| Phase | Scope | Indicative Term |
|-------|-------|-----------------|
| P0 | Lab build-out: workstation, vault, zones | Month 0–1 |
| P1 | Android backup + logical extraction engines | Month 1–3 |
| P2 | Analysis, timeline, report builder + signer | Month 3–5 |
| P3 | Audit subsystem + control self-assessment | Month 5–6 |
| P4 | ISO 27001 certification / OWASP pentest / NIST validation | Month 6–9 |
| P5 | Continuous improvement & DR drills | Ongoing |

---

## 13. 📚 References & Standards

- ISO/IEC 27001:2022, ISO/IEC 27002:2022, ISO/IEC 27037:2012, ISO/IEC 17025:2017
- NIST SP 800-101 Rev. 1, NIST SP 800-124 Rev. 2, NIST SP 800-86, NIST SP 800-61 Rev. 3
- SWGDE Best Practice Manual for Mobile Phone Examinations
- ACPO Good Practice Guide for Digital Evidence (v5)
- OWASP Top 10:2021
- Definite Android Forensics / Android Backup Extractor (ABE) tooling notes

---

*Maintained by the Digital Forensics & Compliance Engineering Team · Review cycle 90 days · Baseline v1.0*