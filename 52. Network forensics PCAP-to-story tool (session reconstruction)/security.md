# 🔐 security.md — Security Profile of the Portable Suite

> Companion to `architecture.md` §7/§8. Describes the *actual, running* security
> controls inside the portable build (`PCAP-to-Story Suite v1.0.0`), how they map
> to ISO 27001 / NIST / OWASP, and how an auditor can verify them from the GUI.

---

## 1. Threat Model (what this portable tool defends)

| Asset | Threat | Control in-place |
|---|---|---|
| Raw evidence (PCAP) | Cover-patch / tamper before analysis | SHA-256 digest taken *before* any parsing; digests stored per capture |
| Reconstruction results | Fabricated "story" (hallucination) | Deterministic rule engine only — narrative is verbalisation of typed evidence slots, no LLM |
| Session timeline | Altered evidence anchors | Every event stores `frame_id` + `payload_offset` → replayable to byte |
| Audit trail | Retroactive editing / deletion | Append-only SQLite + SHA-256 hash chain + HMAC signature |
| Reports | Forged exports | Each export hashed; hash recorded in report history + audit bus |
| Analyst PII | Over-exposure by clearance | Clearance-capped IP masking (0 / 1 / 2); applied at render time |
| Exfil of base OS / data dir | Theft of portable drive | Sealed 32-byte master key per install; no readable secrets in repo |

**Trust boundary:** the tool is *fully offline*. There is no network egress from the
GUI, no third-party enrichment, no telemetry. (Cloud profiles described in
`architecture.md` remain optional and disabled here.)

---

## 2. Cryptographic services (`app/core/security.py`)

| Primitive | Use | Notes |
|---|---|---|
| SHA-256 | File digest (evidence integrity) & event hashing | `sha256_file()` streams large files; digest captured pre-processing |
| HMAC-SHA256 | Audit signature (`event_hash` gone through HMAC with derived key) | Key derived from per-install master via HKDF-style label |
| Sealed master key | `~/.pcapless/.pcapless_master.key` | 32 random bytes, written via atomic `os.replace`; generated on first run if absent |
| Data masking | IP masking by clearance | `mask_ip(ip, 0|1|2)` — all masked / last octet / full |

Audit event signing path (per `app/core/audit.py`):

```
event_hash = SHA256( prev_hash | ts | actor | action | obj | evidence_hash )
signature  = HMAC-SHA256( audit_key, event_hash )
```

Verification (`Audit tab → Verify hash-chain`) re-walks the chain from `GENESIS`
and flags any record whose recomputed hash deviates.

---

## 3. Assurance map (implementation ↔ frameworks)

### ISO/IEC 27001:2022 — implemented controls

| Control | Where it exists in the build |
|---|---|
| A.8.8 Vulnerability mgmt | SBOM = `pip freeze`; dependencies pinned (dpkt, reportlab, pyinstaller) |
| A.8.11 Masking | Clearance-driven masking in `ReportBuilder` for every export |
| A.8.15 Logging | *(see §5)* — covers evidence reads, exports, app lifecycle |
| A.8.24 Key mgmt | Sealed per-install key; audit sub-key derivation |
| A.8.34 Protection of logs | Append-only store + tamper verification tooling |

> Full enterprise controls (SSO/MFA/KMS) are *design-scoped* in architecture.md
> §7.2 for cloud/server deployments; the portable build keeps the offline subset.

### NIST CSF 2.0 — implemented functions

| Function | In-build capability |
|---|---|
| IDENTIFY | Capture inventory & case metadata in state DB |
| PROTECT | Hash integrity, sealed keys, masked exports |
| DETECT | Beacon/periodicity detection, cleartext-credential flags, exfil imbalance |
| RESPOND | Story graph + MITRE mapping straight from DETECT events |

### NIST SP 800-53 (subset)

`AU-2/AU-6` faultless audit of user actions · `SC-8/SC-28` disk-level integrity ·
`SI-7` evidence integrity (hashing) · `AC-3` clearance-gated data (masking).

### OWASP Top 10 2025 — countermeasures

| # | Risk | Countermeasure |
|---|---|---|
| A01 | Broken Access Control | Case-scoped views, clearance levels, `BLOCKED` verdicts possible in audit |
| A02 | Cryptographic Failures | SHA-256/HMAC keyed; secret material never stored plaintext |
| A05 | Security Misconfiguration | No default creds, no open ports (standalone) |
| A08 | Software & Data Integrity | Every report/evidence hashed; audit chain verifiable |
| A09 | Logging & Monitoring | Full audit bus (§5) + tamper-scan from the UI |

---

## 4. Evidence integrity workflow (chain of custody)

```text
PCAP file
   │  sha256_file() ──────────────────► stored on capture (pre-processing)
   ▼
Parse + reassembly (each session)
   │  event = {type, details, frame_id, payload_offset, ts, dir}
   ▼
Story engine (deterministic)
   │  node/edge/narrative ← evidence-anchored only
   ▼
Report export
   │  report hashed, recorded in history with sha256, audit event created
   ▼
Evidence vault   (immutable PCAP kept on disk, read-only in workflows)
   │
   ▼
Audit tab → "Verify hash-chain" proves nothing was altered after the fact
```

---

## 5. Audit function (enabled by default)

| Item | Value |
|---|---|
| Store | `~/.pcapless/pcapless.db` table `audit` |
| Property | Append-only; no UPDATE/DELETE path in the app |
| Integrity | SHA-256 forward chain + HMAC-SHA256 signature per record |
| Events captured | APP_START/EXIT, INGEST (evidence hash), STORY_VIEW, REPORT_DOWNLOAD (fmt+hash), AUDIT_VERIFY, AUDIT_EXPORT, BLOCKED attempts |
| Verification | In-GUI "Verify hash-chain"; also `scripts/smoke_test.py` asserts integrity |

Audit record shape:

```json
{ "ts":"…Z","actor":"analyst","action":"REPORT_DOWNLOAD","obj":"pdf://report_….pdf",
  "evidence_hash":"sha256:…","prev_hash":"…","event_hash":"…","signature":"…",
  "verdict":"ALLOWED" }
```

---

## 6. Operational security checklist (for the operator)

1. Copy the portable `.exe` **and** the `~/.pcapless` data folder for case handover.
2. Take the file SHA-256 of the PCAP **before** import (the tool displays it on the Ingest tab).
3. Run **Verify hash-chain** on the Audit tab before exporting any report.
4. Grant the analyst the *lowest* clearance that reports must comply with.
5. Keep `sample_triage.pcap` only for demo/training — delete before real cases.

---

## 7. Known limits (honest scope)

- Masking applies to IPv4/IPv6 endpoints in exports, not to payloads (payload
  redaction belongs to the cloud profile).
- HMAC signing uses a sealed per-install key — appropriate for offline DFIR
  portability; asymmetric (Ed25519/HSM) signing is the server-profile upgrade path.
- The audit store is tamper-*evident*, not tamper-*proof* — physical write
  protection (WORM) is the server-profile enhancement.