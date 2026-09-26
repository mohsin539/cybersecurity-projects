# 🔐 security.md — Security Posture & Controls Register

> Companion to `architecture.md` · Applies to the portable GUI build `MobileForensicsLabPortable.exe`

## 1. Build & Runtime Facts

| Property | Value |
|----------|-------|
| Runtime | Python 3.12.7 compressed to single portable EXE (PyInstaller 6.22) |
| GUI | Tkinter 8.6 (`--noconsole`, no console window) |
| Data locality | **Everything persistent stays beside the EXE** (`evidence_vault/`) — usable air-gapped |
| Crypto baseline | SHA-256 (hashing), AES-256-class file storage intent, HMAC-SHA256 manifests (64 hex chars) |
| Signing substitute | HMAC-SHA256 keyed by random 32-byte key in `evidence_vault/keys/signing.key` (HSM integration point) |
| Audit model | Append-only JSONL journal with **SHA-256 hash-chain** (WORM semantics) |

## 2. Implemented Controls (mapped from `architecture.md` §5.1)

| ID | Domain | Implementation in the portable build |
|----|--------|---------------------------------------|
| C01 | Access Control | App is local-single-user; case manifests are per-directory; RBAC boundary = OS user + file ACLs on vault |
| C02 | Evidence Integrity | Every registered exhibit SHA-256 hashed; `inventory.json` + `inventory.csv` hash per file; hash shown in GUI |
| C03 | Event Logging | `AuditJournal` — JSONL, hash-linked; GUI tab **AUDIT** → *Verify Hash Chain* walks every entry |
| C04 | Data Protection | Vault stored beside EXE; encryption-at-rest delegated to OS disk-encryption (BitLocker) or LUKS when mounted |
| C05 | Secure Comms | ADB uses authenticated USB transport; ADB tokens bound at `adb devices`; no network egress in app |
| C06 | Vulnerability Mgmt | PyInstaller ships Python 3.12 runtime; patch by rebuilding EXE; SBOM = `requirements.txt` |
| C07 | Input Validation | Scans iterate `Path.rglob` — no shell interpolation; keys never executed |
| C08 | Secure Config | No admin rights required; no registry writes; no services; default-deny file access |
| C09 | Crypto Strength | SHA-256 + 256-bit HMAC keys; min policy AES-256 when at-rest encryption enabled |
| C10 | Supply Chain | Single pinned dependency `pyinstaller==6.22.3`; source in `app/forensics` is auditable |
| C11 | Incident Response | Journal `verify()` detects tamper; exports timed; runbook in `architecture.md` §9 |
| C12 | Physical Security | Zone model applies in-lab (architecture §3.2); device stays in Faraday procedure per SOP |
| C13 | Business Continuity | Case manifests are JSON — resumable across sessions; folder replicable |
| C14 | Regulatory Handover | Signed deliverables: PDF / DOCX / XML(SDF) / JSON / CSV / HTML + HMAC manifest |

## 3. Key Handling & Signing

```
signing.key  <- 32 random bytes, created on first report generation
report digest = HMAC-SHA256(signing.key, report bytes)
manifest      = entries {format, path, hmac_sha256} stored in case manifest.json
```

- Key lives in `evidence_vault/keys/` → **back up off-line**; losing it invalidates prior signatures.
- HSM upgrade path: replace `reporter.sign_file()` in `app/forensics/reporter.py` with a PKCS#11/TPM call while keeping the same return contract (64-hex signature).

## 4. Threat Model (summary)

| Threat | Exposure | Mitigation |
|--------|----------|------------|
| Evidence tampering | Vault files edited | SHA-256 manifests + re-verify on re-open |
| Audit-log rewriting | Journal edited | Hash-chain `verify()` flags broken link / hash mismatch |
| Malware from extracted artifacts | ADB-pulled content | Files never executed in-app; open outside or in disposable VM |
| Key theft | `signing.key` copy | Restrict vault folder ACLs; HSM for production |
| Phantom device (rogue edge) | adb spoofing | Record `adb devices -l` serial in journal; pair token check |
| Replay of reports | Re-distributed signed PDF | Immutable timestamp = journal `ts`; regenerate not allowed |

## 5. Hardening Checklist (before court use)

- [ ] Windows disk encryption (BitLocker) enabled on the carrier
- [ ] Vault folder ACL limited to the examiner account
- [ ] `signing.key` backed up to the HSM/escrow path, original removed from workstation
- [ ] USB policy: forensic write-blocker hardware in-line for future physical captures
- [ ] Antivirus exclusions avoided — run scans manually **before** importing artifacts
- [ ] Node: this build is **logical-level evidence collection** — root/acquisition images need extra tooling (link in `architecture.md` §4)

## 6. Incident Response (IR) mini-playbook

1. Suspected tamper? → **Audit tab → Verify Hash Chain**. Broken chain ⇒ record exception (that *is* evidence) and preserve original journal byte-for-byte.
2. Suspicion of malicious artifact → do **not** open in-lab; copy to isolated VM; log incident in journal.
3. Key compromise → stop signing; rekey; rebuild EXE; disclose per policy.
4. Report disputes → Rerun from `manifest.json` + `inventory.json`; every field is reproducible.

---
*Baseline v1.0 · Reviewed with architecture.md §5 compliance matrix · Review cycle 90 days*