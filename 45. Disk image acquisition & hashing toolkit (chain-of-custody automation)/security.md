# 🛡️ DIHT — Security Model & Control Implementation (security.md)

> **Disk Image Acquisition & Hashing Toolkit — Portable Build v1.0.0**
> Companion to `architecture.md`. Documents how the *actual shipped implementation* implements ISO/IEC 27001:2022, NIST SP 800-series, OWASP Top 10 (2021) and NIST CSF controls, and how evidence is preserved and protected on the acquisition host.

---

## 1. 📋 Control Objectives

| Framework | Objective applied to this tool |
|---|---|
| ISO/IEC 27001:2022 (Annex A) | Confidentiality, integrity & availability of evidence and credentials |
| NIST SP 800-86 / 800-101 | Forensically sound acquisition & preservation workflow |
| NIST SP 800-53 (§ AC, § SI-7, § SC-13, § AU) | Access control, data integrity, cryptography, audit |
| NIST SF 800-115 | Verified (validated) technical testing capabilities |
| OWASP Top 10 (2021) | Secure application layer (GUI, API, exports) |
| NIST CSF | Identify · Protect · Detect · Respond · Recover |

---

## 2. 🔐 Security By Design — Portable Tool Principles

The tool is **portable** and **forensically responsible**: it deliberately
leaves a *minimal forensic footprint* on the examination workstation.

| Principle | Implementation |
|---|---|
| **Zero host persistence** | No registry keys, no `%APPDATA%` files, no installer, no telemetry. Executable + case folder is the entire footprint. |
| **Immutability of evidence** | Source devices opened **READ-ONLY** (`CreateFileW(GENERIC_READ)` only — see `imaging.py:open_readonly`); write handles are never requested. |
| **Write-blocker handshake** | GUI blocks acquisition until the examiner confirms a hardware/software write-blocker is engaged (`ui.py` `wb_var`). |
| **Least privilege** | Raw-disk access requires Administrator; the tool requests no more rights than imaging demands. |
| **Secrets never persisted** | Passphrases are only in memory, passed to a KDF, and zeroised on close. |

---

## 3. 🧮 Cryptography

| Aspect | Setting | Standard |
|---|---|---|
| Integrity (authoritative) | **SHA-256** + **SHA3-256** streaming | FIPS 180-4 / FIPS 202; validated OpenSSL build via CPython `hashlib` |
| Secondary | BLAKE2b-256 | RFC 7693 |
| Legacy interop | MD5, SHA-1 (labelled non-authoritative) | MD5 is retained for tool-interop only, never for court integrity |
| Key derivation | PBKDF2-HMAC-SHA256, **310 000 iterations**, 32-byte key, 16-byte random salt | OWASP (2023+) PBKDF2 guidance |
| Record integrity | HMAC-SHA256 over canonical JSON + `prev_hash` hash chain | FIPS 198-1 |
| At-rest case files | Encrypt the case folder with OS-level (BitLocker/EFS) or store under the lab's encrypted vault | NIST SP 800-111 |
| In-transit | TLS 1.3 recommended for any upload/sync of the case pack | NIST SP 800-52 |

> **Reserved:** the ledger schema carries `sig` and `tsa` fields where an
> X.509 / eIDAS qualified signature and an RFC 3161 trusted-timestamp token
> are attached in the certified build (`custody.py`).

---

## 4. 🔗 Chain-of-Custody Integrity (Tamper Evidence)

Every event is **hash-chained and HMAC-signed** (`custody.py`):

```text
record[i] = { body..., prev_hash = SHA256(record[i-1]), 
              hmac = HMAC(derived_key, body), record_hash = SHA256(body) }
```

- **Alteration anywhere** breaks the chain and the HMAC → detectable.
- **Audit tool** (`Audit ledger integrity` button, `Case.audit()`) re-derives
  the key from the passphrase and verifies every record, reporting per-record
  disconnects.
- **Machine binding**: `machine_id` (SHA-256 of node+system+user) is embedded;
  the ledger refuses to sign on a different host — evidence cannot be
  "moved" silently between machines.
- Export/verification events are themselves custody records ⇒
  *the reporting of evidence is chained into the evidence record*.

---

## 5. 📊 OWASP Top 10 (2021) Implementation Status

| # | Concern | Where handled |
|---|---|---|
| A01 Broken Access Control | Role fields, per-case ledger separation; no shared mutable store; files restricted to case folder |
| A02 Cryptographic Failures | FIPS algorithms via `hashlib`, PBKDF2 310k, case data only on examiner-chosen media |
| A03 Injection | JSON handled via stdlib `json` (no eval/exec); filenames sanitised `sanitize()` in `workflow.py`; shell is never invoked |
| A04 Insecure Design | Two-person custody actions enforced procedurally; write-blocker gating is mandatory |
| A05 Security Misconfiguration | PyInstaller one-file, no network listeners, no installer, no default credentials |
| A06 Vulnerable Components | `requirements.txt` pinned, rebuild from `build_portable.ps1`, SBOM from `pip freeze` |
| A07 Identification & Auth Failures | Passphrase + fingerprint gate for all signed operations; no persistent sessions |
| A08 Software/Data Integrity Failures | Acquirer must confirm; optional post-acquisition `verify`; every export signed |
| A09 Logging & Monitoring Failures | All custody actions auto-logged to signed ledger; SIEM optional via `chain_of_custody.json` forward |
| A10 SSRF | No network egress from the tool — nothing to redirect |

---

## 6. 🗄️ Evidence Handling & Preservation

| Stage | Control |
|---|---|
| **Capture** | Read-only open; chunked streaming; digests computed *during* acquisition (no write-back) |
| **Transport** | Copy evidence pack via encrypted media/NAS; TLS if transferred |
| **At rest** | Case folder on encrypted volume; WORM-lab or object-lock vault at enterprise level |
| **Verification** | Independent re-hash; tamper test is part of the self-test |
| **Disposition** | Custody action `destroyed` records NIST SP 800-88 purge; nothing is auto-deleted by the tool |
| **Backup** | Backups re-verified by re-computing digests vs `SHA256SUMS` before restore |

---

## 7. 🧪 Security Testing Evidence

The build pipeline runs a mandatory self-test (`python -m app.main --self-test`)
covering:

1. acquisition + multi-algorithm digests,
2. clean-image verification **PASS**,
3. tampered-image verification **FAIL** (attacks are detected),
4. ledger HMAC-chain audit **PASS**,
5. report generation (PDF/PDF-A + CoC PDF), machine formats (JSON/CSV/XLSX/SHA256SUMS).

The frozen executable runs the same self-test after packaging
(`build_portable.ps1`), proving the shipped artifact behaves as written.

---

## 8. 📏 ISO 27001:2022 Annex A — Quick Mapping

| Control | Implementation |
|---|---|
| A.5.1 / A.5.15 | Access & handling policies; role-segregated examiner profile |
| A.8.9 / A.8.12 | Case-folder data owner; prevention of leakage by design (no latent copies) |
| A.8.15 / A.8.16 | Tamper-evident append-only ledger; audit UI |
| A.8.24 | FIPS-compliant crypto, PBKDF2, HMAC chain |
| A.8.29 | Self-test in CI + manual pentest checklist in `README`/build script |
| A.7.x | NDA + chain-of-custody training for examiners (org-level) |

---

## 9. ⚖️ Legal & Admissibility (Cyber Law)

- **ACPO Principle 1**: no tool action alters the source — enforced by read-only
  handle + write-blocker gate + verification.
- **ACPO Principle 2**: competency — operator/org/role are recorded per case.
- **ISO/IEC 27037**: collection & acquisition workflow matching this tool.
- **FRE 901 / Daubert**: reproducible methodology, validated hashes, complete
  audit trail, self-test evidence of tool behaviour.
- **Indian IT Act 2000 §65B / eIDAS**: the reserved `sig`/`tsa` fields allow
  qualified electronic signatures and trusted timestamps in the certified build.

---

## 10. ⚠️ Residual Risks & Operating Notes

| Risk | Note |
|---|---|
| Physical drive access requires **Administrator** | Denied otherwise — by design (least privilege) |
| MD5/SHA-1 are legacy-only | They are *additional*, never the authoritative integrity pair |
| Passphrase loss | Signing key cannot be recovered — recreate case and re-acquire |
| No RFC 3161 / X.509 in portable build | Provide certified build per case jurisdiction requirements |
| Antivirus may flag unsigned PyInstaller exe | Sign with Org EV code-signing cert; provide hash/SBOM |

> ❗ Run this tool **only** on an examiner-controlled workstation, with the
> write-blocker physically verified. The tool assumes lawful authority to
> acquire the media in question.