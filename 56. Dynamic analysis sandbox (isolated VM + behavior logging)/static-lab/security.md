# 🛡 Security Framework — StaticLab

Security model for the portable static-analysis pipeline, aligned with the parent
architecture (`architecture.md` §9) and the frameworks it references.

---

## 1. Threat Model (STRIDE applied to this tool)

| Threat | Risk | Mitigation |
| :--- | :---: | :--- |
| **Malicious sample injection** (user analyze a hostile file) | Med | All input is treated as untrusted: no execution, strings are only displayed/escaped, export writers use HTML-escape, samples never auto-open |
| **Lateral exfiltration of API keys** | High | Keys only live in a DPAPI-encrypted vault (`secrets.bin`) and in memory during a lookup; never logged, never embedded in reports |
| **Audit forgery / repudiation** | Med | Append-only SQLite ledger; each row HMAC-SHA256-signed with a machine-scoped key; chain hash links every row to its predecessor; `verify_chain()` walk |
| **Report tampering** | Med | Reports embed the audit chain hash; HTML report shows VERIFIED/FAILED status; manifest concept reserved for the evidence bundle |
| **Supply-chain (exe/distribution)** | Med-High | Deps pinned, build is reproducible via `build.ps1`; release exe should be Authenticode-signed (hint provided) |
| **Code injection via API responses** | Low | Providers return JSON; only primitives are rendered, URLs are escaped in HTML export |
| **Local DoS (huge files)** | Low | Streaming hash (1 MB chunks), string runs bounded, report string counts capped |

**Assumption:** analyst console runs on a trustworthy host; the sample itself is never executed by this tool.

---

## 2. What the tool does NOT do (explicit boundary)

- ❌ Does **not execute** samples (that is the dynamic sandbox half of the architecture).
- ❌ Does **not** submit samples to providers (lookups are hash-based only).
- ❌ Does **not** store plaintext secrets anywhere.
- ❌ Does **not** phone home; all network traffic is opt-in (per-provider API key) over TLS 1.2+.

---

## 3. Compliance mapping (surface)

### ISO/IEC 27001:2022 (Annex A highlights)
| Control | Application |
| :--- | :--- |
| A.5.15 / A.5.17 | Console is local; secret vault integrity controlled by OS (DPAPI) |
| A.7.10 Malware Protection | Static pre-analysis in an isolated (non-executing) pipeline |
| A.7.15 Logging | Audit chain ledger for every analysis & report export |
| A.8.10 Info Removal | Config/store under `%APPDATA%\StaticLab`; delete dir to purge |
| A.8.28 Secure Coding | Input escaping, param SQL, boundary checks, safe defaults |

### NIST SP 800-53r5 (families touched)
`AC`·`AU` (AU-3/6/8/11 audit + review via Verify) · `SC` (SC-13 signatures/HMAC, SC-28 at-rest vault) · `SI` (SI-7 integrity → chain verification, SI-11 sanity on malformed PE).

### OWASP Top 10 (2021)
| ID | Weakness | StaticLab Mitigation |
| :--- | :--- | :--- |
| A02 | Crypto failures | TLS ≥1.2 to providers; DPAPI AEAD vault; SHA-256 chain/HMAC |
| A03 | Injection | HTML-escape all string fields in exports; SQLite uses only bound params |
| A06 | Vulnerable components | Pinned `pefile`; runtime deps = stdlib only |
| A07 | ID/auth failures | Provider creds kept out of source and logs |
| A09 | Logging failures | Every analysis/export is an audit entry with verification UI |

---

## 4. Secrets handling (implementation detail)

- `app/config.py` → `SecretVault`: `CryptProtectData`/`CryptUnprotectData` (Windows DPAPI, current-user scope).
- Vault file header `STL-VAULT-1` + DPAPI blob. Plaintext is never persisted on disk.
- `audit.key`: random 32-byte HMAC key, created on first run under `%APPDATA%\StaticLab\`.

## 5. Audit ledger (implementation detail)

- `app/core/audit.py` — SQLite table `audit_chain(id, chain_hash, prev_hash, ts, payload, mac)`.
- `chain_hash = SHA256("StaticLab::audit::v1" | prev_hash | ts | payload | nonce)`
- `mac = HMAC-SHA256(chain_key, prev_hash|ts|payload)`
- Tamper anywhere ⇒ `verify_chain()` reports the exact record(s).

## 6. Hardening checklist for release

- [x] No secrets in code; no logs of keys
- [x] HTML report escapes user-controlled strings
- [x] CLI/JSON output clean (progress → stderr, report → stdout)
- [x] Streaming hashing (memory-bounded)
- [ ] Code-sign the `.exe` (Authenticode + RFC-3161 timestamp)
- [ ] Add a release SBOM + hash manifest