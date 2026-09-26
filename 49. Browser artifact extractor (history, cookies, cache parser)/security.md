# Browser Artifact Extractor — Security

**Document status:** published · **Version:** 1.0.0 · **Owner:** security/engineering
**Scope:** security architecture, threat model, control implementation, verification.

This document records **what**, **why** and **how to verify** each security control.
It is the companion to `architecture.md` and the source for the in-app
**Compliance** view.

---

## 1. Security objectives

1. **Integrity** — prove collected evidence is exactly what was on the host.
2. **Confidentiality** — secrets stay on-device, masked by default, never
   transmitted.
3. **Accountability** — every action is attributable (who/what/when).
4. **Non-invasiveness** — the host's evidence is never modified or destroyed.
5. **Least functionality** — the tool does only collection and reporting.

---

## 2. Trust model

| Actor | Trust | Notes |
|---|---|---|
| Operator (GUI/CLI user) | **High** | Consent to decrypt, case metadata; captured in audit log |
| Local browsers / profiles | **Untrusted data** | SQLite/JSON content is attacker-controllable (crafted bookmark titles, cookie values) |
| Host OS | **Trusted base** | DPAPI (Crypt32) and WAL/ACL semantics define the boundary |
| Report consumers | **Untrusted** | Never execute report content; HTML/XML is escaped |
| The tool itself | **Trusted** | Single artifact, no dynamic plugin loading |

---

## 3. Threat model (application-level)

| Threat | Vector | Mitigation | Control ref |
|---|---|---|---|
| Tampered evidence | Post-collection edits | SHA-256 manifest + HMAC option | NIST 800-86 3.2/3.3 |
| Tampered audit | Retro-active log edits/deletions | SHA-256 **hash chain** with `verify()` | ISO A.8.15, NIST AU-9 |
| Injection into reports | Crafted title / cookie value | `html.escape` on every value; SAX escaping; parameterised SQL | OWASP A03 |
| Data exfiltration | Compromised analyst box | **Zero network** code paths; grep-invariant | ISO A.8.12 |
| Secret disclosure | Careless export | Masked defaults; opt-in decrypt; status labels | ISO A.8.11 |
| Locked-file bypass | Browser holds exclusive lock | Acquisition ladder incl. **elevated VSS**; never kills browser | ISO A.8.3 |
| Supply chain | Tainted dependency | Pinned ranges in `requirements.txt`; report lists versions | OWASP A06 |
| CSV injection | Value beginning `=`, `+`, `-`, `@` | `csv.QUOTE_ALL` quoting on all fields | OWASP A03 |
| Path traversal | Crafted profile names | Paths built from OS APIs; no user-supplied targets | NIST SI-10 |
| Memory scrubbing | Session key recovery | Key cached in-process only; temp copies removed | ISO A.8.10 |

---

## 4. Control implementation map (20 controls)

Generated from `sec/compliance.CONTROLS`. Grouped by framework.

### ISO/IEC 27001:2022
| Control | Implementation | Verify |
|---|---|---|
| **A.5.15** Access control | Operator consent gates decryption; read-only source access | Set `--decrypt` only with consent; observe no writes to profiles |
| **A.8.3** Evidence handling | DB copied to `tempfile.mkdtemp` before parse; originals untouched | Check profile dir mtimes unchanged after scan |
| **A.8.10** Information deletion | Temp dirs `rmtree`'d in `finally`; keys in-memory only | Run scan; confirm no `bae_db_*` dirs remain |
| **A.8.11** Data masking | Cookie/password values `""` unless `decrypt_secrets` | Export without `--decrypt`; values masked |
| **A.8.12** DLP | No socket/urllib/http code anywhere | `rg -i "socket\|urlopen\|http\\."` on source |
| **A.8.15** Logging | JSONL audit, hash-chained, severity floor configurable | `sec.audit.AuditLogger.verify()` |
| **A.8.24** Cryptography | AES-256-GCM (Chromium v10/v11), DPAPI unwrap, SHA-256 | Inspect `core/decrypt.py` |

### NIST SP 800-53 Rev.5
| Control | Implementation | Verify |
|---|---|---|
| **AU-2/AU-3** Event logging | timestamp, level, event, actor, host, pid, details | Inspect `audit_log.jsonl` schema |
| **AU-9** Audit protection | HashChain `chain_prev`/`chain`; genesis `"0"*64` | Delete one line; `verify()` → `False` |
| **SC-8/SC-13** Crypto | DPAPI + AES-GCM (session), hashing (at rest) | Key length checks (16/24/32) in `load_master_key` |
| **SI-10** Input validation | Bounded wildcard glob (`Arc` path), parameterised SQL, `limit` coercion | Code review `paths/extractors` |
| **CM-7** Least functionality | No eval/exec, no plugin hooks, no network, feature flags only | `rg "eval\|exec(" core sec report ui` |

### NIST SP 800-86
| Control | Implementation | Verify |
|---|---|---|
| **3.2** Collection integrity | `sha256_file` per artifact recorded in manifest | Compare manifest hash of a copy via `sha256sum` |
| **3.3** Chain of custody | collector, host, timestamps, digests in report header | Open any report; header printed |

### OWASP Top 10:2021
| Control | Implementation | Verify |
|---|---|---|
| **A01** Broken access control | Selection-scoped collection; no privilege escalation path | Profile filter rejects labels outside discovered set |
| **A03** Injection | HTML escaped, XML SAX-escaped, CSV quoted, SQL parameterised | Feed `<script>alert(1)</script>` bookmark → renders as text |
| **A05** Misconfiguration | Safe defaults (masked, limited records, offline); no debug endpoints | Review `ScanOptions` defaults |
| **A06** Vulnerable components | Version ranges pinned in `requirements.txt`; bootstrapped exe | `pip check` in build env |
| **A08** Integrity failures | Manifest digest + optional HMAC `sign_manifest(secret)` | Re-run report; digest stable |
| **A09** Logging & monitoring | Full audit trail + `--cli` summary of chain validity | CLI output prints `Audit chain` |

---

## 5. Secret-handling lifecycle (opt-in only)

```
Local State (os_crypt.encrypted_key)          browser cookies / Login Data
      │ base64                                   │ bytes
      ▼                                          ▼
  strip "DPAPI" prefix                      prefix byte ?
  DPAPI unwrap (current user)            ┌── v10/v11 ── AES-256-GCM (nonce 3:15, tag -16:)
      ▼ key (16/24/32 B)                ├── v20 ───── status "v20_appbound" (unsupported)
  cached in-process per user_data       └── other ─── DPAPI raw blob
```

Rules enforced in code:
- Key material exists **only in process memory** (`engine._key_cache`).
- `decrypt_value()` always returns a **status** alongside plaintext.
- Firefox `logins.json` NSS-encrypted fields keep status `encrypted` — no key is
  ever written to a report.
- v20 (App-Bound Encryption, Chrome 127+) is **reported, not decrypted**.
- Reports emitted in a `--decrypt` run must be handled as sensitive; the audit log
  records the consent event (`secrets.decrypt_enabled`).

---

## 6. Audit log design (tamper-evident)

Record shape (one JSON object per line):

```json
{
  "timestamp":  "2026-09-21T14:36:20.123+00:00",
  "level":      "INFO",
  "event":      "scan.start",
  "actor":      "operator",
  "host":       "hostname",
  "pid":        12345,
  "message":    "...",
  "details":    {...},
  "chain_prev": "<sha256 of previous record>",
  "chain":      "<sha256 of this record + chain_prev>"
}
```

- Each record's `chain` = SHA-256(canonical(record) + chain_prev).
- `HashChain.verify(entries)` replays the chain from genesis; any edit/delete
  breaks it.
- GUI button **Verify Audit Chain** and CLI `Audit chain` line expose the result.

---

## 7. Evidence integrity workflow

1. During collection, `Engine._record_evidence` hashes each file source
   (`sha256_file`, streaming 1 MiB chunks).
2. `build_manifest()` writes the canonical JSON digest (`manifest_sha256`) over
   all evidence items.
3. `scan.integrity.manifest` is embedded in **every** report and
   `evidence_manifest_<ts>.json`.
4. Optional HMAC: `sec.integrity.sign_manifest(manifest, secret)` for external
   verification by a keyholder.

Reproducibility: given the same host state, a re-run yields the same file digests
for unchanged artifacts; the manifest digest is deterministic over its items.

---

## 8. Output sanitisation

- HTML: `templates._e()` = `html.escape(value, quote=True)` on headers, cells,
  metadata of every string.
- XML: `xml.sax.saxutils.escape`.
- CSV: `csv.writer` with `QUOTE_ALL` (defeats formula injection).
- Markdown: `|` escaped in cells.
- XLSX: values written as strings via openpyxl (no formula evaluation on write).
- SQLite reads: parameterised queries only; rows decoded `errors="replace"`.

---

## 9. Supply chain & build hygiene

- `requirements.txt` uses caret/set range pinning.
- `build_portable.py` excludes analysis-only packages (numpy/matplotlib/etc.) to
  minimise attack surface and size.
- One-file PyInstaller binaries can trigger AV false positives — documented in
  README troubleshooting; `--onedir` is the fallback distribution.
- Running `pip check` and `pip-audit` on the build environment is recommended
  before releases.

---

## 10. Verification playbook

```powershell
# 1. Static hygiene
rg -n -i "socket|urlopen|urllib.request|requests\." core sec report ui main.py   # expect nothing

# 2. Escaping (OWASP injection)
python - <<'PY'
from report.templates import _e
assert _e('<img src=x onerror=alert(1)>') == '&lt;img src=x onerror=alert(1)&gt;'
PY

# 3. Audit tamper detection
python - <<'PY'
import json
from sec.integrity import HashChain
entries=[json.loads(l) for l in open(r'BAE_Output\...\audit_log.jsonl')]
assert HashChain.verify(entries)          # valid
del entries[1]; assert not HashChain.verify(entries)   # detected
PY

# 4. Source invariance
(Get-Item "$env:LOCALAPPDATA\Google\Chrome\User Data\Default\History").LastWriteTime  # before/after scan

# 5. Manifest reproduction
sha256sum report_*.json evidence_manifest_*.json
```

---

## 11. Residual risks (accepted)

| Risk | Reason accepted | Compensating control |
|---|---|---|
| Chromium v20 App-Bound cookies undecrypted | Requires browser's privileged COM service | Labelled `v20_appbound`; still collected |
| Firefox NSS logins undecrypted | `key4.db` + NSS master password may apply | Metadata extracted; fields flagged |
| Live locked `Cookies` (non-elevated) skip | Hard exclusive lock by design | VSS path when elevated; clear operator messaging |
| One-file AV false positives | PyInstaller bootloader | Signed distribution; `--onedir` fallback |