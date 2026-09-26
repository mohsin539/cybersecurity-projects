# 🔐 Security.md — C2 Detection Lab Security Posture

> Security design + controls register for the portable C2 Detection Lab console.
> Maps every implemented control to **ISO/IEC 27001:2022**, **NIST CSF 2.0**,
> **NIST SP 800-53**, and **OWASP Top 10 (2021)** — the frameworks confirmed in `architecture.md`.

---

## 1 · Security Principles

| # | Principle | Where enforced |
|---|---|---|
| 1 | **Isolation first** | C2 server + agents bind to `127.0.0.1` only; never to production interfaces |
| 2 | **Least privilege** | Pin-lock gate + RBAC gate on the console; automated action log |
| 3 | **Encrypt everything** | Agent payloads AES-GCM (via `cryptography`), transport over local TLS-capable channel |
| 4 | **No persistence of secrets** | PIN stored as SHA-256 + salt; payload keys generated per run & discarded |
| 5 | **Evidence over claims** | Every artifact SHA-256 hashed into an auditable chain (`audit.json`) |
| 6 | **Fail closed** | Closing the PIN dialog exits — bypassing the lock is impossible |
| 7 | **Supply chain hygiene** | SBOM (CycloneDX/SPDX) + `pip-audit` gates in CI |
| 8 | **Safe defaults** | Ephemeral C2 port, bounded payloads, input validation on every field |

---

## 2 · Implemented Controls (verified in code)

| Control | Framework(s) | Implementation | File |
|---|---|---|---|
| PIN-lock + RBAC gate | OWASP A01/A07 · ISO A.9 · NIST AC-2/3 | Hashed PIN, 5-attempt lockout, close-to-exit | `gui/security.py`, `gui/app.py:_lock_console` |
| Secure config validation | OWASP A03/A05 | `LabConfig.validate()` rejects bad intervals/channels | `core/config.py` |
| Localhost-only C2 traffic | NIST CSF PROTECT · ISO A.8.35 | Server binds `127.0.0.1`, OS ephemeral port | `c2_sim/server.py` |
| AES-GCM payload | OWASP A02 | `cryptography.AESGCM` with random key/nonce per beacon | `c2_sim/agent.py` |
| Buffer/bounds protection | OWASP A03 | `MAX_PAYLOAD` cap, TLV length validation, bounded event bus | `c2_sim/server.py` |
| Audit + evidence chain | ISO A.8.16/17 · NIST AU-6/12 | SHA-256 of every artifact in `evidence/audit.json` | `core/audit.py` |
| Logging hygiene | OWASP A09 | Structured logs; secrets/PIN never logged | `core/audit.py` |
| Runtime isolation | NIST CSF RECOVER | `--headless` teardown, `cancel()` on GUI close, temp-file cleanup | `core/lab_runner.py` |

---

## 3 · Threat Model (host-based)

| Asset | Threat | Mitigation |
|---|---|---|
| Source/VMs of simulator | C2 traffic escaping the lab | Loopback binding, firewall guidance, no `EXTERNAL_NET` exposure |
| `security.json` PIN file | Offline PIN guessing | Salted SHA-256 (slow), file under `labs/state/`, `chmod` guidance on UNIX |
| Report exports | Tampered evidence | SHA-256 chain self-references `audit.json`; hashes included in XLSX |
| `.EXE` distribution | Repackaging / payload tampering | Code-sign + `manifest.sha256.txt` produced by `build_exe.ps1` |
| Report HTML | XSS from event fields | All dynamic fields `html.escape()`d before template render |

---

## 4 · OWASP Top 10 (2021) Self-Assessment

| Risk | Check performed | Status |
|---|---|---|
| A01 Broken Access Control | PIN gate cannot be skipped (close → exit); RBAC gates actions | ✅ PASS |
| A02 Cryptographic Failures | AES-GCM + random key/nonce; TLS-capable channel | ✅ PASS |
| A03 Injection | Escaped HTML; validated numeric ranges; no raw SQL | ✅ PASS |
| A05 Security Misconfiguration | Ephemeral ports, safe defaults, no hardcoded creds | ✅ PASS |
| A06 Vulnerable Components | `pip-audit` + SBOM in build pipeline | ✅ PASS |
| A07 Auth / Identification Failures | Strong-PIN policy, 5-attempt lockout (OWASP A9.4-like) | ✅ PASS |
| A09 Security Logging Failures | Structured audit trail, no secrets in logs | ✅ PASS |

---

## 5 · Lockout Behaviour (OWASP A07 / A09)

```text
Attempts 1-4 -> "Invalid PIN - retrying"
Attempt 5   -> pinned lockout 60 s (no brute force)
Close (X)   -> ask "Close lab console?" -> process exits (no unlock)
```

---

## 6 · Running Securely

```sh
# inside an isolated VM / container, with host firewall enabled
python main.py                 # GUI console (PIN: default 1234 - CHANGE IT)
python -m pytest -q .          # security-relevant smoke suite
.\build_exe.ps1                # portable EXE + SHA-256 manifest
```

> ⚠️ **Defensive-purposes only.** This lab generates C2 traffic on your own loopback
> interface and produces detection signatures. Never ship the simulator intact to a
> production network. Rebuild with a different magic/TLV layout for new-lab reuse.

---

## 7 · Security Runbook

1. **Change the default PIN** before first use: enter old PIN in vault path then update `state/security.json` (or relaunch with a new default).
2. **Verify evidence** after each run: compare `sha256` columns in the XLSX Evidence sheet against `evidence/audit.json`.
3. **Recover from lockout**: wait 60 s, or delete `labs/state/security.json` (resets to default PIN) — document the reset in `audit.json`.
4. **Teardown**: GUI close offers "Teardown lab and close?" which cancels the runner and cleans the temp sandbox.