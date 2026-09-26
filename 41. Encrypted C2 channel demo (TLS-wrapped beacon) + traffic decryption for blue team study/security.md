# 🔒 Security Model — C2 Deconfliction Lab

> **Purpose.** Defines the security architecture, controls, and compliance posture of the demo
> **console** (web-based blue-team lab) built from `archectecture.md`.
> Authorized lab use only. No Internet egress. No production systems.

---

## 1. Scope & Authorized Use

| Attribute | Value |
|---|---|
| Classification | 🔒 Internal / Authorized lab only |
| Environment | Isolated sandbox (own infra or scoped engagement) |
| Egress | Disabled to live Internet (simulated hosts only) |
| Purpose | Blue-team education: TLS C2 anatomy, decryption, detection |
| Forbidden | Real targets, persistence, AV evasion, production exfiltration |

> [!CAUTION]
> Running this outside an authorized lab is **illegal and unethical**. The demo doubles as a
> teaching harness for defenders — not a weapon. Treat all generated keys/evidence as lab artifacts.

## 2. Security Principles (from `archectecture.md`)

1. **Split mindset** — attacker-sim (Zone A/C) and defender-observatory (Zone D) are logically separated.
2. **Encrypted by default** — TLS 1.3 outer layer + AES-256-GCM inner payload layer; no plaintext C2 blobs.
3. **Transparent telemetry** — everything logs (audit, traffic, key escrow) for study.
4. **Traceable controls** — each control maps to OWASP / NIST / ISO 27001.
5. **Portable evidence** — `.xlsx` / `.csv` / `.html` exports, never copy‑paste.

## 3. Crypto & Transport Policy

Implemented in `app/core/crypto.py`, `app/core/security.py`, config in `app/config.py`.

| Control | Setting | Reference |
|---|---|---|
| TLS min version | `TLS1.3` (config), TLS 1.2 tolerated | NIST SP 800-52 |
| Preferred cipher | `TLS_AES_256_GCM_SHA384` | NIST SC-13 |
| Inner payload layer | AES-256-GCM, 96-bit random nonce, 256-bit escrowed key | ISO A.8.24 |
| Key derivation | `secrets.token_hex` (CSPRNG) | NIST IA-5 |
| Certificates | Self-signed lab CA via `cryptography` (dev/HTTPS mode) | ISO A.8.24 |
| HSTS/reneg | Not applicable locally; don't enable renegotiation | OWASP A02 |

**KEYLOG handling.** `SSLKEYLOGFILE`-equivalent capture exists **only** in the lab profile
(`key_type='sslkeylog'`). It is the blue-team teaching surface, never a production pattern.

## 4. Key Custodianship (simulated SSLKEYLOG / escrow)

| Key type | Where | Rotation | Exposure |
|---|---|---|---|
| Session AES (inner layer) | `keys` table, `status='escrow'` | `POST /api/admin/keys/rotate` | Console "Security" tab |
| Simulated TLS (pre-)master | `keys` table, `type='sslkeylog'` | per session | Decryption lab |
| Server TLS key | `data/certs/` mounted only in HTTPS mode | regenerate via `ensure_lab_certs` | filesystem |

> ⚠️ **Do not** place real production key material in this demo. The escrow table is intentionally
> readable so analysts can study the decryption path (ISO A.8.24 dual-integrity trade-off).

## 5. Authentication & Authorization

| Surface | Mechanism | Location |
|---|---|---|
| Console UI/API | `X-Lab-Token` bearer (random 48-hex, stored in `data/admin_token.txt`) | `app/main.py` middleware |
| Beacon → panel | Session UUID + kill-switch guard | `app/core/security.py` |
| Report download | `?token=` query check (browser download) | `app/api/reports.py` |
| Static UI | token fetched from `/api/admin/hello` at boot | `console.js` |

Scope of protection: `/api/panel`, `/api/blue`, `/api/reports/{list,generate}`, `/api/admin/*`.
`/api/v1/beacon/*` uses UUID identity (beacon registration with agent-name resume).

## 6. Audit & Monitoring

Every state-changing action writes to `audit_log` (actor, action, zone, detail, IP):
`register`, `task`, `update:{status}`, `rule:{on/off}`, `alert:{status}`, `decrypt_*`, `rotate_keys`, `generate`.

Viewable at **Security → Audit**. Exported into `.xlsx` sheet `AuditLog` and `.html` report.

## 7. Detection Engineering (Defender focus)

- JA3/JA3S-style fingerprints derived per session (ciphertext-only signal).
- Risk formula per `archectecture.md` §10:
  `0.35·JA3 novelty + 0.25·periodicity + 0.20·novel DST + 0.10·size variance + 0.10·decrypt success → 0–100`
- 5 correlation rules (`R-001..R-005`) seeded and toggleable at **Detections**.
- Alerts triage lifecycle: `new → triaged → resolved`.

## 8. Framework Compliance (implementation trace)

### 🟢 OWASP Top 10 (2021) — how the console addresses it

| ID | Control implemented |
|---|---|
| A01 Broken Access Control | Token-gated panel/blue/report zones; UUID-gated beacon API |
| A02 Cryptographic Failures | TLS policy enforced; AES-256-GCM inner layer; no homebrew crypto |
| A03 Injection | Parameterized SQL (all `db.py` queries); HTML escaping (`esc()`) |
| A04 Insecure Design | Zone isolation, threat model in `security.md`, defense-in-depth |
| A05 Security Misconfiguration | Config-as-code lab defaults; `lab_mode` flag; no debug in report paths |
| A06 Vulnerable Components | Pin via `requirements.txt`; SBOM generation recommended before release |
| A07 Authentication Failures | CSPRNG tokens; token rotation via admin; kill-switch per beacon |
| A08 Integrity | Reports immutable files; audit log append-only style |
| A09 Logging/Monitoring Failures | Structured audit + traffic + keylog telemetry; alert pipeline |
| A10 SSRF | Only local bind (127.0.0.1 default); no upstream URL fetch anywhere |

### 🟠 NIST CSF 2.0 + SP 800-53

| Function | Console evidence | Controls |
|---|---|---|
| **Govern** | security.md risk register | SA-3, PL-2 |
| **Identify** | session/asset inventory in Beacons tab | CM-8, RS-2 |
| **Protect** | TLS 1.3, AES-GCM, token auth, certs | SC-8, SC-13, IA-5 |
| **Detect** | correlation rules, JA3-style fingerprints, alerts | AU-6, SI-4 |
| **Respond** | alert triage, kill-switch, session flagging | IR-4, IR-6 |
| **Recover** | evidence bundles, reseedable demo data | IR-4, CP-4 |

### 🔵 ISO/IEC 27001:2022 Annex A

| Control | Application |
|---|---|
| A.5.14 Info transfer | TLS-wrapped transport only |
| A.8.9 Config management | config-as-code + run flags |
| A.8.12 Vulnerability mgmt | dependency pins + SBOM (release gate) |
| A.8.15/16 Logging & monitoring | audit/telemetry → console & reports |
| A.8.24 Use of cryptography | AES-256-GCM + X25519-style TLS suites, key custody |
| A.8.26 App security | OWASP-informed review of all endpoints |

## 9. Threat Model

| Scenario | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Demo breakout / uncontained agent | Low | High | Bind to 127.0.0.1, no egress, sandbox flags |
| Key/cert leakage | Medium | High | Per-session escrow, rotation endpoint, lab-only material |
| Console token disclosure | Medium | Medium | Token regenerates per install; rotate on exposure |
| False-positive alert fatigue | Medium | Low | Baseline rebuild of JA3/periodicity, rule toggles |
| Legal misuse of the pattern | — | Critical | Authorized-use banner (UI + this doc), console-lab mode |

## 10. Operations Runbook

```powershell
# 1) seed + launch (web-preferred)
python tools\demo_seed.py
python run.py --open

# 2) HTTPS profile (self-signed lab cert auto-generated)
python run.py --https

# 3) spawn a simulated beacon against the console (sandbox exercise)
python beacon_agent.py --server http://127.0.0.1:8443 --name lab-beacon-1

# 4) portable exe build (optional)
powershell -ExecutionPolicy Bypass -File build_exe.ps1
```

**Incident mini-playbook (blue):**
1. Detect alert → check Risk & session details (Beacons tab).
2. Use **kill-flag** on the session (revoke heartbeats).
3. Decrypt session/records (Traffic tab) to read task/result plaintext.
4. Export `.xlsx/.csv/.html` evidence bundle (Reports tab).
5. Rotate session keys (Security tab) → archive audit trail.

## 11. Known Limitations & Hardening Backlog

- [ ] SQLite at-rest encryption not enabled in lab build (accepted risk; add `sqlcipher` for release).
- [ ] `request` bodies are plaintext JSON over HTTP in dev; use `--https` profile for transport realism.
- [ ] Report downloads use `?token=` — fine for lab; move to Secure Cookie if internet-exposed.
- [ ] No rate limiting on beacon API (could add token-bucket to harden).
- [ ] Seed data simulates fingerprints; real JA3 capture recommended for production training.

## 12. Verification Summary (2026-09-20)

Smoke test executed end-to-end with `TestClient` and live `uvicorn` boot:
- register → ping → task → encrypted result → rules fired — ✅
- decrypt record/session via escrowed key — ✅
- reports `.xlsx` (14.4 KB), `.csv` (9.0 KB), `.html` (32.6 KB) — ✅ downloads with valid token, 401 on bad/missing — ✅
- compliance endpoint returns `owasp|nist|iso` matrices — ✅
- console `/`, `/static/*` — HTTP 200 — ✅
- risk scoring live: high-activity beacon 96.5/100 — ✅

---
*Authorized lab study only · Maintainers update this file whenever the security posture changes.*