# 🥽 WebXR Security Awareness Training Module

A complete, working, browser-based immersive security training platform — with **zero runtime
dependencies** (Node stdlib only). Built to the reference design in
[`architecture.md`](architecture.md); security posture in [`security.md`](security.md);
state design in [`state.md`](state.md); data/retention in [`memory.md`](memory.md).

## Quickstart

```bash
npm test        # 22 security & integration tests (should print: pass 22)
npm start       # → http://localhost:8443
```

Then:

1. Open **http://localhost:8443**
2. Click **“Try demo (learner)”** — or sign in as the seeded admin
   (local mode seeds `admin@corp.example` / `Admin#Passw0rd!` when `ADMIN_SEED_PASSWORD` is set)
3. Start **Phishing Email Triage**, make decisions, get a server-computed debrief
4. Check **Dashboard** for scores; sign in as admin to see the **hash-chained audit log**
   and verify its integrity

## What's Included

| Layer | Details |
|---|---|
| 🖥️ **WebXR client** (`public/`) | PWA with WebXR Device API detection (immersive-vr/ar), graceful 3D/DOM fallback, 5 training modules, dashboards, admin console. All DOM writes via `textContent` (XSS-safe), strict CSP honored |
| ⚙️ **API server** (`server/`) | Auth (scrypt + HMAC tokens, rate-limited), module catalog, session lifecycle, **server-side scoring**, xAPI-style records, RBAC admin, **hash-chained audit log** |
| 🧪 **Tests** (`tests/`) | 22 tests: crypto, tokens, tamper detection, RBAC, rate limiting, path traversal, headers, full training flow |
| 🔒 **Frameworks** | ISO 27001:2022 control↔code↔test matrix, NIST 800-53/800-63B/800-207 mappings, OWASP Top 10:2021 mitigations — all in [security.md](security.md) |

## Training Modules

📧 Phishing Email Triage · ☎️ Vishing & Deepfake Call · 🚪 Tailgating & Badge Security ·
🦠 Ransomware Response Drill · 💾 Data Handling & Clean Desk

## Configuration

| Env var | Required | Purpose |
|---|---|---|
| `JWT_SECRET` | ✅ in production | Token signing key (fail-fast boot check) |
| `FIELD_KEY` | ✅ in production | 64-hex (32-byte) AES-256-GCM key for PII encryption |
| `ADMIN_SEED_PASSWORD` | local only | Seeds the demo admin account |
| `NODE_ENV=local` | optional | Enables demo login + ephemeral dev keys |
| `PORT` | optional | Default `8443` |
| `DATA_DIR` | optional | Data directory (default `./data`) |

> `NODE_ENV=local` generates ephemeral keys per boot (tokens reset on restart) — the single
> documented dev-mode deviation, per [security.md §2.1](security.md).

## Production Notes

- Deploy behind a TLS-terminating proxy (config in [security.md §2.3](security.md))
- Run `npm run retention` on a schedule (GDPR storage limitation — [memory.md §3](memory.md))
- Roadmap to PostgreSQL/SSO/WORM-SIEM: [security.md §3](security.md)

## Verification

```bash
npm test          # unit + HTTP integration, all green required
curl -s localhost:8443/api/health | jq .auditChainValid   # true = audit chain intact
```
