# 💎 PrismForge

A secure, audited, web-based **3D product configurator** — drag, rotate and customize
products in the browser, with compliance-grade reporting and a tamper-evident audit trail.

> Part of the [AI Masterclass cybersecurity portfolio](../../#readme) — project 76 of 72.
> Demo/educational project; not a production storefront.

## 🧱 Tech Stack

| Layer | Technology |
|---|---|
| **API** (`apps/api`) | Node.js ≥ 20 · TypeScript · Express · Zod validation · Helmet |
| **Persistence** | Node built-in `node:sqlite` — **zero native addons**, no node-gyp |
| **Auth** | JWT (`jose`) + scrypt password hashing (NIST SP 800-132) |
| **Audit trail** | Hash-chained, append-only audit log with checkpoint verification |
| **Reports** | PDF (pdfkit) / Excel (exceljs) export |
| **Shared** (`packages/shared`) | Catalog, pricing, schema — used by both apps |
| **Tooling** | npm workspaces, tsx, tsc typecheck |

## 🚀 Quickstart

```bash
npm install          # install all workspaces
npm run db:migrate   # create + migrate the SQLite database
npm run db:seed      # seed demo catalog data
npm run dev          # API + web in watch mode
```

Production start: `npm start`. Database utilities: `npm run db:reset`, `npm run db:seed`.

## 🧪 Verification

```bash
npm run typecheck    # tsc --noEmit across workspaces (--if-present)
npm run lint         # currently mirrors typecheck
npm run test         # workspace tests (--if-present)
npm run audit:verify # verify hash-chain integrity of the audit log
npm run audit:report # emit an audit report
```

## 🗂️ Project Layout

| Path | What it is |
|---|---|
| `apps/api/src/index.ts` | Boot: migrate → bind loopback → graceful shutdown + watchdog |
| `apps/api/src/http/` | Auth, security, validation, audit middleware |
| `apps/api/src/modules/` | admin, audit, auth, catalog, configurations, health, reports |
| `apps/api/src/db/` | SQLite driver, migrations, seed, audit chain CLI |
| `packages/shared/` | Catalog, pricing & schema shared between client and API |
| `scripts/smoke.mjs` | End-to-end smoke test |

## 🔒 Security Notes

- Binds to **loopback by default**; Helmet security headers; strict Zod input validation
- Secrets via `.env` (see `apps/api/.env.example`) — never committed
- **OWASP A05/A06-aligned**: no key material in the repo, no compiled supply-chain paths
- Audit log is **tamper-evident** (hash-chained); verify with `npm run audit:verify`

## 🧪 CI

A GitHub Actions job runs typecheck, lint and workspace tests on every push — see
[`.github/workflows/ci.yml`](../../blob/master/.github/workflows/ci.yml).
