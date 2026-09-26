# 🌍 AEGIS-SENTINEL

**WebGL-based global data-breach & live threat feed visualization** — secure by design, auditable by default.

A 3D neon-noir command center: live threat arcs pulse across a GPU-rendered globe, every action lands in a tamper-evident audit ledger, and any filtered view exports as a signed, court-ready report.

![React 18](https://img.shields.io/badge/React-18-61dafb) ![Three.js](https://img.shields.io/badge/Three.js-r160-white) ![TypeScript](https://img.shields.io/badge/TS-strict-3178c6) ![Vitest](https://img.shields.io/badge/tests-passing-3ae374)

## Quickstart

```bash
npm install
npm run dev        # → http://localhost:5173
npm run build      # typecheck + production build
npm test           # ledger tamper-evidence tests
```

## What you get

| Area | Details |
|---|---|
| 🌐 **Live 3D globe** | Dash-flow threat arcs, glow markers, shockwave rings on critical events, bloom post-FX, starfield, point-cloud continents. 60 fps budget with live perf HUD. |
| ⚡ **Threat stream** | Deterministic mock feed (same contract as the production WSS client) with backfill + live batches. |
| 🎛️ **Filters** | Severity (shape + color coded), category, feed source trust tiers, risk floor, time window. |
| 📄 **Signed reports** | Executive HTML (print→PDF), CSV, JSON, STIX 2.1 bundle, Audit Pack — each SHA-256 digested + Ed25519 signed. |
| 🧾 **Audit ledger** | Hash-chained, append-only, in-app viewer with one-click chain verification + JSON export. |
| 🔐 **RBAC** | viewer / analyst / auditor / admin roles with central `allow()` decision point — try switching roles in the HUD. |

## Documentation

- [`architecture.md`](./architecture.md) — full system architecture (§1–18)
- [`security.md`](./security.md) — security & compliance framework implementation
- [`state.md`](./state.md) — client state architecture
- [`memory.md`](./memory.md) — data retention, persistence & lifecycle

## Keyboard & interaction

- Click a marker → drill-down drawer (IOCs, provenance, ATT&CK).
- Click an IOC chip → copy (audited).
- 🎬 Cinematic orbit for SOC-wall displays · 🎥 Director mode flashes on critical events · 📊 perf HUD toggle.
