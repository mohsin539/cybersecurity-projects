# 📌 Project State — C2 Deconfliction Lab

> Living status/decision log for the **Encrypted C2 channel demo (TLS-wrapped beacon) +
> traffic decryption** built to `archectecture.md`. Update this file as work progresses.

---

## 1. Status at a Glance (2026-09-20)

| Milestone | Phase (from arch roadmap) | State |
|---|---|---|
| Architecture (`archectecture.md`) | Phase 1 · Foundations | ✅ Delivered |
| Threat model + zones design | Phase 1 | ✅ Delivered (encoded in code + security.md) |
| Beacon ↔ C2 TLS session | Phase 2 · Red build | ✅ Delivered (simulation + real AES inner layer) |
| Capture + decrypt lab | Phase 3 · Blue build | ✅ Delivered (SSLKEYLOG-sim + escrow decrypt) |
| Correlation rules + risk scoring | Phase 3 | ✅ Delivered (R-001..R-005 + composite formula) |
| Reporting engine (.xlsx/.csv/.html) | Phase 4 | ✅ Delivered |
| OWASP/NIST/ISO traceability | Phase 4 | ✅ Delivered (console tab + reports) |
| Web console GUI | Industry-standard delivery | ✅ Delivered (portable web app) |
| Portable .exe | Packaging bonus | 🟡 Scripted (`build_exe.ps1` + `build.spec`); not yet built in this session |
| Full DRY-RUN + lesson pack | Phase 4 | 🟡 Next step (see §6) |

**Overall:** MVP complete and verified. Remaining work is polish + packaging execution.

## 2. Deliverable File Map

```
project root/
├── archectecture.md          comprehensive architecture (+ security frameworks + report formats)
├── security.md               security model, controls, compliance mapping, runbook
├── state.md                  this file
├── memory.md                 agent/human persistence & conventions
├── requirements.txt          pinned runtime dependencies
├── run.py                    launcher (--seed --https --open)
├── run_entrypoint.py         PyInstaller entry shim
├── beacon_agent.py           standalone simulated beacon (sandbox, authorized-lab)
├── build.spec / build_exe.ps1  portable exe packaging
├── app/
│   ├── config.py             constants, paths, TLS policy
│   ├── db.py                 sqlite3 layer (WAL, parameterized)
│   ├── main.py               FastAPI app + token authz middleware + routes
│   ├── api/                  beacon · panel · blue · reports · admin routers
│   ├── core/                 crypto (AES-GCM/JA3/fingerprint) · security (keys/audit/certs)
│   ├── services/             tasking · capture · decryption · detection · reporting
│   ├── static/               single-page console (index.html, console.css, console.js)
│   └── templates/            report.html.j2 (evidence report)
├── tools/demo_seed.py        3 realistic sessions + staggered traffic + alerts
└── data/                     runtime: c2lab.db, admin_token.txt, certs/, reports/, evidence/, logs/
```

## 3. Feature Status Matrix

| Feature | Endpoint / Tab | Status |
|---|---|---|
| Beacon register (mTLS-style, resume-aware) | `POST /api/v1/beacon/register` | ✅ |
| Heartbeat ping + traffic record | `POST /api/v1/beacon/ping` | ✅ |
| Task poll (queued→sent) | `GET /api/v1/beacon/tasks/{uuid}` | ✅ |
| Result callback (AES-GCM decrypted server-side) | `POST /api/v1/beacon/result` | ✅ |
| Kill-switch + flag | `PATCH /api/panel/sessions/{uuid}` | ✅ |
| Task console | `POST /api/panel/tasks` | ✅ |
| Traffic feed + decrypt record/session | `POST /api/blue/decrypt/*` | ✅ |
| Rules toggle + alert triage | `POST /api/blue/rules|alerts/action` | ✅ |
| Reports generate + token-gated download | `POST/GET /api/reports/*` | ✅ |
| Compliance matrix | `GET /api/admin/compliance` | ✅ |
| TLS policy + keys + audit | `GET /api/admin/tls|keys|audit` | ✅ |
| Demo beacon from UI | Beacons tab → "Run demo beacon" (WebCrypto AES-GCM) | ✅ |
| Demo seed | `python tools\demo_seed.py` | ✅ |
| HTTPS profile (self-signed) | `run.py --https` | ✅ (verified boot) |
| Account/RBAC, real mTLS client certs, live pcap ingestion | — | 🔴 Future |

## 4. Decision Log (ADR-lite)

| # | Decision | Why | Status |
|---|---|---|---|
| D-1 | **Web-first**, `.exe` as bonus | User preference; FastAPI runs anywhere, debuggable, UI-rich | ✅ |
| D-2 | **sqlite3 stdlib**, no SQLAlchemy | Zero extra deps, enough for lab scale, simpler packaging | ✅ |
| D-3 | **AES-256-GCM inner layer** with escrowed key = "SSLKEYLOG" | Faithful to arch §8 onion model + real working decrypt demo | ✅ |
| D-4 | **Beacon API auth = UUID**; panel/blue/admin = `X-Lab-Token` | Separation of concerns; beacons need no human token | ✅ |
| D-5 | Download auth via `?token=` | `window.location` cannot set headers; lab-acceptable | ✅ |
| D-6 | Simulated capture records (no live pcap) | Keeps bundle portable/offline; swap-in tshark later | ✅ |
| D-7 | ASCII-only CLI banner | Windows cp1252 console cannot print box-drawing chars | ✅ |
| D-8 | Per-row report bundle records | Comma-joined paths broke `FileResponse` on Windows | ✅ |

## 5. Verification History

- **Smoke test 1** — fixed `reporting._scope_data` missing bindings (sqlite param count).
- **Smoke test 2** — fixed Jinja `data.keys` → `data["keys"]`.
- **Smoke test 3** — fixed report path comma-join → per-format rows; demo_seed `sys.path`.
- **Smoke test 4** — fixed `compute_risk` int cast (`strftime %s` returns str); seeded staggered timestamps; live peak-risk in stats.
- **Live boot** — `run.py --port 8765` → `/api/health` 200, `/` 200.

## 6. Known Issues / Open Items

1. 🟡 `.exe` packaging not executed (requires ~1–3 min PyInstaller build; needs `pip install pyinstaller`).
2. 🔵 Seeded alerts use `now_iso()` timestamps (same second) — cosmetic; fix to staggered if visuals matter.
3. 🔵 `sessions.risk_score` column is stored but recomputed live; harmless but can be normalized later.
4. 🔵 No automated unit tests file yet (manual verification via `TestClient` scripts).

## 7. Next Steps

- [ ] Run `build_exe.ps1` to produce `dist/C2DeconflictionLab.exe` (portable single-file).
- [ ] Auto-open page after boot when `--open` used (implemented; verify UX).
- [ ] Add lesson-pack markdown (walkthrough for the DRY-RUN exercise from arch §14).
- [ ] Optional: tshark/PyShark ingestion behind `data/evidence/*.pcap`.
- [ ] Add SBOM export step (`pip freeze` → `sbom.txt`) for ISO A.8.12 release gate.

## 8. Quickstart

```powershell
pip install -r requirements.txt
python tools\demo_seed.py       # optional realistic data
python run.py --open            # http://127.0.0.1:8443
python beacon_agent.py --server http://127.0.0.1:8443   # optional live beacon
```

---
*Keep §4/§5/§6 fresh after every working session — this file is the project's source of truth.*