# 🧠 MEMORY — Persistence & Working Context for C2 Deconfliction Lab

> This file is the **operational memory** (reservation) for any future human or agent session.
> Read it before making changes. Keep it honest; update it when behavior changes.
> Companion files: `archectecture.md` (design), `security.md` (controls), `state.md` (progress).

---

## 1. Project Identity

- **Project:** Encrypted C2 channel demo — TLS-wrapped beacon + traffic decryption for blue team study.
- **Delivered as:** Portable **web console** (FastAPI + SQLite + vanilla JS single-page app). Optional PyInstaller `.exe`.
- **Authorization contract:** Lab-only, no egress, blue-team education. Keep banners/alerts present. ✅ hard invariant.
- **North star:** everything must be *decryptable, detectable, and reportable* — that is the whole point.

## 2. Environment Facts (Windows)

| Item | Value |
|---|---|
| OS / shell | win32 / PowerShell 5.1 |
| Python | 3.12.7 (CPython, `C:\Users\mohsi\...\Python312`) |
| Key libs (already installed) | fastapi 0.115.14, uvicorn 0.32.1, cryptography 50.0.1, openpyxl 3.1.5, Jinja2 3.1.6, pydantic 2.13.5, requests 2.34.2 |
| Run | `python run.py` (add `--seed --https --open`) |
| Default port | 8443 |
| Shell quirk | ASCII-only prints to console (cp1252); avoid box-drawing/emoji in CLI output |

## 3. Working Conventions (MUST follow)

1. **Web-first.** Prefer editing `app/` + `app/static/`; `.exe` is packaging only.
2. **No comments in code** unless the user asks; use the three `.md` docs for prose.
3. **DB access** goes through `app/db.py` helpers only (`execute`, `query_all`, `query_one`) — all SQL parameterized.
4. **Auth:** panel/blue/reports/admin endpoints require `X-Lab-Token` (middleware in `app/main.py`). Beacon API authenticates by session UUID. Downloads use `?token=`.
5. **Traffic telemetry:** every beacon call records a Traffic row via `app/services/capture.py:record_traffic`. New beacon events must record traffic too.
6. **Key model:** per-session AES-256-GCM key is **escrowed** (`keys.key_type='session_aes'`). That escrow IS the simulated SSLKEYLOG. Keep it discoverable.
7. **Crypto:** never add homebrew crypto. Reuse `app/core/crypto.py` (AESGCM from `cryptography`).
8. **Reports:** add new content to all three formats symmetrically — `_write_xlsx`, `_write_csv`, `_write_html` in `app/services/reporting.py`.
9. **Risk/detection:** changes to risk formula or rules live in `app/services/detection.py`; rule seeds in `DEFAULT_RULES`.
10. **Encoding:**  `.md` files contain emoji + mermaid (design docs); Python files stay ASCII.

## 4. Architecture in 60 Seconds

```
Zone A (RED sim)  beacon_agent.py / UI demo-beacon  →  Zone B capture (traffic rows)
Zone C (Server)   FastAPI: api/beacon.py registers/pings/tasks/results (AES-inner encrypted)
Zone D (BLUE)     api/blue.py decrypt + detections  →  reporting.py → .xlsx/.csv/.html
Compliance        admin/compliance matrix (owasp|nist|iso) + audit_log
```

Data model (`app/db.py`): `sessions · tasks · traffic · keys · alerts · rules · audit_log · report_bundles`.

## 5. Key File Roles (quick ref)

| File | Role | Edit when… |
|---|---|---|
| `app/api/beacon.py` | beacon REST (register/ping/tasks/result) | beacon protocol changes |
| `app/api/panel.py` | sessions, task creation, kill-switch | UI tasking/session actions |
| `app/api/blue.py` | decrypt, rules, alerts, stats | detection workflows |
| `app/api/reports.py` | generate + token-gated download | report API |
| `app/services/detection.py` | risk formula + R-001..R-005 + stats | detection tuning |
| `app/services/capture.py` | traffic recording | telemetry columns |
| `app/services/decryption.py` | escrow + decrypt record/session | key/decrypt logic |
| `app/services/reporting.py` | 3-format export + compliance rows | report content |
| `app/static/{index,console}.{html,js}` | GUI (fetch-driven) | UI layout/actions |
| `app/templates/report.html.j2` | HTML evidence report | report layout |
| `run.py` | launcher/banner/HTTPS/seed | CLI entrypoints |
| `tools/demo_seed.py` | seeds 3 sessions + evidence | demo data realism |
| `beacon_agent.py` | standalone beacon CLI | agent behavior |

## 6. Verified Commands & Known-Good Flows

```powershell
python run.py --seed --open                # launch console w/ demo data
python tools\demo_seed.py                  # seed only
python beacon_agent.py --server http://127.0.0.1:8443   # live beacon (loop)
python -c "TestClient smoke"               # see state.md §5 / security.md §12
powershell -ExecutionPolicy Bypass -File build_exe.ps1  # .exe packaging
```

**Verified behaviors (2026-09-20):** register→ping→task→encrypted-result→rules fire✅ ·
decrypt record/session✅ · xlsx/csv/html downloads (401 for bad/missing token)✅ ·
compliance matrix✅ · risk scoring (96.5 peak on seeded beacon)✅ · live boot http 200✅.

**Known traps:**
- Jinja dict access: use `data["keys"]`, not `data.keys` (dict method shadowing).
- SQLite `strftime('%s', ts)` returns **string** → wrap in `CAST(... AS INTEGER)` for math.
- Don't comma-join filesystem paths in one DB row — `FileResponse` breaks on Windows; use **per-format rows** (D-8).
- `webbrowser`/`print` with glyphs → keep CLI output ASCII (cp1252).

## 7. Open Threads / Handoff Notes

- Next big task: execute `build_exe.ps1` → deliver `dist/C2DeconflictionLab.exe` (not yet built).
- Lesson-pack markdown for the arch §14 DRY-RUN exercise is planned but not written.
- Optional later: live pcap ingestion (tshark) behind the same `traffic` table; real JA3 capture.
- `ENFORCE_AUTH=True` is set but middleware keyed off token presence; real RBAC is future work.
- If a human asks "what's the current state?" → point to `state.md` §1/§6. If they ask policy → `security.md`.

## 8. Session Rehydration Checklist (for AI agents)

1. Read this file first, then `state.md`, then `security.md`. Skim `archectecture.md` for design intent.
2. Confirm working directory = project root.
3. To reason about the app: read `app/main.py` (routes/middleware) → the router you're touching → its services.
4. To verify: prefer `TestClient` + `ADMIN_TOKEN` import; never commit real keys.
5. After any change: update `state.md` §4/§5/§6 and this file's "Verified" section (deliberately).

---
*Reserved memory — authorized lab project. Keep this file short enough to read at session start.*