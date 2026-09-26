# 🧠 memory.md — Decision Memory, Conventions & Reservations

> Living memory for the build team · append new entries; never rewrite history

## 1. Architecture Decision Records (ADR)

| ADR | Date | Decision | Rationale |
|-----|------|----------|-----------|
| ADR-01 | 2026-09-21 | Air-gapped lab / evidence never on enterprise net | Custody integrity, ISO 27037 |
| ADR-02 | 2026-09-21 | `adb backup` first, logical pull fallback (Android 12+) | Backwards reach; documented limits surfaced in UI |
| ADR-03 | 2026-09-21 | WORM + SHA-256 hash-linked journal | Tamper-evident proof for court |
| ADR-04 | 2026-09-21 | SDF/XML canonical evidence format | Machine readability, vendor interchange |
| ADR-05 | 2026-09-21 | Portal/DMZ only for *signed* reports | DLP boundary; OWASP A04/A10 |
| ADR-06 | 2026-09-21 | Sign-only key, HSM for production | Non-repudiation frame hold memory |
| ADR-07 | 2026-09-21 | GUI build = pure stdlib (tkinter) + one pinned build dep | Portable 12 MB exe, auditable, air-gap friendly |
| ADR-08 | 2026-09-21 | All persistent state beside exe (`evidence_vault/`) | True portability; OS-independent of registry |

## 2. Conventions (do not break)

- Case ID prefix `CSE-YYYY-NNNN`, evidence `EXH-<TYPE>-NNN` (`BU`=backup, `LG`=logical, `DEMO`=sample).
- Journal actor is always `examiner` (single-examiner portable deployment; extend RBAC in production).
- Never edit `audit.jsonl` or `manifest.json` by hand — GUI is the only writer.
- Hashing: SHA-256, lowercase hex; chunked read (1 MiB) — stable across rebuilds.
- Reports regenerate deterministically (SDF line layout); signatures change only if content or key changes.

## 3. Reservation Registry (evidence/exhibit IDs & namespaces)

| Namespace | Reserved for | Status |
|-----------|--------------|--------|
| `CSE-2026-*` | Case integers, auto-increment | assigned on create |
| `EXH-BU-*` | Android full backups (`.ab`) | auto from Acquisition |
| `EXH-LG-*` | Logical extractions | auto from Acquisition |
| `EXH-DEMO-*` | Demo artifacts (train/test) | Intake → Create Sample |
| `EXH-<free>` | Manual exhibits | Intake form |
| `reports/<case>_report.{pdf,docx,xml,json,csv,html}` | Deliverable filenames | fixed |
| `exports/audit_export.json` | Audit snapshots | overwritten per export (kept in journal too) |
| `keys/signing.key` | Single team-generation key | v1 substitute until HSM |

> Reservation rule: never assign an exhibit ID that `evidence_vault/cases/*/manifest.json` already holds; the UUID (`uid`) disambiguates duplicates.

## 4. Team Memory / Notes

- **Python 3.12 f-strings**: backslash-escaped quotes inside `f'…\{…}\…'` fail to compile → use intermediate variables (see `reporter.py` fix).
- **PyInstaller + tkinter**: `--noconsole` hides stdout — all diagnostics are GUI/journal only.
- **`.ab` reality check**: post-Android-12 factory builds may refuse full backups; logical pull is the guaranteed path (documented in app + architecture §4.1).
- **PDF writer**: minimal Type1/Courier PDF, latin-1 — court-compatible render, not print-grade; swap to reportlab for DTS spec later (ADR pending).
- **DOCX**: minimal OOXML (document.xml only) — opens in Word/LO; add styles/properties at DTS milestone.

## 5. Known Open Items

- [ ] HSM integration for signing key (ADR-06 production step)
- [ ] Root/extraction (physical) acquisition module beyond logical level
- [ ] Multi-examiner RBAC + per-examiner journal actor
- [ ] Court grade PDF typesetting + page numbers / exhibit tabs
- [ ] Automated control self-assessment job (A1 in architecture §7.2)
- [ ] OEM backup API fallback driver (Android 12+ `.ab` workaround)

## 6. Change Log

- **v1.0 2026-09-21** — initial build: portable exe, ZONE0-5 workflow, signed multi-format reports, WORM audit; docs security.md / state.md / memory.md emitted.

---
*Append below the line — never rewrite entries above.*
---