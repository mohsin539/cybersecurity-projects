# Project State

Track 2 / Task 21 — Phishing Email Analyzer (header, URL, attachment triage tool).

**Last updated:** 2026-09-17

---

## Milestones

| Milestone | State |
|---|---|
| `docs/architecture.md` v1.0 (NIST / ISO 27001 / OWASP mapping, STRIDE) | **Complete** |
| Application scaffold + all source modules | **Complete** |
| Security core (crypto / identity / audit / validation) | **Complete** |
| Analysis engines (header / URL / attachment / content / risk) | **Complete** |
| Encrypted data plane (cases, settings, at-rest tests) | **Complete** |
| GUI (login gate + analyst console) | **Complete** |
| Self-test suite (`--self-test`, 57 checks) | **Complete — passing** |
| pytest suite (`tests/`, 37 tests) | **Complete — passing** |
| PyInstaller spec + `build.build.bat` | **Complete** |
| `security.md` | **Complete** |
| `state.md` / `memory.md` | **Complete** |
| README update | **Pending** |
| Build portable `.exe` + verify launch | **Pending** |

---

## Layout

```
README.md              # project overview (being updated)
requirements.txt       # pinned runtime deps
launcher.py            # frozen-bundle entry point
docs/architecture.md   # approved architecture reference
security.md            # implemented security controls
state.md / memory.md   # this state file + session memory
src/app/
  main.py              # bootstrap, --self-test hook
  analysis.py          # engine orchestration pipeline
  sec/                 # crypto, identity, audit, validation, constants
  data/                # encrypted settings + case store, retention/export
  engines/             # header, url, attachment, content, risk, model, dns
  ui/                  # login Gate + AppWindow
  tests_self.py        # headless self-test runner (57 checks)
tests/                 # pytest suite (37 tests)
build/                 # PyInstaller spec + build.bat
```

---

## Key Security-Tuned Modules & Decisions

- `sec/crypto.py` — AES-256-GCM with AAD-bound containers; min-length guard exact (no off-by-one).
- `sec/identity.py` — single-credential profile; auth == successful GCM decrypt; constant `data_key` wrapped inside body; lockout state in plaintext `lockout.dat`. `create_profile`/`change_password` reload blob so in-process auth works.
- `sec/audit.py` — hash-chained, encrypted, tamper-evident events (`verify()` returns violations).
- `engines/header_engine.py` — RFC 6376 canonicalization verified against official test vectors; multi-char tag parser (`bh`, `h`, …) fixed; DKIM `bh=` body-hash checked before signature loop; DMARC reported as none vs fail correctly; `_relay_chain(res, meta, received)` arg order fixed; `meta` carries display/reply-to/return-path for impersonation checks.
- `engines/risk.py` — deterministic verdict matrix, fail-closed.
- Failure topology found & fixed in testing: swapped `_relay_chain` args, missing multi-char DKIM tags, stale identity state after create/rotate.

---

## Test Status

- `py -3.12 -m src.app.main --self-test` → **SELF-TEST PASS failures=0** (57 checks across crypto, validation, audit, identity/RBAC, RFC 6376 vectors, DKIM round-trip, URL, attachment, content, risk, full pipeline, at-rest).
- `py -3.12 -m pytest -q` → **37 passed**.

---

## Next Steps

1. Update `README.md` with build/run/verification docs + link to `security.md`.
2. Run `build\build.bat` (self-test + pytest gates, then PyInstaller) to produce `dist\PhishingEmailAnalyzer.exe`.
3. Verify the `.exe`: launch (watch for GUI), run `--self-test` against the frozen build if feasible, confirm encrypted state dir creation.