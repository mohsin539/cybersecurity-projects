# Phishing Email Analyzer — Header, URL & Attachment Triage Tool

A security-first phishing email triage platform that ingests raw emails and produces
evidence-backed, explainable verdicts across three analysis domains:

- **Header analysis** — SPF (RFC 7208), DKIM (full RFC 6376 verification), DMARC (RFC 7489), anti-spoofing and hop/route anomaly detection
- **URL analysis** — extraction, de-obfuscation, shortener / typosquat / brand-abuse heuristics, and SSRF-hardened reputation lookups
- **Attachment triage** — type faking, executable/PE, OLE/macro magic, and zip-bomb heuristics

Verdicts are correlated by a deterministic risk engine into **ALLOW / FLAG / SANDBOX / QUARANTINE**
with a full evidence trail (A04 / SI-4). All persisted state (profile, audit, settings, cases) is
**AES-256-GCM encrypted at rest**.

## Documentation

| Document | Description |
|---|---|
| [`docs/architecture.md`](docs/architecture.md) | Full system architecture, component deep-dives, threat model (STRIDE), and controls mapping to **NIST CSF / SP 800-53 / SP 800-218**, **ISO/IEC 27001:2022 Annex A**, and **OWASP Top 10 (2021)** |
| [`security.md`](security.md) | **Implemented** security controls, at-rest encryption scheme, threat model summary, and ops guidance |

## Status

Implemented and **tested green**:

- In-app self-test: `py -3.12 -m src.app.main --self-test` → **57 checks pass**
- pytest suite: `py -3.12 -m pytest -q` → **37 tests pass**
- Portability: PyInstaller single-file Windows build (`build\build.bat` → `dist\PhishingEmailAnalyzer.exe`)

## Quick Start (from source)

Requires Python 3.12 (`py -3.12`).

```powershell
py -3.12 -m pip install -r requirements.txt
py -3.12 -m src.app.main                 # launch GUI analyst console
py -3.12 -m src.app.main --self-test     # headless engine/security self-check
py -3.12 -m pytest -q                    # pytest suite
```

First launch: create an **administrator profile** (the vault has no default credentials).
All state is written, encrypted, under `%LOCALAPPDATA%\PhishingEmailAnalyzer`
(override with the `PEA_DATA_DIR` environment variable).

## Portable Build

```powershell
build\build.bat
```

The build script runs the self-test and pytest as **gates** (aborts on failure), then packages
with PyInstaller into `dist\PhishingEmailAnalyzer.exe` and prints the artifact SHA-256.

```powershell
dist\PhishingEmailAnalyzer.exe                   # GUI
dist\PhishingEmailAnalyzer.exe --self-test       # frozen-build self-check
```

## Security Highlights

- **Hostile-input-by-default:** every component treats emails as untrusted attacker input — size/NUL/line-count caps, sanitized filenames, plain-text-only rendering (anti-XSS by construction).
- **Authentication == decryption:** one encrypted profile; successful AES-256-GCM auth is login; PBKDF2-derived key; brute-force lockout (AC-7); RBAC (admin/analyst).
- **SSRF as a first-class constraint (A10):** the URL engine never dials arbitrary URLs; private/reserved-IP literals are blocked; reputation calls are allowlisted HTTPS hosts only.
- **Fail-closed verdicts (A04):** missing evidence never yields a pass; absence of a DMARC policy is "none", not a failure.
- **Tamper-evident, encrypted audit trail (AU / ISO A.12.4):** hash-chained batches + separately-keyed head; `verify()` reports any tampering.
- **Compliance-ready:** control-to-component mapping tables in `docs/architecture.md`.

Archive: after every analysis, store findings (screenshot, detonation summary, STIX artifact if available).