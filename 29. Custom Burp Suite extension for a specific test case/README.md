# BurpTester — Custom Burp Suite Extension Platform (Portable .EXE)

A **pluggable, test-case-driven Burp Suite extension** packaged with a **GUI-based
portable `.exe` launcher**, engineered and hardened to align with:

| Framework | Alignment |
|---|---|
| **ISO/IEC 27001:2022** | Annex A controls (SDLC, config mgmt, cryptography, logging, asset handling) |
| **NIST SP 800-53** | Security controls (AC, AU, CM, SC, SI, PL families) |
| **OWASP Top 10:2021** | Nothing the app does *introduces* these risks; it *detects* them |
| **OWASP ASVS / WSTG** | Every built-in test case maps to a WSTG test ID |

```
┌────────────────────────────────────────────────────────────────────┐
│                     PORTABLE .EXE  (RUNTIME BUNDLE)               │
│  ┌───────────────────┐        ┌───────────────────────────────┐   │
│  │  JavaFX Launcher   │        │  jlink modular JRE (minimal)  │   │
│  │  (GUI dashboard)   │◄──────►│  + signed extension .jar      │   │
│  └───────────────────┘        └───────────────┬───────────────┘   │
└────────────────────────────────────────────────┼──────────────────┘
                                                  │ load
┌─────────────────────────────────────────────────▼──────────────────┐
│                    BURP SUITE  (Montoya API)                      │
│  ┌────────────────────────────────────────────────────────────┐   │
│  │              BurpTester Extension                          │   │
│  │  Scanner │ Proxy filter │ Context menu │ Tab / UI panel     │   │
│  └────────────────────────────────────────────────────────────┘   │
└────────────────────────────────────────────────────────────────────┘
```

## What it does

1. **Hooks into Burp Suite** (Proxy / Repeater / Scanner) via the Montoya API.
2. Runs a **specific OWASP WSTG test case** (default reference module: **WSTG-SESS-10
   JWT / Token security**) through a **pluggable Test-Case Engine**.
3. Streams findings to the GUI launcher — a **portable `.exe`** that bundles its own
   minimal JRE, so no client-side install is required.
4. Produces **compliance-ready reports** (JSON + HTML) with a full control mapping.

## Repository layout

| Path | Purpose |
|---|---|
| `burp-extension/` | The Burp Suite extension (Java, Montoya API, Gradle) |
| `gui-launcher/` | JavaFX portable `.exe` front-end (dashboard, config, reports) |
| `docs/` | Architecture, compliance mapping, threat model, hardening specs |
| `scripts/` | Portable build, code-signing and SBOM generation |
| `sbom/` | CycloneDX SBOM templates / output |
| `vuln-app/` | Intentionally JWT-flawed fixture (Python) for E2E and demos |

## Quick start

```bash
# Build the extension (requires JDK 17+)
.\gradlew :burp-extension:jar

# In Burp Suite Pro → Extensions → Add → select:
#   burp-extension\build\libs\burp-extension-1.0.0.jar

# Build the portable Windows solution (app-image .exe + bundled runtime)
.\gradlew :gui-launcher:packagePortable
#   → gui-launcher\build\portable\BurpTester\BurpTester.exe   (runs from any folder / USB)
.\scripts\build-portable.ps1 -Version 1.0.0
#   → dist\BurpTester-1.0.0-portable.zip + dist\SHA256SUMS.txt
```

### Local E2E against the vulnerable fixture

```bash
# 1. Start the intentionally flawed JWT target (dependency-free Python 3)
python vuln-app\server.py 8765

# 2. Drive the engine against it (detects alg=none → HIGH finding)
$env:BURPTESTER_E2E = "1"
.\gradlew :burp-extension:test

# SBOM (aggregated CycloneDX for both modules)
.\gradlew cyclonedxBom        # → build\reports\bom.json
```

## Documentation index

| Doc | Content |
|---|---|
| [Architecture](docs/01-architecture.md) | System context, modules, data flow, diagrams |
| [Compliance Mapping](docs/02-compliance-mapping.md) | ISO 27001 / NIST 800-53 / OWASP Top 10 |
| [Threat Model](docs/03-threat-model.md) | STRIDE analysis + mitigations |
| [Portable .EXE & Release Pipeline](docs/04-portable-exe-release.md) | jlink, signing, SBOM, CI/CD |
| [Reference Test Case (JWT)](docs/05-test-case-reference-jwt.md) | WSTG-SESS-10 working spec |
| [Security Guide](docs/security.md) | Hardening, cryptography, IPC, mutation safety, release gates |
| [State](docs/state.md) | Runtime state machine, session/pairing/config/audit state |
| [Memory](docs/memory.md) | Persistent knowledge base for maintainers/agents |

## Security posture in one line

The tool is **safe-by-default**: it only inspects traffic the operator deliberately
directs through Burp, stores no credentials, exposes no network listeners, writes
findings only to local files the operator chooses, and every release is signed and
SBOM-attested.