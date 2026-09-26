# Log Anonymizer with Redactor

Securely share logs without leaking PII/PHI/PCI. The system detects sensitive
data across seven strategies, applies policy-driven redaction, and keeps a
tamper-evident audit trail — aligned with **OWASP Top 10 (2021)**, **NIST CSF /
SP 800-53 R5**, and **ISO 27001:2022**.

| Document | Contents |
|----------|----------|
| [`ARCHITECTURE.md`](ARCHITECTURE.md) | Full system design, diagrams, compliance matrices, risk register |
| [`SECURITY.md`](SECURITY.md) | OWASP/NIST/ISO control mapping, threat model, crypto controls |
| [`STATE.md`](STATE.md) | State file format, DPAPI protection, integrity, erasure |
| [`MEMORY.md`](MEMORY.md) | Memory store design, sanitization, privacy (GDPR Art. 17) |

---

## Features

- **Multi-layer detection** — regex patterns, key-value/JSON context analysis,
  pluggable ML/NER hook, Luhn validation for card numbers
- **7 redaction strategies** — full redact, partial mask, tokenize (Vault-ready),
  pseudonymize, generalize (k-anonymity), date-shift, contextual
- **Policy engine** — destination-aware sharing policies (vendor vs analytics)
- **Tamper-evident audit trail** — append-only, sequence-anchored hash chain,
  independently recomputable root for verification
- **Desktop GUI** — tkinter application with entity highlighting, side-by-side
  redacted preview, security dashboard, and encrypted export
- **Input hardening (OWASP A03)** — null bytes, control chars, size/batch limits
- **Never stores originals** — only salted HMAC/SHA-256 hashes (A.8.24)
- **Secure state** — Windows DPAPI encryption of token salt; integrity-tagged
  state and memory files; atomic writes

---

## Quick Start

### Desktop GUI (recommended)

```bash
# From source
$env:PYTHONPATH = "src"
py gui_launcher.py

# Build the standalone .exe (Windows)
.\build_gui.ps1          # output: dist\LogAnonymizer.exe (15 MB)
```

### CLI

```bash
$env:PYTHONPATH = "src"

# Anonymize from stdin
echo "user bob@x.io ssn 555-66-7777" |
  py -m anonymizer --policy share-with-vendor --salt my-tenant
# => user TOK_9c2728b3b8ca59dc ssn [REDACTED]

# Verify audit chain integrity
py -m anonymizer --audit-check
```

### REST API

```bash
py -m uvicorn anonymizer.api:app --host 0.0.0.0 --port 8000
curl -X POST localhost:8000/api/v1/ingest \
     -H 'Content-Type: application/json' \
     -d '{"lines": ["email a@b.co ssn 123-45-6789"], "policy_id": "default"}'
```

---

## Tests & Quality

```bash
py -m pytest tests -q      # 75 tests
py -m ruff check src tests  # all checks passed
py -m ruff format src tests  # formatted
```

---

## Security Framework Alignment

| Control | Implementation | Reference |
|---------|----------------|-----------|
| Data masking | 7 redaction strategies | ISO A.8.11, PCI-DSS 3.4 |
| Logging | Tamper-evident audit chain | ISO A.8.15, OWASP A09, NIST AU-2 |
| Input validation | `InputValidator` | OWASP A03, ISO A.8.26 |
| Access control | Policy/RBAC engine + passphrase gate | OWASP A01, ISO A.5.15 |
| Cryptography | DPAPI + HMAC + AES-GCM/Fernet | OWASP A02, ISO A.8.24 |
| Secure defaults | Force-redact unknown/CRITICAL | GDPR Art. 25, NIST PR.DS |
| State protection | DPAPI-encrypted token salt; integrity tags | NIST SC.12 |
| Right to erasure | `forget()` + `forget_all()` | GDPR Art. 17 |

See `SECURITY.md` for the full threat model and NIST/ISO control table.

---

## Project Layout

```
ARCHITECTURE.md               full system design + compliance matrices
SECURITY.md                   security control mapping + threat model
STATE.md                      state preservation format + DPAPI protection
MEMORY.md                     memory store design + sanitization rules
config/                       sharing policies (JSON + YAML)
src/anonymizer/
  core/                       data models (classification, strategies)
  detection/                  pattern + contextual + ML detection
  redaction/                  7 redaction strategies
  security/                   audit trail, hashing, validation
  services/                   policy engine + orchestration
  api/                        FastAPI REST endpoints
  config/                     runtime configuration
  gui/
    state_manager.py          DPAPI-encrypted state persistence
    memory_manager.py         sanitized cross-session memory
    scanner.py                engine bridge + encrypted export
    theme.py                  dark/light themes + entity colors
    text_view.py              highlighted log pane widget
    main_window.py            desktop GUI (tkinter)
    security_dashboard.py     OWASP/NIST/ISO compliance viewer
    audit_viewer.py           audit trail viewer + chain verify
    settings_dialog.py        preferences + token salt management
    export_dialog.py          plaintext/JSON/encrypted export
    framework.py              compliance data for dashboard
scripts/demo_samples.py       end-to-end demo
tests/                        pytest suite (75 tests)
gui_launcher.py               GUI entry point (also PyInstaller target)
anonymizer_gui.spec            PyInstaller build spec
build_gui.ps1                 one-command .exe build script
```

---

## Building the .exe

```powershell
# Requires: Python 3.10+, PyInstaller, cryptography
.\build_gui.ps1

# The script:
#   1. Installs build dependencies
#   2. Runs full test suite + ruff lint
#   3. Builds dist\LogAnonymizer.exe (15 MB, GUI-mode, no console)
```

The .exe bundles tkinter, the full anonymization engine, Windows DPAPI bindings
(via ctypes/crypt32) and the cryptography library (Fernet/AES-GCM export). No
Python installation is required on the target machine.