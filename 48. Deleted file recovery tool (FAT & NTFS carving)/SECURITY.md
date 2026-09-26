# Security Policy — RecovPro Secure

Recovery of deleted data lives at the boundary between legitimate incident
response and privacy abuse. This policy documents the protective design,
assumptions, and reporting process.

## Scope

Applies to the RecovPro Secure source tree, the PyInstaller portable bundle
(`dist\RecovProSecure\`), and every release consumed by operators.

## Supported environments

- Windows 10 / 11, x64, py3.12–compatible.
- Logical volume sources (`\\.\C:`): no elevation required.
- Physical drive sources (`\\.\PhysicalDriveN`): elevation required (checked at
  open time, surfaced in the UI).
- Forensic images (`.img`, `.dd`, `.raw`, MBR/GPT) open as plain read-only files.

## Data-safety guarantees

1. **No writes** are ever issued to a scanned source. All handles use
   `GENERIC_READ | FILE_SHARE_READ | FILE_SHARE_WRITE` with `OPEN_EXISTING`;
   `ReadOnlySource` additionally clamps reads and marks `readonly=True` at open.
2. **Write destinations** are confined to the configured vault directory.
   `safe_name()` strips drive letters, `..`, absolute prefixes, separators and
   reserved device names; `is_unsafe_path()` refuses any path that resolves
   outside the vault root.
3. **Recovered artifacts are fingerprinted** with SHA-256 and recorded in a
   manifest before they are touched by any further export step, giving an
   immutability anchor for chain-of-custody.

## Cryptographic controls

- **At rest (vault):** each artifact stored with its SHA-256 in
  `manifest.json`; verification returns a pass/fail and total count.
- **At rest (export bundle):** AES-256-GCM with per-bundle random nonce;
  the key is derived from the operator passphrase via PBKDF2-HMAC-SHA256,
  600 000 iterations, 32-byte salt.
- **Log integrity:** `audit.jsonl` is an append-only hash chain; each record
  commits the SHA-256 of the previous record. `audit.tail.sha256` is the
  operator-verifiable root. `AuditLogger.verify_chain()` must be run before any
  log is trusted as evidence.

## Carving bounds & tamper resistance

- Free-space scanning is always bounded (`PROBE_STEP`, `MAX_ARTIFACT`,
  `FOOTERLESS_MAX`) so hostile disk images cannot exhaust memory or stall the app.
- Every candidate header passes a structural plausibility gate *before* an
  expensive probe; validation re-checks structure after materialization.
- Self-test (`python app/main.py --selftest`) exercises all recovery paths
  against generated synthetic media and is a **build gate** for the portable EXE.

## OWASP-relevant operational notes

The statefulness here is minimal (a desktop utility), but the following classes
are handled explicitly: path traversal (path sanitization + vault confinement),
sensitive data exposure at rest (AES-256-GCM bundle), stdout leakage (self-test
output is synthetic only; real file names never print to logs), and supply-chain
pin (exact `requirements.txt` pins + PyInstaller spec from a trusted checkout).

## Reporting a vulnerability

Do **not** open a public issue for security defects. Contact the maintainer
directly with:

1. Affected module and version,
2. Steps to reproduce (synthetic image preferred — do not attach real
   customer/media data),
3. Impact assessment (read amplification, memory exhaustion, path escape, …).

We will acknowledge within 5 business days and ship a fix plus a regression
self-test case.

## Maintainers

- Keep `SECURITY.md`, the threat-model notes in `docs/`, and the self-test in
  sync with every release.
- Re-run `python -m compileall app` and `python app/main.py --selftest` before
  tagging.
- Build with `python -m PyInstaller --noconfirm --clean packaging\RecovPro.spec`
  and verify the bundle with `RecovProSecure.exe --selftest`.