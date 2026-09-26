# Security.md - Security Posture of SQLiDetect Shield

Companion to ARCHITECTURE.md Section 8 (security of the tool itself) and
Section 9 (compliance matrix). This file is the living security record for
the project; update it whenever a control changes.

## 1. Data handling rules (hard constraints - enforced by design)

| Rule | Implementation | Status |
|---|---|---|
| Raw payload values are never persisted | Only SHA-256 digests (salted per deployment) via `normalize.ParameterValue.finalize()` | Implemented |
| Findings store is memory-only | `FindingStore` in `src/gui.py`; no disk writes on analyze | Implemented |
| PII redaction at ingest | Decoded values analyzed transiently only; digests kept | Implemented |
| Scanner requires explicit approval | `approve` checkbox gate + `SCAN_APPROVAL_HINT` | Implemented |
| TLS verification on scan | `verify_tls` flag defaults True; user can disable (documented risk) | Implemented w/ warning |

No code path writes findings, payload values, or digests to disk except
user-initiated **exports** (JSON/CSV/compliance snapshot via Save dialogs).
Warn users that exported findings may contain sensitive evidence fragments.

## 2. Crypto & secrets
- No secrets in the codebase; no credentials/config baked into the exe.
- Exports and logs are plain text on the host filesystem - storage-level
  encryption (BitLocker/EDR) is the operator's responsibility (A.8.24).
- Distributed tool: threat model assumes the binary may be reverse-engineered;
  do NOT embed scan tokens/API keys. Scanner beacon/OOB credentials are
  operator-configured out-of-band (ARCHITECTURE.md 5.2).

## 3. Authentication & authorization
- GUI is a local desktop tool: **no remote access, no shared credentials**.
- Privileged mode (running scans with TLS disabled / on prod targets) is
  governed by operator policy; tool logs every scan session to the log pane.
- Audit/analyst roles (ARCHITECTURE.md 8.1) apply to the server/enterprise
  deployment of this architecture, not the portable single-user exe.

## 4. Input & output hardening
- All ingested input (URLs, raw requests) is treated as untrusted:
  - No logging of raw request bodies; log pane shows decoded params (may show
    attack payload text by design - that is the tool's output).
  - Treeview/Text rendering uses tk text widgets only (no HTML/script exec),
    mitigating stored-XSS style console attacks (ARCHITECTURE.md 4.2).
- Regex rules are precompiled; RE2-style but Python `re` is used - review any
  third-party rule additions for ReDoS before merging (`rules.py`).

## 5. Supply chain & build
- `requirements.txt` pins: `requests>=2.28`, `pyinstaller>=6.0`.
  Future harden: pin exact versions + generate SBOM/hash checksums.
- Build: `build.ps1` runs the selftest CI gate before packaging; artifacts are
  checksummed (SHA-256 printed). Dist EXE integrity should be verified by
  operators before distribution (NIST SA-10 / SI-7 alignment).
- Known current gap: no code signing certificate for the exe - Windows SmartScreen
  will warn. (Roadmap: sign with org/OV or EV cert.)

## 6. Operating guidelines
- Scan only targets you own or are explicitly authorized to test
  (OWASP scanning agreement; ISMS A.8.2 / IR flow).
- Keep the tool off shared drives; run from approved, encrypted workstation.
- Do not connect outbound to production DBs - the scanner only sends HTTP
  payloads to WEB endpoints (never to DB ports).
- Time-based probes (`SLEEP(2)`, `pg_sleep(2)`) are non-destructive but add
  load; default inter-probe delay 0.5s prevents hammering (ARCHITECTURE.md 5.5).

## 7. Compliance quick-reference (this build)
- OWASP A03 (Injection): core detection layers 1-3 active (signature, grammar,
  heuristics). Layers 4-5 (ML, correlation) are roadmap for the server edition.
- OWASP A06: dependency status must be re-verified each rebuild
  (`pip audit` / SCA once configured).
- ISO 27001 A.8.28/A.8.29: secure-coding gates = selftest fixtures + CI;
  static analysis (ruff/bandit) NOT yet wired - add in next iteration.
- NIST SI-7: SHA-256 printed at build; verify at install.
- PCI 6.6: usable as an intermittent web-attack detection control for
  low-volume app segments; consult QSA for scope.

## 8. Security debt / backlog
1. Add `ruff`/`bandit` to CI + `pip-audit` or OSV scanner (inexpensive - high value).
2. Code-sign the exe (removes SmartScreen warnings).
3. Add scanning consent/audit journal file (append-only local log) so scanner
   usage is evidence-backed for ISMS A.5.24.
4. RC4/weak-cipher or ReDoS regression tests for rule packs.
5. Optional: harden the log pane against payload rendering (limit per-line width).