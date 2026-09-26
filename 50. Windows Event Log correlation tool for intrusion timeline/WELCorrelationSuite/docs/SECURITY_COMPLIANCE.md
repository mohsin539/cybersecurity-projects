# Security & Compliance

The suite was built so that a security reviewer can audit **both the analysis output and the tool
itself**. Detection rules carry framework tags; the dashboard/report surface maps its own hardening
to the same frameworks.

## 1. Detection-alignment (what the analysis is mapped against)

Every one of the 40 rules is tagged with:

| Framework | Scope in this tool |
|---|---|
| **ISO/IEC 27001:2022** | 16 Annex A controls the detected activity evidences (e.g. 8.15 Logging, 8.16 Monitoring, 8.28 Secure coding, 5.28 Collection of evidence) |
| **NIST CSF 2.0** | Functions/categories each rule supports: ID (Identify), PR (Protect), DE (Detect), RS (Respond), RC (Recover) |
| **MITRE ATT&CK** | Technique IDs per rule (e.g. T1027 Obfuscated Files, T1059 Command and Scripting Interpreter, T1558 Steal or Forge Kerberos Tickets) |

Report includes a **coverage matrix** showing which ISO/NIST controls the 40-rule pack demonstrably
addresses, and per-technique heat maps.

Detected-activity framework controls (subset):

- `5.15` Access control · `8.2` Access right assignment (privilege escalation / persistence)
- `8.16` Monitoring activities (anomalies) · `8.15` Logging (cleared-log detection, event 1102/104)
- `5.26` Response to incidents · `5.27` Learning from incidents · `5.28` Collection of evidence
- `8.7` Protection against malware · `8.20` Networks security

## 2. Tool-surface hardening (self-compliance)

The web/API surface implements:

| Measure | OWASP 2021 | NIST CSF | ISO 27001 |
|---|---|---|---|
| Localhost-only binding, random ephemeral port | A05 | PR.PT | 8.20 |
| Single-use session token on every request | A07, A01 | PR.AC | 8.2 |
| No SQL / no shell string interpolation (parameterized subprocess) | A03 | PR.DS | 8.28 |
| Contextual / HTML-escaped rendering of untrusted log data | A03 | PR.DS | 8.28 |
| Security headers: CSP, nosniff, referrer-policy, X-Download-Options | A05 | PR.PT | 8.28 |
| Content-Type checks + 100 MB upload cap | A03 | PR.DS | 8.28 |
| Path-traversal-safe file serving | A05 | PR.PT | 8.28 |
| Idle self-termination + graceful shutdown endpoint | A05 | PR.PT | 8.16 |
| Action-level audit trail with SHA-256 integrity | A09 | DE.CM | 8.15 |
| Tamper-evident reports (embedded SHA-256 of artefacts) | A08 | PR.DS | 8.24 |
| No outbound fetch / no SSRF surface (loopback-only) | A10 | PR.PT | 8.20 |

`app/compliance.py` powers the Compliance tab and report section; `tool_framework_compliance()`
emits this exact checklist as machine-readable evidence.

## 3. Audit trail & evidence integrity

- Every event carries `hash` = SHA-256 of its normalized `data` block **(A08: evidence immutability)**.
- The audit trail is a **JSONL file formed as a hash chain**:

```json
{
  "ts": "...", "actor": "user", "action": "report",
  "detail": "downloaded HTML (sha256 abc123...)",
  "integrity": { "prev_hash": "<previous entry's chain hash>",
                 "hash": "<sha256 of this entry incl. prev_hash>" }
}
```

  Chain root is the fixed genesis `WELICS1.0`. Any reordering, deletion or tampering breaks
  `AuditTrail.verify()` → the dashboard and report surfaces flag the case as *tampered*.

- Reports are written next to the case assets with `.sha256` sidecars
  (`report.html.sha256`, `events.csv.sha256`, `case.json.sha256`) created at generation time —
  you can verify a downloaded report against the sidecar later.
- Generated artifacts are re-hashed on every request, making the exported proof reproducible.

## 4. Threat model & mitigations

| Threat | Mitigation |
|---|---|
| Another local process snoops the dashboard | loopback bind + random port + session token in URL + short idle lifetime |
| Malicious log payloads (XSS) | strict CSP, all log data HTML-escaped before injection |
| Path traversal / arbitrary file read | whitelisted web dir, `..`/drive/absolute-path rejection |
| Oversized or malformed imports (DoS) | size cap, strict content-type, guarded parsers with bounded reads |
| Evidence tampering after export | hash chain + per-artifact SHA-256 sidecars |
| Injection via shell | all `wevtutil` calls are a fixed binary invoked with an argument list (no shell) |

## 5. Notes for reviewers

- Source-mode ports bind to `127.0.0.1` on `WELICS_PORT` if set, otherwise a random OS-assigned
  port (never exposed outside loopback).
- The tool requires **no admin rights**; live collection uses the *Security/System/Application/
  PowerShell/Setup/OpsManager* channels available to the current account (`wevtutil`).
- Run `python tests\run_tests.py`, `python tests\server_smoke.py` and `python tests\exe_smoke.py`
  to reproduce the green audit-chain evidence claims.