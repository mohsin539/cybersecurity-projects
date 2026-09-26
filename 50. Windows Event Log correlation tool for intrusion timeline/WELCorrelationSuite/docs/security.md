# Security Reference

Reference-only projection of the security posture, controls and threat model of the
WEL Intrusion Correlation Suite. Written for maintainers and reviewers; no code.

---

## 1. Trust boundary & running model

- **Single machine, single user.** The tool runs as a local dashboard. It never phones home,
  makes no outbound HTTP calls, and requires no admin rights.
- **Web surface** binds to `127.0.0.1` on a random OS-assigned port (override: `WELICS_PORT`),
  never to a remote interface. Traffic never leaves loopback.
- **Session token:** the server generates a 64-bit-random hex token at boot; the browser URL is
  `http://127.0.0.1:<port>/tk-<token>/index.html`. Every request outside that path is denied
  (403) and logged to the audit trail.
- **Idle lifetime:** no traffic for 30 minutes → automatic self-termination (log entry written
  first).

## 2. Tool surface hardening evidence

| Area | Implementation |
|---|---|
| Server hardening (A05) | CSP `/ X-Content-Type-Options: nosniff / Referrer-Policy / X-Download-Options`, loopback-only binding, random port |
| AuthN (A07) | Single-use session token path gate; denied attempts logged |
| Injection (A03) | No SQL, no HTML template injection of raw data (all untrusted strings HTML-escaped in the UI and report); `wevtutil` invoked with an argument list, never `shell=True` |
| Path traversal | Static file serving whitelists the web directory; rejects `..`, backslashes, absolute paths, drive letters |
| Upload limits | 100 MB cap, strict `Content-Type` check; guarded parsers |
| Idle terminate | Watchdog + graceful shutdown endpoint for hygiene |
| Logging (A09) | Every mutation (start, collect, import, analyze, download, denied request, exit) written to the audit trail |
| Data integrity (A08) | Per-artifact SHA-256 sidecars; audit chain in JSONL |
| SSRF (A10) | Loopback-only service — no facility to fetch arbitrary URLs |

## 3. Threat model

| Threat | Vector | Mitigation |
|---|---|---|
| Local user reads dashboard | Browser history / other process | Loopback bind + random port + token in URL; tool auto-exits after idle |
| Log payload attacks the UI | Malicious field content (XSS) | Strict CSP, escaped rendering, no innerHTML with raw log text |
| Log payload tricks the engine | Negative/invalid timing | Epoch coercion guards, bounded parsers, numeric matchers |
| Path traversal/file read | `../../etc` style URLs | Whitelisted web dir + explicit traversal denial |
| Oversized/malformed imports | DoS / memory pressure | Size caps, content-type checks, small page limits on `/api/events` |
| Evidence tampering | Post-hoc file edits | SHA-256 hashes + sidecars + chain-of-custody audit log |
| Shell injection | Crafted event values | No shell, argument-list subprocess only |
| Port hijacking | Local rogue bind | Port chosen by OS on boot (or fixed via `WELICS_PORT`); worker restarts if unavailable |

## 4. Audit & chain-of-custody design

- Format: JSONL, append-only, one entry per action.
- Entry shape:

```json
{
  "ts": "<UTC ISO>",
  "actor": "system|user|?",
  "action": "start|collect|import|analysis|report|denied request|stop",
  "detail": "...",
  "level": "info|warn|error",
  "integrity.prev_hash": "<previous entry hash or GENESIS>",
  "integrity.hash": "<sha256 of entry excluding the hash field itself>"
}
```

- Chain root: `sha256_of("GENESIS")` fixed constant.
- `verify()` replays the file and reports the first broken line; the UI badge shows
  `chain valid` / `chain review`.
- Report/artifact downloads also hash the bytes, log the short hash, and write `.sha256`
  sidecars for later verification.

## 5. Data handling

- **Data retention:** no telemetry, no cloud persistence, no external storage. All state lives
  in the workspace (console mode: `workspace/`, exe mode: `welics_case_data/` next to the exe).
- Evidence hashes: every ingested event is fingerprinted (`SHA-256` of its canonical JSON),
  so the correlation inputs are reproducible from the exported `case_*.json`.
- Transient temp uploads live in `tmp/` and are cleaned after parse.

## 6. Verification checklist (maintainers)

```powershell
python tests\run_tests.py        # 30/30 engine (incl. audit chain validity)
python tests\server_smoke.py     # 28/28 HTTP security checks (CSP, nosniff, token 403, traversal)
python tests\exe_smoke.py        # 10/10 frozen .exe end-to-end
```

The HTTP suite specifically asserts: `Content-Security-Policy`, `X-Content-Type-Options`,
token rejection, no-token 403, path-traversal block, and report download headers.

## 7. Incident-response notes for the IR audience

- The tool itself is an IR aid: if you import a case whose audit chain fails verification,
  treat the case data as potentially tampered and rebuild the timeline from a trusted source.
- Whole-case JSON export contains events + incidents + analysis + compliance + audit + integrity — 
  use it as the machine-readable evidence package to hand to an SIEM or ticketing system.