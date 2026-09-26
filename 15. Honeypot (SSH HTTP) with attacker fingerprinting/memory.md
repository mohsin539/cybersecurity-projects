# Project 15 — Memory (Development Journal)

## 1. Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| App-level emulation (not real sshd/httpd) | Risk containment is the top design force; real servers = real attack surface |
| Sessions exported as CES-like JSONL, not DB | Simple, searchable, wallet-friendly; analyst replay uses archive |
| Attribution = weighted scores, never certainty | Tools overlap; confidences ranked, single best guess only in top-3 list |
| Blocklist push is a SINK (honeypot emits, Project 16 consumes) | Avoids loop; honeypot stays read-only wrt enforcement |
| Doors bind 0.0.0.0 by default in demo | Production MUST bind specific interface — documented in security.md §4 |

## 2. Gotchas (trap list updated 2026-09-13)

1. **`in` on a LIST checks element equality, not substring!** In fingerprint.py the check `if "cat /etc/passwd" in [str(x["value"]) ...]` NEVER matches because it compared the whole command string (with `; ls -la\r\n` tail) for equality. Use `any("needle" in item for item in items)`. This bit me exactly where an analyst would introduce it.
2. **ssh.py decodes bytes with errors="replace"**: attacker-sent binary is replaced; safe but loses bytes that could be useful for fingerprinting C2. Keep as is (never raise on bad input).
3. **session duration ~0 in tests**: session.ended set in finally at socket close; because the loop runs fast, duration is near-zero. On real attackers it grows. Don't assert `duration > 0` in tests.
4. **Banner first line**: SSH client sends our banner back? OpenSSH clients echo `SSH-2.0-...`; `_handle` treats lines starting `SSH-2.0-` as kex-init. Real key-exchange lines are binary — NOT supported here (documented; scripted simulators only).
5. **`http.server.ThreadingHTTPServer` logs are silent** — `log_message` overridden; good for honeypot, bad for debugging. Enable via env `HONEYPOT_DEBUG=1` when needed.

## 3. Conventions

- Score keys: `tool_scores`, `os_guess`, `campaign_sig`, `net`, `payload`, `http` (stable contract with dashboard).
- Severity in export: `critical` when interactive attacker with cmd chain ≥0.8 conf, else high for http/ssh probes.
- Fake FS content lives ONLY in `doors/ssh.py::_fake_exec` + `doors/http.py::PAGES`; never add real data.
- `sessions.jsonl` append-only; archive rotation by dir (not in-code).

## 4. Cross-Project Hooks

- Export envelope field `source=honeypot` + CES fields → directly consumable by Project 11 correlation rules.
- `ioc` payload pushed to Project 16 (`feed_id=honeypot-internal`, `ioc_type=ipv4`).
- Syslog-style line can be fed to Project 13 `chain-cmdline` decoder if routed (hids-agent line format NOT matched — do not claim parity).

## 5. Warning for Future Developers

- NEVER add `os.system`/`subprocess` to satisfy an "interactive shell" demand. If a real attacker gets a real shell, the honeypot becomes the beachhead.
- Keep `_fake_exec` a static mapping; do not start mirroring directory listings from the real host.
- Do not enable HTTPS door without a plan for cert rotation and TLS fingerprint consistency (browser quirks reveal honeypots).
- Blocklist push runs only on critical; avoid flooding Project 16 — dedupe on `campaign_sig` before pushing (planned).