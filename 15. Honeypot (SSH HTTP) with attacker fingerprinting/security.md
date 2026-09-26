# Project 15 — Security Posture

Controls mapped to **NIST CSF 2.0**, **ISO 27001:2022 Annex A**, and **OWASP Top 10**.

---

## 1. Threat Model Summary

| Asset | Trust boundary | Main threats |
|-------|----------------|--------------|
| Fake SSH/HTTP doors | Network reachable | Attacker payloads exploit emulation gap (never real shell), DoS, traffic flood |
| Emulation layer | same process as service | Logic bug spawns real process / escapes sandbox |
| Session/export store | local FS | Attacker-controlled data lands in logs; massive logs → disk fill |
| Blocklist webhook | Outbound HTTPS | Send attacker->victim spam to Project 16; token exfil |
| Honeypot host | VM/container edge | Honeypot used as jump-off point (egress abuse) |

PIVOT: the honeypot is a **sink**. Legit traffic should never arrive; anything arriving is adversary-controlled and fully recorded, but must NEVER let the emulation execute real commands or reach real systems.

---

## 2. Controls — NIST CSF 2.0

| CSF Function | Control | Implemented |
|--------------|---------|-------------|
| **Identify** | ID.AM/ID.RA | Deployments air-gapped from prod; OWASP-level review for each door module |
| **Protect** | PR.AC least privilege | Doors run as unprivileged service user; no egress except allow-listed DNS/HTTPS |
| **Protect** | PR.DS-1 | Fake credentials (honeytokens) never real; `config/doors.yaml` explicitly lists them |
| **Protect** | PR.PT-1/3 audit | Every session (success + fail) exported to sessions.jsonl, no silent truncation |
| **Detect** | DE.CM | Attribution engine reports tool/OS/campaign; severity escalation rules |
| **Respond** | RS.CO | Critical-severity signal triggers Project 16 blocklist feed push |
| **Recover** | RC.RP | Sessions archive retention; rollback = kill doors, restore fake FS image |

## 3. Controls — ISO 27001:2022 Annex A

| Clause | Domain | Control |
|--------|--------|---------|
| A.8.16 | Security monitoring | Continuous session capture + attribution; event envelope CES-aligned |
| A.8.12 | Prevention of info leakage | Fake passwd/db decoys contain only fake data; honeytokens fake |
| A.8.9 / A.8.10 | Vulnerability mgmt | App-level emulation → limited attack surface; container/VM base patched; notes in ops |
| A.8.15 | Logging | Sessions exported JSONL (sessions.jsonl), SIEM hook available |
| A.8.31 | Separation | Honeypot isolated VPC/container; no prod connectivity (egress allow-list) |
| A.6.8 / A.8.34 | Compliance & privacy | Deception deployments documented + consent-level sign-off (README `AUTH_ETICS.md` future) |

## 4. OWASP Top 10 (Door-as-App)

| OWASP | Risk | Mitigation |
|-------|------|------------|
| A03 Injection | Attacker command text could be evaluated | `_fake_exec` NEVER evals; only string matching against a fixed map of commands. `str.replace`-free. |
| A05 Security Misconfig | Opened on prod IP or public egress | Doors bindable to specific interfaces (default 0.0.0.0 → production: bind internal/DMZ interface only) |
| A06 Vulnerable Components | `http.server` STDLIB | stdlib = minimal surface; HTTPS path not yet wired (tls downgrades unlikely in LAN demos) |
| A08 Data Integrity | Fake log poisoning | Export envelope includes source+ts; session IDs unique per peer |
| A10 SSRF | Webhook URL could be GDE tricked | Blocklist webhook requires HTTPS + authorization header; host allow-list config (default empty → disabled) |

## 5. Safety Rails (hard, not soft)

1. **No real exec**: `_fake_exec` is a static lookup; no `os.system`, no `subprocess`.
2. **Egress allow-list**: `config/doors.yaml` `guards.egress_allowlist`; any attempt to reach outside → blocked at network layer (network policy, not in-process).
3. **Rate limiting**: `max_auth_attempts_per_session` (20) and `session_timeout_s` (30) in config — enforced by guards; another hard brake, not a soft warning.
4. **Honeytoken hygiene**: tokens listed explicitly in config; no real credentials allowed there (CI check planned).
5. **Volatile task**: sessions flush on shutdown; disk-write flood guarded by bounded queue in `EventExporter` (appends only, no unbounded buffering in memory).

## 6. Incident Response Notes

1. **Session reaches fake "root"** → this is expected behavior for an attacker; verify it's only logged (fake passwd, fake FS) not real. If a real exec occurred → incident: revert FS image, kill doors, rotate all creds in image.
2. **Blocklist push storm** (many critical sessions) → check `guards.max_auth_attempts`; consider raising; confirm Project 16 dedupe accepts bursts.
3. **Honeypot itself compromised** (e.g., container escape): egress blackhole + snapshot of image for forensics; do NOT destroy evidence.
4. Recovery: restore fake FS from golden image, rotate honeytokens, relaunch under tightened network policy (only DMZ + blocklist egress).