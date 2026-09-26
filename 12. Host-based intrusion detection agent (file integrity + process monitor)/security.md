# Project 12 — Security Posture

Controls for the HIDS agent mapped to **NIST CSF 2.0**, **ISO 27001:2022 Annex A**, and **OWASP Top 10** (agent-as-application perspective).

---

## 1. Threat Model Summary

| Asset | Trust boundary | Main threats |
|-------|----------------|--------------|
| File integrity baseline (DB) | Host filesystem | Attacker modifies baseline to hide tampering (T1070.002) |
| Process snapshot | Kernel / proc interface | Agent bypassed by DKOM or rootkit |
| Alert output (JSONL / syslog / webhook) | Outbound network / filesystem | Alert suppression, man-in-the-middle exfil |
| Agent binary + config | Host FS, same user | Agent itself tampered — masquerading (T1036) |

The agent runs with **least-privilege**: it reads FS/proc, writes only under `--state`. It never executes attacker data and never blocks.

---

## 2. Controls — NIST CSF 2.0

| CSF Function | Control (NIST 800-53) | Implemented |
|--------------|-----------------------|-------------|
| **Govern** | GV.RM | Agent scope config (JSON) centrally controlled; own file ACLs tightened at install |
| **Identify** | ID.AM, ID.RA | FIM baseline serves as asset inventory; process scan captures process inventory |
| **Protect** | PR.AC-4 least privilege | Agent runs under its own user; never gains root beyond its state dir |
| **Protect** | PR.DS-1 integrity, PR.DS-2 protection | Baseline DB stored WAL; detect if DB tampered via hash-chained snapshots (architecture.md 2.4) |
| **Protect** | PR.PT-4 audits (logging) | All findings written to local JSONL + Wazuh/syslog; chain-of-custody: source+seq+ts |
| **Detect** | DE.CM-1, DE.AE-2 | FIM hash diff + process anomaly detection |
| **Respond** | RS.AN-4 escalation | Findings carry severity; high findings routed to SIEM webhook |

## 3. Controls — ISO 27001:2022 Annex A

| Clause | Domain | Control |
|--------|--------|---------|
| A.8.9 | Technical vulnerability mgmt | FIM detects unpatched/out-of-configuration file changes in real time |
| A.8.16 | Monitoring activities | Process snapshot at configurable interval; deviations flagged per-risk |
| A.8.15 | Logging | Findings include: timestamp, affected path/pid, action, severity, sha256 |
| A.8.28 | Secure coding | Stdlib-only; no eval; no dangerous imports; full stack in repo for audit |
| A.8.31 | Separation of environments | Agent state DB isolated from monitored scope paths (prevent false baseline writes) |
| A.8.24 / A.8.25 | Secure development | CI: hash check, process cmdline tests, tamper-simulation test |

## 4. OWASP Top 10 (Agent-as-App)

| OWASP | Risk | Mitigation |
|-------|------|------------|
| A03 Injection | Baseline DB is read-only in production; path values validated (no SQL injection — SQLite parameterized, no string interpolation) | SQLite `?` parameterization throughout `BaselineDB` |
| A04 Insecure Design | FIM scope auto-baseline on first run could overwrite attacker state | Mitigated by explicit `--baseline` flag (no silent auto-update) |
| A05 Security Misconfiguration | Agent runs as root by default on Linux | Install script creates dedicated `hids` user; process dir ACLs documented |
| A06 Vulnerable Components | No external dependencies — SBOM trivial (stdlib + CPython) | Pin `>=3.10`, CVE scan on CPython itself |
| A08 Data Integrity | Attacker could tamper findings.jsonl | Findings are append-only in a restricted directory; baseline DB is WAL (detectable tamper via journal hash) |

## 5. Security-Specific Implementation Notes

- **SQLite parameterization:** all queries use `?`-bound parameters (`cursor.execute("SELECT ... WHERE path=?", (path,))`), eliminating injection vectors.
- **Scope allows explicit deny list:** `Scope.ignores` is hardcoded; no untrusted input can whitelist attacker files.
- **Process names from /proc/[pid]/comm:** bounded-length kernel source; cmdline parsed from `/proc/[pid]/cmdline` null-separated buffer, not shell-split.
- **At-rest sensitivity:** baseline DB can be encrypted via volume-level encryption (OS layer, documented in `security.md` §6). Agent never handles encryption keys directly.
- **Agent self-protection (planned):** alert on own-file change (agent binary + config in FIM scope). Install script sets immutable bit (Linux) or read-only DACL (Windows).

## 6. Incident Response Notes

1. **FIM: baseline override detected** (DB hash mismatch) → agent self-alerts, enters alert-only safe-mode.
2. **Process flag high-severity** (unknown binary) → analyst reviews `hash + exe path + cmdline`.
3. **Alert suppression suspected** → check `findings.jsonl` gaps vs expected schedule; compare with SIEM (Project 11) log arrival pattern.
4. **Full DB tamper** → restore from snapshot; run fresh `--baseline` with operator approval (audit logged).