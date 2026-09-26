# Project 14 — Security Posture

Controls mapped to **NIST CSF 2.0**, **ISO 27001:2022 Annex A**, and **OWASP Top 10**.

---

## 1. Threat Model Summary

| Asset | Trust boundary | Main threats |
|-------|----------------|--------------|
| Rule fixtures / adapter inputs | Local FS / cloud API | Forged rulebases (adversary-controlled rules), path injection in fixture load |
| Analyzer (probes, scorer) | same process | Logic bugs → missed misconfig; DoS via huge rulesets |
| Reports (`findings-*.json`) | Local FS | Tampered conclusions; secrets (cloud creds) leaking into report |
| Remediation module | Network mutations | Inadvertent destructive edits if `--apply` misused |

Trust POSTURE: the tool is READ-ONLY by default. All mutation paths are gated behind explicit flags (`--apply` + double-confirm) and dry-run only.

---

## 2. Controls — NIST CSF 2.0

| CSF Function | Control | Implemented |
|--------------|---------|-------------|
| **Identify** | ID.RA, ID.AM | Rule inventory per device (fixture model); asset tagging stubbed (blast-radius weights by `some`/`many`) |
| **Protect** | PR.AC-3 access control, PR.DS safe storage | Read-only adapters; report dir chmod 640-documented (OS layer) |
| **Protect** | PR.PT-1/3 audit | Every scan timestamped snapshot; `findings-<snap>.json` immutable pattern; diff function for change detection |
| **Detect** | DE.CM | Broad-exposure / shadowing / any-any probes run on every scan |
| **Respond** | RS.RP | Remediation proposals rendered per finding (no auto-apply) |
| **Recover** | RC.RP | Prior snapshots retained → rollback/restore grounding |

## 3. Controls — ISO 27001:2022 Annex A

| Clause | Domain | Control |
|--------|--------|---------|
| A.8.8 / A.8.9 | Technical vuln mgmt | Broad/admin port exposure flagged; patched device posture reportable |
| A.8.12 | Prevention of info leakage | Cloud creds never pass through; adapters accept fixture JSON only today (live adapters must be run in authenticated, single-purpose service accounts) |
| A.8.15 | Logging | Every scan writes a report; diff events auditable |
| A.8.28 | Secure coding | Pure-function probes (no I/O inside analysis), whitelisted JSON schema, no eval |
| A.8.24/8.25 | SDLC | Self-test suppresses drift (golden fixture + PASS/FAIL) |
| A.6.8 | Compliance (future) | PCI/HIPAA port-baselines can be expressed as probe parameter sets (policy-driver pattern planned) |

## 4. OWASP Top 10

| OWASP | Risk | Mitigation |
|-------|------|------------|
| A03 Injection | Fixture JSON could include path injection or huge lists | `_to_ports`/`ports` validated against ints; CIDR parsed via `ipaddress` (strict parse rejects garbage → None, treated as any — documented) |
| A04 Insecure Design | Adversarial rulebase could silently defeat analysis | Probes are pure functions over normalized model; no hidden evaluator; self-test acts as oracle |
| A05 Security Misconfiguration | Reports contain sensitive network topology | `data/` read-restricted; future redaction config for report redaction (state.md) |
| A06 Vulnerable Components | stdlib only | CPython version pinned in package.json; SBOM = interpreter |
| A08 Data Integrity | A rolled-back rule change could pass scanning | Snapshot hash comparison planned (`diff` + snapshot retention) |

## 5. Implementation Notes

1. **`load_json_fixture`** — only integer port specs, CIDR strings, and known keywords (`any`) accepted; unknown keys ignored (schema allow-list).
2. **`ipaddress` strict parse** — malformed CIDR returns `None` and is **treated as `any`** (fail-open). This is safer than failing (never miss a config) but documented; alternative fail-closed flag configurable.
3. **Probes carry no I/O** — all analysis happens in pure functions; network/data access isolated in `collect.py` (adapter boundary).
4. Recommended OS-level: run with least-privilege Linux/Windows service user; `data/` on encrypted volume; adapter creds via vault/env (never fixtures).

## 6. Incident Response Notes

1. **False negative suspect** (missed shading): run `--self-test` to regenerate oracle; verify the fixture's golden counts still pass.
2. **Report tampering** detected by diff-of-snapshots → restore from previous snapshot, re-run scan.
3. **Credential exposure** in a report: rotate immediately, redact fixture, confirm `load_json_fixture` schema rejects secrets (never reads them).
4. **`--apply` dry-run practice** — always two-person review for live enforcement rules (projects 16 blocklist integration).