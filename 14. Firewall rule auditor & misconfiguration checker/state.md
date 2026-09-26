# Project 14 — State

## 1. Component Status

| Component | Status | Notes |
|-----------|--------|-------|
| `model.py` (Rule, range algebra) | ✅ Implemented | traffic_covered / identical / superset tested |
| `collect.py` (load_json_fixture) | ✅ Implemented | generic JSON adapter; live adapters not wired |
| `analyze.py` probes (shadow, redndant, broad, default, any-any, logging) | ✅ Implemented | 6 pure-function probes |
| `score.py` (risk matrix) | ✅ Implemented | severity × exposure × blast ÷ mitigations |
| `report.py` (findings + remediation + diff) | ✅ Implemented | remediation text + additive diff |
| `main.py` CLI | ✅ Implemented | `--rules`, `--out`, `--self-test` |
| Live adapters (iptables, AWS boto3, Azure/GCP, K8s, IaC) | 🔲 Not started | architecture.md §2.1 |
| Snapshot retention + hash chain | 🔲 Planned | integrity of reports (OWASP A08) |
| Report redaction/scanning | 🔲 Planned | security.md §5 |
| `--apply` remediation (dry-run only) | 🔲 Planned | gated + two-person review |

## 2. Verified Behavior (SMOKE TEST dated 2026-09-13)

`py main.py --self-test` → **PASS** (6 probes, exact golden counts).
`py main.py --rules fixtures\aws_sg.json --out data` produced:
- findings: 5 — broad_exposure(critical), shadowed(high), any_any(high), logging_disabled(medium), redundant(medium)
- device score 100 (worsened posture — fixture deliberately vulnerable)
- report written: `data/findings-<snap>.json` with remediation strings

Unit truth checks: `traffic_superset` action-aware vs `traffic_covered` action-blind both validated; port range rules (`[443,443]`, `[1,65535]`, `any`) verified.

## 3. Known Gaps & Risks

| Gap | Risk | Priority |
|-----|------|----------|
| Live adapters absent | Only static fixture input today | High (adapter workstream) |
| IPv6 CIDR | `ipaddress` handles but fixtures are v4-only | Medium — add v6 fixture |
| Rule ordering bugs in iptables-style (priority distinct) | Model supports priority but probes assume ordered list | Low — document canonical ordering contract |
| No `--apply` yet | Remediation proposals manual only | Medium |
| Blast-radius weights hardcoded | Asset inventory integration absent | Low |

Priorities: (1) live adapter MVP (iptables text + AWS SG), (2) IPv6 fixture + probes, (3) snapshot hash chain.

## 4. Definition of Done for Next Milestone

- [ ] `iptables -S` text adapter with golden parsing test
- [ ] AWS `describe-security-groups` JSON adapter (read-only) same as fixture but via boto3-free REST-injectable mock
- [ ] `probe_shadowed` confirmed on realistic 100-rule corpus
- [ ] Report snapshot hash + `--verify`