# Project 14 — Firewall Rule Auditor & Misconfiguration Checker

> Scans firewall rulebases (cloud + on-prem) for **shadowing, redundancy, broad/exposed rules, bad default policies**, and risky changes, scoring risk so teams can remediate before attackers do.

---

## 1. High-Level Architecture

```
┌─────────────────────────── FLOW ────────────────────────────┐
                                                              │
  COLLECT ──▶ MODEL ──▶ ANALYZE ──▶ SCORE ──▶ REPORT/REMEDIATE
   (via        (NFA      (12 probes)   (risk    (dashboard,
    adapters)   graph)                  matrix)   webhook, diff)
                                                              │
  RULE SOURCES                        OUTPUT                 │
  ┌ iptables/nftables                 ┌ JSON/CSV findings     │
  ├ pf / Windows (netsh/Netsh adv)    ├ HTML/PDF report       │
  ├ Cisco ASA IOS-XE                  ├ API (paged)           │
  ├ AWS SG / NACL, Azure NSG          ├ Slack/webhook         │
  ├ GCP firewall, Kubernetes NetworkPolicies                    │
  └ Terraform/CloudFormation files    └ optional auto-fix (opt-in)
```

**Core guarantee:** the analyzer works on a **platform-neutral rule model** so the same detection logic runs for cloud + on-prem + IaC.

---

## 2. Component Breakdown

### 2.1 Collect Layer (Adapters)

| Adapter | Protocol/API | Output |
|---------|-------------|--------|
| `iptables` / `nftables` | subprocess parse | flat ruleset |
| `pf` / Windows Firewall | `netsh advfirewall`, `pfctl -sr` | ruleset |
| Cisco ASA/IOS-XE | SSH/`show running-config` | ruleset |
| AWS SG & NACL | `boto3` (ec2, ec2-describe-sns) | SG+Ingress tables |
| Azure NSG | `az network nsg list` / REST | NSG tables |
| GCP | `gcloud compute firewall-rules describe` | FW table |
| K8s NetworkPolicy | kube API `networking.k8s.io/v1` | policy graph |
| IaC static | parse Terraform/CFN files (no cloud creds) | projected ruleset |

**Design requirements**
- Every adapter normalizes to a canonical object:
```yaml
{id, priority, action: allow|deny|reject, protocol, src: cidr|sg_ref, dst, ports: [..],
 stateful: bool, log: bool, direction, metadata: {device, region, source_of_record, last_seen}}
```
- Adapters are read-only by default; a single **remediation module** (gated behind a flag) performs dry-run proposals, never silent mutation.
- Refresh/ingestion via scheduler; diffs against previous snapshot stored as audit trail.

### 2.2 Model Layer (Canonical Rulebase Graph)

- Imports all collected rulesets into a unified graph/trie for set-based analysis.
- For each device: build **range trees** on `(src_cidr, dst_cidr, protocol, port_range)`.
- Normalize IPv4-mapped-IPv6 and `0.0.0.0/0` ↔ `::/0` equivalences (classic source of missed shadowing).
- Keep per-rule provenance (`device`, `rule_no`, `is_managed`, `created_by`).

### 2.3 Analyze Layer — Detection Probes

Core probes (each a pure function over the model):

| Probe | Definition | Severity |
|-------|-----------|----------|
| **Shadowed rule** | earlier rule with same/less-specific match already decides the packet (denied duplicate) | high |
| **Redundant rule** | matches identical traffic as another rule (or is subset — dead weight) | medium |
| **Broad exposure** | `0.0.0.0/0` or `*:*` allows admin ports (22/3389/8080… to internet) | critical |
| **Default-policy hole** | default `allow` w/ unscoped `deny` (implicit allow-all) | critical |
| **Any-any** | rule with `from any to any` | high |
| **Port-range creep** | rule bounded only by `1-65535` | medium |
| **Directional chaos** | bidirectional rules outnumber the expected mix (misconfig smell) | low/med |
| **Logging disabled** | `log=false` on allow rules (breaks SOC) | medium |
| **Stale/inactive rules** | rules never matched in the last N days (from flow logs) | low |
| **IaC drift** | live device differs from IaC-managed state | high |

**Rules ordering bugs** also flagged: a more-specific rule placed *after* a general `allow any` that shadows it.

### 2.4 Score Layer — Risk Matrix

- Weighted risk per finding: `risk = base_severity × exposure_factor × blast_radius ÷ mitigations`.
  - `exposure_factor`: reachable-from-internet vs internal-only.
  - `blast_radius`: affected assets count (from asset inventory / tag propagation).
  - `mitigations`: compensating controls (VPC NACL, host firewall, VPN-only).
- Aggregate device score → per-network score → org score (0–100, higher = worse).
- Findings deduplicated + merged across adapters (same rule from live and IaC counts once).

### 2.5 Report / Remediate Layer

- **Dashboard/report:** findings grouped by probe, sorted by risk; remediation suggestion per finding (proposed delete/constrict/retag).
- **Diff view:** side-by-side historical snapshot vs current — "what changed and who".
- **Webhooks:** Slack/Teams pinned to critical-only; SIEM (Project 11) receives audit events.
- **API:** paged `GET /findings`, `GET /diff/{device}`.
- **Opt-in remediation:** `--apply` proposes an ordered, reversible changeset (rollback hash), requires explicit confirm twice, writes audit log.

---

## 3. Data Flow (End-to-End Walkthrough)

1. Scheduler pulls AWS SG in us-east-1 → adapter builds ruleset.
2. Model layer composes graph with existing tf-defined SG for same VPC.
3. Analyzer finds `sg-allow-all-ssh` `0.0.0.0/0:22 allow` reachable externally → **Broad exposure, critical**.
4. Scorer: allocated weight, asset count 14, no compensating NACL → score 82.
5. Reporter adds finding; webhook to Sec channel; writes ticket via API.
6. `--apply` proposal: constrict cidr to `10.0.0.0/16`; dashboard shows diff + rollback.
7. Next scan confirms remediation; finding clears (auto-closed if absent for 1 scan).

---

## 4. Projected Directory Layout

```
fw-auditor/
├── core/
│   ├── collect/       # adapters/: iptables, aws, azure, gcp, k8s, netsh, asa, iactf
│   ├── model/         # rule schema, range trees, provenance, normalizers
│   ├── analyze/       # probes/ (one module per detection), ordering checks
│   ├── score/         # risk matrix, aggregation, dedupe
│   └── report/        # findings db, api, diff store, notify (slack/siem), remediate/
├── config/            # devices.yaml, scopes, severities, weights, retention
├── data/              # snapshot store (jsonl/parquet), audited changes
├── scripts/           # scheduler, docker-entrypoint
└── test/              # golden rulesets with expected findings
```

---

## 5. Non-Functional Requirements

| Aspect | Requirement |
|--------|-------------|
| **Scale** | Analyze 50k rules / device, 200 devices per scan, < 5 min |
| **Safety** | Read-only collection; remediation dry-run default; pilot gated |
| **Correctness of model** | Unittests on CIDR/port-set algebra incl. IPv6/to-port edge cases |
| **Credential hygiene** | Cloud creds via env/vault role, never stored in findings db |
| **Auditability** | Every scan stores snapshot + findings + scorer version → diff/rollback chain |
| **Operability** | Cron/daemon, retry-on-adapter-failure, health endpoint, structured logs |

---

## 6. Validation Strategy

1. **Golden rulebases** (with hand-verified shadow/redundant/broad cases) → every probe asserts exact finding set (regression safe).
2. **Fuzz algebra**: random CIDR/port/pair generation vs brute-force pairwise comparison → probes equal brute truth.
3. **Live sandbox**: spin disposable `iptables-nft` namespaces + fake cloud responses in CI → adapter integration.
4. **Drift test:** IaC + live difference fixture → correct drift finding.
5. **Dry-run test:** proposed changeset applied in sandbox network, network reachability verified both pre/post.

---

## 7. Decision Log (Architecture Choices)

1. **Platform-neutral model + adapter pattern** — detection logic written once; vendor adapters thin.
2. **Pure-function probes** — independently unit-testable, no I/O inside analysis.
3. **Snapshot + provenance first** — audit trail is a product requirement for compliance reviews, not an afterthought.
4. **Risk scoring with exclusions** — avoids "everything is critical" alert fatigue; supports compensating controls.