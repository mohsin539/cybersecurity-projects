# Project 13 — Custom Wazuh/OSSEC Detection Rule Pack for a Specific Attack Chain

> A **versioned, tested rule pack** delivered for Wazuh/OSSEC managers that detects the stages of a chosen attack chain (e.g., AoW or a custom C2 chain) and maps each fired rule to MITRE ATT&CK for incident response clarity.

---

## 1. High-Level Architecture

```
        MANAGER SIDE                              PACK CONSUMERS
┌──────────────────────────────┐   ┌───────────────────────────────┐
│ OSSEC/Wazuh Manager          │   │ Security Analyst / SOC         │
│                              │   │                               │
│  Decoders ─▶ Rules ─▶ Output │   │  Alerts dashboard / Wazuh UI    │
│   (parse   (match   (match   │   │  MITRE ATT&CK mapping          │
│    raw)    fields,  level,   │──▶│  Threat hunting queries        │
│            group)  id/level)│   │  IOC escalation / response      │
│        ▲                     │   └───────────────────────────────┘
│        │  unified pack via                    ▲
│        │  <decoder> / <rule> files            │
│  ┌─────┴──────┐        ┌──────────────────┐   │
│  │  Decoder   │        │  Ruleset         │   │
│  │  plugins   │        │  (ids, groups,   │   │
│  │  (pcre2)   │        │   levels, alerts)│   │
│  └────────────┘        └──────────────────┘   │
│         CHAIN-AWARE PACK = grouping over      │
│         kill-chain phase + correlation hooks  │
└───────────────────────────────────────────────┘
```

**Escalation path of an alert:**
`RAW LOG → DECODER (pcre2) → RULE MATCH (ordered by id) → LEVEL/GROUP ACCUMULATION → ALERT OUTPUT (level threshold, e.g., >= 3 scored) → Wazuh indexer / analyst queue`.

---

## 2. The Target Attack Chain (What the Pack Detects)

Chain of choice (assumed here: **Initial Access → Execution → Persistence → C2**). Adjust keys in `pack.yaml`.

| Phase | MITRE T-code | Observable (log source) | Rule intent |
|-------|--------------|-------------------------|-------------|
| Initial Access | T1566 (phishing), T1190 (exploit) | webserver 5xx + odd UA; `POST /upload` | flag anomalous web requests |
| Execution | T1059.001 (pwsh), T1203 | `powershell -enc`, cmd `/c` from web | flag encoded cmdline |
| Persistence | T1547.001 (registry), T1053 (schtasks) | registry change, new scheduled task | flag persistence install |
| C2 | T1071.001 (HTTP), T1573 (enc) | beacon regex in HTTP headers, long-lived conn | flag C2 channel pattern |
| Exfil | T1041 (HTTP) | large outbound POST to new egress | flag data egress |

Each stage becomes a **rule cluster**; the pack's novelty = **cross-stage correlation** (an exec-stage alert enriched with prior access-stage alerts on the same host becomes a higher-signal incident).

---

## 3. Component Breakdown

### 3.1 Decoders
- `custom_decoder.xml` — pcre2 patterns tuned to the *specific* logs the chain produces (app-specific error strings, IIS/nginx formats, Windows `Sysmon` event IDs that the OSSEC default decoders under-cover).
- New/override `<decoder name="eventchannel-Sysmon" ...>` keeping the **prefilter** structure of stock decoders so the pack composes with defaults rather than replaces them.
- Each decoder emits **only fields the rules consume** (`user`, `srcip`, `fw-action`, `url`, `cmdline`) — keeps rules readable.

**Decoding hierarchy rules (inheritance):**
```
<decoder name="chain-http-hits">
  predecode: same_as  ▶ parent matched
  <regex> attack pattern 1 </regex>
```
> OSSEC/Wazuh decoders are matched **in definition order**, first match wins; the pack must place custom decoders *after* base ones but anchor with restrictive regexes to avoid overshadowing.

### 3.2 Ruleset
`custom_rules.xml` with a reserved ID range (e.g., `200010–200999`) to avoid collisions with vendor IDs.

Rule anatomy:
```xml
<rule id="200101" level="7">
  <decoded_as>chain-app</decoded_as>
  <field name="action">upload</field>
  <field name="status_code">^4</field>
  <description>Potential webshell upload (access.detect)</description>
  <mitre>
    <id>T1505.003</id>
    <tactic>Persist</tactic>
  </mitre>
  <group>chain_access,</group>
</rule>
```

**Structure conventions in the pack:**
| Convention | Purpose |
|------------|---------|
| Sequential `group="chain_<phase>,"` tags | Quest for phase-level hunting |
| `<if_sid>` / `<if_group>` cross-references | Chain-aware escalation (event in phase N + prior phase signal) |
| Nested `<rule>` (parent → child) | Reuse: e.g., `100101generic_timeout` parent + custom child keeps logging tidy |
| Levels: 2=informational, 6–7=suspicious, 10–12=critical phase finalization | Consistent free-tier escalation |

### 3.3 Chain Correlation Hooks
- **Group propagation:** alerts tagged `chain_persistence` enable the manager to run the *phase-final* rule `200950` at level 12 whenever ≥ 3 distinct chain groups match within a window — implemented as a *synthetic parent rule* using stock OSSEC `alerts` JSON + `wazuh-db` query on `alert.groups`.
- **Lookup extension:** pack ships a `wazuh-api`-consuming script (`chain_enrich.py`) that, on phase-final alert, pulls prior alerts for the same host from the indexer and attaches the chain graph to the alert as `data.chain_evidence`.

### 3.4 Output / Alert Enrichment
- `ossec.conf` `<alerts>` actions: forward level ≥ 6 to the indexer; level ≥ 10 to an outbound webhook (SIEM of Project 11 / blocklist of Project 16).
- Alert JSON enriched with: `mitre.technique`, `chain.phase`, `chain.attempt_id`, `rule.description`, `decoder` name.

---

## 4. Pack Composition / Directory Layout

```
custom-chain-pack/
├── etc/
│   ├── decoders/
│   │   └── 01-chain_decoders.xml
│   └── rules/
│       ├── 20-chain_access_rules.xml     # phase1
│       ├── 20-chain_exec_rules.xml       # phase2
│       ├── 20-chain_persist_rules.xml    # phase3
│       ├── 20-chain_c2_rules.xml         # phase4
│       ├── 20-chain_exfil_rules.xml      # phase5
│       └── 20-chain_phasefinal.xml       # synthetic phase-final correlator
├── scripts/
│   ├── chain_enrich.py                  # post-alert enrichment via API
│   └── validate_pack.py                 # CI: schema + id-range + cycle checks
├── tests/
│   ├── sample_logs/                      # one fixture log per phase stage
│   └── expected/                         # golden expectations (rule_id, level)
├── pack.yaml                             # metadata: chain name, MITRE matrix, id ranges
└── README.md                             # install & tuning guide
```

---

## 5. Validation / CI Strategy

1. **Latency regression:** run each fixture through `ossec-rule-engine` in a test manager (Wazuh `elastic-stack` dev install); assert exact `rule_id`, `level`, `group`, and `description` match expectations.
2. **No-shadow test:** assert custom decoder does not intercept logs meant for default decoders (feed a control corpus of normal logs, expect zero triggers).
3. **ID hygiene:** `validate_pack.py` asserts every custom id inside reserved range; no duplicate ids; every `<mitre>` uses a real technique id; dependencies (`<if_sid>`) reference ids that exist.
4. **False-positive smoke test:** replay 1 week of legit production logs → alert volume stays under a stated SLO (noise budget).
5. **Chain test:** concatenated fixture of the full attack chain → assert phase-final level-12 alert appears with `chain_evidence` attached.

---

## 6. Operational Notes (Manager Configuration)

- Install: copy decoder/rules into `ossec/etc/decoders` + `ossec/etc/rules`, tag with `chmod` read-only, restart `ossec-analysisd`.
- Tuning surface in one file: `pack.yaml` exposes threshold & level overrides; regenerates the XML on `make build` — keep XML hand-editable, but generated from canonical YAML to stay reproducible.
- Documented **baseline tuning**: whitelist repeaters via `<rule level="0">` exceptions in a separate `tuning` file, never deleting pack defaults.

---

## 7. Decision Log (Architecture Choices)

1. **Pack as pure config + companion scripts** (no manager fork) — deploys unmodified on OSSEC 3.x and Wazuh 4.x.
2. **Dedicated ID range** — collision-free upgrade against stock sets.
3. **Synthetic phase-final rule over external logstore joins** — correlates within the manager for free; directory-level joining lives in the script layer so it's optional.
4. **Canonical YAML → generated XML** — review-friendly diffs, single tuning point, testable build.