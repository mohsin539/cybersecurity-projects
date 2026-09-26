# Project 13 — Memory (Development Journal)

## 1. Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| XML rule files as primary artifact | Wazuh/OSSEC expects etc/rules/*.xml; pack must load unchanged in stock manager |
| pack.yaml as canonical source | Human review of YAML diffs; deterministic build; CI re-generates, no hand-edit conflicts |
| Trailing commas in group tags | Wazuh/OSSEC uses comma-delimited group names; always include trailing comma |
| Reserved ID range 200010-200999 | Collision-free with vendor stock rules (stock IDs are <200000) |
| Phasefinal as synthetic parent + chain_enrich.py | In-memory join on group membership; avoids modifying analysisd internals |

## 2. Gotchas (You Will Hit These)

1. **if_group and if_sid are comma-separated in Wazuh XML** — missing trailing comma causes false grouping silently.
2. **Group name chain_phasefinal is manually bootstrapped** — without rules tagged in that group first, if_group never sees alerts. Bootstrap rule 200900 and bridge rule 200902 fix this.
3. **Wazuh ET.parse() vs lxml** — stock Wazuh uses stdlib XML parser. lxml may support entity expansion that stdlib does not. Always validate with stdlib ET.parse().
4. **ReDoS risk is real** — regexes like a?a?...a?ab have exponential backtracking. All regexes in this pack are bounded literal patterns. Future rules must be fuzz-tested.

## 3. Cross-Project Hooks

- **Project 11 alerts**: chain_enrich.py queries Project 11 alert index by host=source_ip.
- **Project 12 HIDS**: hids-agent[0] prefix in syslog events matches chain-cmdline decoder prematch rule.
- **Project 16**: Phase-final alert can feed into Project 16 auto-blocklist as critical IOC source.

## 4. Conventions

- Rule IDs always prefixed with 2000xx for this chain pack (immutable once shipped).
- MITRE tags must be checked quarterly against current ATT&CK matrix.
- pack.yaml is the single source of truth; never hand-edit generated XML directly.
- Test fixtures live under tests/sample_logs; golden alerts under tests/expected.
- validate_pack.py output is machine-parseable (RESULT: PASS/FAIL).

## 5. Warning for Future Developers

- Never remove a rule ID once shipped; it breaks alert correlation for deployments using old goldens.
- The phasefinal bootstrap pattern (rule 200900 + bridge 200902) is fragile; if Wazuh changes group propagation semantics, this breaks silently.
- All regex patterns in the pack are intentionally simple; if you add complex patterns, run hypothesis ReDoS fuzz test first.