# Project 13 — State

## 1. Component Status

| Component | Status | Notes |
|-----------|--------|-------|
| `etc/decoders/01-chain_decoders.xml` | ✅ Implemented | 4 decoders: web, cmdline, persist, C2 |
| `etc/rules/20-chain_access_rules.xml` | ✅ Implemented | levels 6-7, traversal detect |
| `etc/rules/20-chain_exec_rules.xml` | ✅ Implemented | level 6-8, pwsh/curl/shell shape |
| `etc/rules/20-chain_persist_rules.xml` | ✅ Implemented | level 7-8, cron/autorun |
| `etc/rules/20-chain_c2_rules.xml` | ✅ Implemented | level 8-9, beacon/POST/upload |
| `etc/rules/20-chain_exfil_rules.xml` | ✅ Implemented | level 9-10 |
| `etc/rules/20-chain_phasefinal.xml` | ✅ Implemented | level 5 bootstrap → level 12 final |
| `scripts/validate_pack.py` | ✅ Implemented | ID range, deps, MITRE, XML parse |
| `scripts/chain_enrich.py` | ✅ Implemented | Equivalent-mode + live-index fallback |
| `tests/sample_logs/*` | ✅ Implemented | 2 fixtures (web + hids) |
| `tests/expected/golden_alerts.json` | ✅ Implemented | 9 alert goldens |
| ReDoS fuzzer for regex validation | 🔲 Planned | state.md §3 |
| ATT&CK update automation | 🔲 Planned | state.md §3 |

## 2. Verified Behavior (SMOKE TEST dated 2026-09-13)

**validate_pack.py:**
```
rules parsed: 16  ids: 16
coverage: chain_access=3, chain_c2=2, chain_exec=3, chain_exfil=2, chain_persist=3, chain_phasefinal=3
RESULT: PASS
```

**chain_enrich.py:**
```
enriched -> chain_alert.enriched.json
  phases attached: ['access', 'exec', 'persist']
RESULT: phasefinal-confirmed
```

Golden fixture loaded, phases correctly aggregated, enrichment works in offline/equivalent mode.

## 3. Known Gaps & Risks

| Gap | Risk | Priority |
|-----|------|----------|
| ReDoS fuzzer not automated | A crafted regex in future pack update could cause analysisd hang | High |
| No Wazuh integration test harness | Pack validated statically; no proof it passes `ossec-analysisd -t` | Medium |
| MITRE ATT&CK update | Techniques retired/renamed (T-codes remain but names shift) | Low (quarterly) |
| Phasefinal detection relies on group propagation | Groups must be correctly triggered across analysisd runs; if group list flushed between window, final may not fire | Medium — documented caveat |
| No `if_sid` dependency graph visualizer | Harder to trace which rules chain-escalate; PR reviewers may miss regressions | Low — state.md §3 |

## 4. Definition of Done for Next Milestone

- [ ] ReDoS fuzz test (Python `hypothesis` + timeout) integrated in CI (or stdlib timeout-based)
- [ ] Wazuh dev-docker install for live validation test
- [ ] ATT&CK ID checker calls ATT&CK STIX API (canonical list, not regex-only)
- [ ] Phasefinal rule hardened: require same `src_ip`/`host` across phases via `<field>` check in parent