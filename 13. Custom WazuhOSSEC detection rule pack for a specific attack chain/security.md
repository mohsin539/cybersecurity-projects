# Project 13 — Security Posture

---

## 1. Threat Model Summary

| Asset | Trust boundary | Main threats |
|-------|----------------|--------------|
| Rule XMLs (`etc/rules/*.xml`) | Manager analysisd trust | Injection: crafted regex causes ReDoS, or wrong `<if_sid>` ID triggers benign false-positive / is bypassed |
| `validate_pack.py` / `chain_enrich.py` | CI / analyst workstation | Dependency-less stdlib mitigates supply-chain; but scripts run as the analyst who deploys |
| Wazuh/OSSEC manager endpoint | Host process with root | Pack loaded into analysisd; malformed XML can crash the analysis engine (Denial of service on detection pipeline) |
| TLP handling in `chain_enrich.py` | External API call | Accidentally exfiltrate ATT&CK data to untrusted endpoint if `--index` points elsewhere |

All three control families below apply here: NIST, ISO, and OWASP mapped to the pack-as-software.

---

## 2. Controls — NIST CSF 2.0

| CSF Function | Control | Implemented |
|--------------|---------|-------------|
| **Govern** | GV.OC | Pack metadata (`pack.yaml`) declares versioned, author-tagged, TLP rule; deployment gated behind `validate_pack.py` CI |
| **Identify** | ID.RA | MITRE technique IDs verified at build; every `<mitre>` tagged to a known T-code |
| **Protect** | PR.IP-1 secure config mgmt | `pack.yaml` is single source of truth; `make build` regenerates XML from canonical definitions (no hand-edits for `level_overrides`) |
| **Detect** | DE.CM-1 detection engineering | Test fixtures replay attack stages; `golden_alerts.json` asserts expected rule_id/level |
| **Respond** | RS.AN-4 incident response | Phase-final alert (level 12) triggers auto-enrichment attaching full evidence chain (4-phase coverage) |

## 3. Controls — ISO 27001:2022 Annex A

| Clause | Control |
|--------|---------|
| A.8.31 (new 2022) | Separation of test vs prod rulepacks; CI runs `validate_pack.py` against `etc/rules` only; test fixtures never loaded by analysisd |
| A.8.8 (TPM/mgmt) | Versioned pack (pack.yaml); git commit hash embedded in release artifacts |
| A.8.28 | `validate_pack.py` enforces ID hygiene, regex length, and target existence—secure coding practice |
| A.8.15 | CI log `RESULT: PASS/FAIL` (machine parseable) logged per build |
| A.8.11 | Tagged IDs never collide with stock Wazuh/OSSEC rules (reserved range 200010-200999 documented) |

## 4. OWASP Top 10

| OWASP | Risk (in context) | Mitigation |
|-------|-------------------|------------|
| A03 Injection (ReDoS) | Regex in `<regex>` can attack analysisd engine | **Controlled regex patterns**: all regexes in this pack are bounded, no backtracking-heavy patterns; `validate_pack.py` should (future) call a regex-fuzzer (documented in state.md) |
| A05 Security Misconfig | Default `<level>` settings can produce noise floods | `pack.yaml` `noise_budget_alerts_per_day: 50` enforced by `validate_pack.py` in coverage report |
| A07 Auth Failures | `chain_enrich.py` sends auth-token to external endpoint | Token bound via `$TOKEN` env, never hardcoded; HTTPS-only enforced in future |
| A08 Data Integrity | MITRE IDs in pack must remain current | `validate_pack.py` regex verify; periodic ATT&CK update check planned (state.md) |

## 5. Security-Specific Implementation Notes

1. **`validate_pack.py` runs `ET.parse()`** — XML standard library parser; no custom eval; safe against XML entity expansion (entity declarations stripped by default).
2. **`chain_enrich.py` does network I/O only when `--index` is set** — safe to run offline/air-gapped; golden fixture works fully without network.
3. **Rule groups** (`chain_access,`, `chain_exec,`, etc.) always **trailing comma-delimited** — standard for Wazuh group lists; prevents double-match bugs.
4. **Test fixture naming convention** (`fs access.log`) uses spaces; safe on Linux, acceptable on Windows but no quoting ambiguity in `ET.parse()`.

## 6. Incident Response Notes

1. **False-positive flood**: reduce `noise_budget_alerts_per_day` in `pack.yaml`, remove offending `<regex>` from affected rule, re-run `validate_pack.py`.
2. **MITRE update needed** (technique retired/renamed): update `<mitre>` tag in rules XML; run validator; snapshot golden_alerts.json.
3. **Phase-final false-positive**: review `chain_enrich.py` attached evidence; if host showed unrelated phases on different users, tighten `<if_group>` to require same `src_ip` (field check on the parent rule).