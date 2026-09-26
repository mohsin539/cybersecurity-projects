# Project 14 — Memory (Development Journal)

## 1. Architecture Decisions

| Decision | Rationale |
|----------|-----------|
| Platform-neutral `Rule` model + adapters | One detection engine for cloud+on-prem+IaC (architecture.md §7.1) |
| Pure-function probes | Unit-testable, no I/O in analysis, oracle-driven self-test |
| Probes ordered by rule-list index (not priority field) | Matches real devices where order of table = decision order; keep that contract |
| Read-only defaults | Audits never mutate; `--apply` future extension gated |
| Fixture as golden | Self-test doubles as regression oracle + CI gate |

## 2. Gotchas / Semantics Landmines

1. **action-aware vs action-blind superset** — `traffic_superset` requires same action (pure redundancy). `traffic_covered` is blind (used for the *security* shadow case allow→deny). Do NOT replace one with the other.
2. **`ipaddress` treats `0.0.0.0/0` and `::/0` differently** — both map to "any" via `normalize_cidr`, but strict False-y rules can compare IPv6 vs IPv4 networks and crash `overlaps`. All probes use `None-any` conventions first. Keep it that way.
3. **`any` port vs exact port** — `traffic_identical` deliberately treats any-ports NOT identical to a specific port. An any-ports rule is a superset → that's redundancy or broad-exposure, never "identical duplicate".
4. **Fall-open on bad CIDR → treated as any** — safer for availability, mistaken for config only if data is malformed. Documented; `--fail-closed` config flag planned.
5. **Rule list must preserve firewall first-match ordering** — probe order matters; do not sort rules by priority in the fixture without updating the ordering contract.

## 3. Conventions

- Probe functions named `probe_<kind>` returning `List[dict]` with `kind` key.
- `findings-<snap>.json` immutable-named per scan (timestamp UTC).
- `SELF_TEST_EXPECT` mirrors golden counts; extends when probe output changes (update both together).
- All network/IO strictly in `collect.py` adapters; probes/score/report are pure.

## 4. Cross-Project Hooks

- Findings feed **Project 16** (auto-blocklist overrides: never block own infrastructure, respond to firewall change events).
- Cleanup/remediation recordings notify **Project 11** SIEM via `intel_event` webhook (planned).

## 5. Warning for Future Developers

- Adding a probe? Add it to `PROBES`, add golden count to `SELF_TEST_EXPECT`, add remediation in `report.remediation_suggestion`, and update fixture with the exact case. Ship all four together — self-test enforces it.
- NEVER let `collect.py` parse non-whitelisted JSON keys into `metadata` silently; unknown keys are dropped (schema allow-list) — keep it that way, it prevents injection.
- IPv6: keep `normalize_cidr` returning None for both v4/v6 `any`; if you add `overlaps()` for v6, guard version-mismatch pairs.