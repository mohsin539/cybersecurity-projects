# Custom Metasploit Module for a Lab-Only Vulnerable Service

**VulnLab Sentinel** — a portable web-based console that drives a *custom Metasploit module*
against a *deliberately vulnerable lab-only service*, classifies findings against **OWASP
Top 10**, **NIST (CSF 2.0 / SP 800-115 / SP 800-53)** and **ISO/IEC 27001:2022**, and exports
**`.xlsx` / `.csv` / `.html`** reports.

> **LAB-ONLY.** This project is intended for isolated, authorized penetration-testing
> education. It ships with scope, consent, and no-payload-by-default gates.

## Deliverables in this directory

| File                    | Purpose                                                        |
|-------------------------|----------------------------------------------------------------|
| `ARCHITECTURE.md`       | Full system, component, framework-mapping and packaging design |
| `design-blueprint.html` | Colorful, self-contained UI/design mockup (open in any browser)|
| `README.md`             | This overview                                                  |

## Quick start (design phase)

1. Open `design-blueprint.html` in a browser to review the full UI styling and layout.
2. Read `ARCHITECTURE.md` for the component design, MSGRPC integration, framework mapping and report pipeline.
3. Use `ARCHITECTURE.md` §11 as the scaffold for implementation.

## Preview the design

Double-click `design-blueprint.html` (fully offline, no CDN required). It walks through
four views: **Dashboard**, **Module Console**, **Compliance Map** and **Reports**, plus the
design-token palette.

## Compliance coverage (summary)

- **OWASP Top 10 (2021):** A01, A02, A03, A04, A05, A06, A07, A08, A09, A10 — each finding tagged.
- **NIST:** CSF v2.0 functions (Govern/Identify/Protect/Detect/Respond/Recover),
  SP 800-115 testing lifecycle (&sect;4–5), SP 800-53Rev5 (CA-8, SI-2, RA-5, AU-6).
- **ISO/IEC 27001:2022:** Annex A controls A.8.8, A.8.9, A.8.28, A.5.15, A.5.24/25, A.7.10.

## Report formats

- **`.xlsx`** — multi-sheet (Summary / Findings / OWASP / NIST / ISO / Evidence), color-coded severity, auto-filters.
- **`.csv`** — flat normalized rows for SIEM/integration.
- **`.html`** — single-file executive + technical report with inline charts.

## Implementation scaffold

```
backend/            FastAPI app, orchestrator, ScopeGate/ConsentGate
integration/        MSGRPC JSON-RPC adapter (loopback 127.0.0.1:55553)
modules/exploits/lab/*.rb   custom Metasploit module
lab-service/         deliberately vulnerable lab service (Docker/portable)
reporting/          xlsx / csv / html renderers
web/                compiled SPA (no CDN)
```