# Social Engineering Awareness Simulator — Architecture (Bangladesh Banking Edition)

> Internal phishing-test platform for production deployment in Bangladeshi banks.
> **Format overview** — see `architecture.html` for the full colour-rendered architecture document.

## Compliance Scope
- Bangladesh Bank ICT Security Guidelines (2015 / revised circulars) — data residency, awareness & training, audit retention, secure SDLC
- **OWASP Top 10 (2021)** — A01–A10 control matrix
- **NIST CSF 2.0** — Govern / Identify / Protect / Detect / Respond / Recover
- **ISO/IEC 27001:2022** — Annex-A mapping (prepared evidence)
- OWASP ASVS L2 target, OWASP Top-10 API Security

## Tech Stack
| Layer | Choice |
|---|---|
| Frontend | React 18 + TypeScript + Vite + Tailwind + AG-Grid |
| Backend | FastAPI (Python 3.12), REST/OpenAPI 3 |
| Async | Celery + Redis 7 (queue/broker) + Beat scheduler |
| Data | PostgreSQL 16 (OLTP, RLS, replicas via Patroni), Elasticsearch 8, MinIO/S3 |
| Security | CDN+WAF (OWASP CRS), mTLS, Vault/KMS, MFA/SSO (OIDC/SAML), rate limiting |
| Delivery | SMTP relay farm (SPF/DKIM/DMARC), BD SMS aggregator, sandboxed lure hosts |
| Reports | **.XLSX** (openpyxl) · **.CSV** (RFC 4180 + UTF-8 BOM) · **.HTML** (self-contained) |
| Deploy | Kubernetes / on-prem (Bangladesh DC), GitLab CI / GH Actions |

## Topology (zones)
1. **Internet / WAN** — admin console, target browser, mobile/SMS.
2. **Perimeter / DMZ** — CDN+WAF, Nginx LB (TLS 1.3), reverse proxy w/ SSRF guard.
3. **Application zone (segmented)** — SPA, API gateway, FastAPI replicas, Celery workers, Beat.
4. **Data zone (Bangladesh DC, no foreign egress)** — Postgres, Redis, Elasticsearch, MinIO, Vault.
5. **Outbound lure fabric (isolated)** — SMTP/SMS/landing-page hosts with **no return route** to the data plane except the signed event webhook.

## Functional Modules
1. Campaign Studio (multi-vector, approvals, traffic shaping)
2. Template & Lure Engine (Bengali/English clones, A/B, sandboxed)
3. People Directory (SCIM/AD/HR, opt-out registry)
4. Delivery & Tracking Engine (pixel/click/submit/report)
5. Training & Remediation (micro-learnings, quizzes, re-test loop)
6. Risk Scoring & Analytics (SE-Index 0–100, predictive)
7. Compliance Engine (hash-chained audit, consent, evidence bundles)
8. Reporting & Export Hub (XLSX / CSV / HTML)

## Campaign Lifecycle
Design → Audience → Approval (dual) → Schedule → Deliver → Track → Report → Score → Train → Export.

## Domain Model (PostgreSQL)
`organizations · employees · campaigns · campaign_variants · email_templates · sms_templates · landing_pages · deliveries · events · submissions · risk_scores · trainings · consent_records · audit_logs · report_bundles · identities`

## Security Highlights
- **OWASP:** A01 RBAC/RLS · A02 AES-256/TLS 1.3 · A03 parameterised SQL / sandboxed templates · A04 consent-driven design · A05 OWASP CRS + security headers · A06 Trivy/SBOM in CI · A07 SSO+MFA · A08 signed artifacts & audit chain · A09 WORM logs → SIEM · A10 SSRF guard + egress allow-list.
- **NIST CSF:** risk register (Govern/Identify), micro-segmentation + DLP (Protect), SIEM alerts (Detect), runbooks + DR drills (Respond/Recover).
- **ISO 27001 Annex A:** A.5 policy/access/incident, A.6 workforce awareness (this platform), A.7 physical, A.8 technology & secure dev.
- **Ethics:** board policy, employee consent ledger, masked/hashed captured inputs, Do-Not-Phish registry, retention & purge SLA.

## Report Formats
- **.XLSX** — multi-sheet (Executive Summary, Campaign Performance, Employee Risk Matrix, Raw Events) + charts + conditional formatting.
- **.CSV** — strict RFC 4180, UTF-8 BOM (Bangla-safe in Excel), logical splits.
- **.HTML** — self-contained interactive pack (inline SVG charts, drill-down, printable, optional AES passphrase).
- Pipeline: authorised request → SQL rollups → async render → sign/store (S3) → signed short-lived URL or scheduled email.

## Non-Functional
50k employees/tenant · 100k deliveries/day · 99.5% uptime · p95 < 400 ms · export < 5 min · RPO 15 min / RTO 2 h (two in-country zones + DR city + quarterly drills).

## Rollout
P0 Foundations → P1 MVP (email, pilot branch, XLSX/CSV) → P2 Multivector (SMS/QR/HTML, risk v1) → P3 Predictive (ML, board BI, regulator API) → P4 Programme (vishing/USB, group-wide, ISO evidence).

---
*See `architecture.html` for colour diagrams, control matrices and the full report-pipeline detail.*