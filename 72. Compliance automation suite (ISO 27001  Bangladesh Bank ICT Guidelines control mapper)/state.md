# 🗃️ State.md — System State, Data Model & Lifecycle

> **Reserved & maintained as the authoritative data/state reference.** Mirrors `architecture.md` §6/§7 and the running implementation (`backend/app/models.py`, `backend/app/seed.py`).

---

## 1. Data Stores

| Store | Tech (impl) | Purpose | Path / Notes |
|---|---|---|---|
| Primary DB | SQLite (prod → PostgreSQL) | Tenancy, users, controls, assessments, risks, tickets | `backend/data/compliance.db` (WAL journal) |
| Control Graph | SQLAlchemy relations (prod → Neo4j) | CCO + `ControlMapping` 1:N edges | `controls`, `control_mappings` |
| Evidence Vault | WORM files + SHA-256 chain | Immutable artefacts + ledger | `backend/data/vault/ev-N.meta.json` |
| Reports | Generated on demand | Pre-signed exports | `backend/data/exports/` |
| Settings | Key/value table | Platform state | `settings` table |

---

## 2. Entity-Relationship (implemented tables)

```mermaid
erDiagram
    FRAMEWORKS ||--o{ CONTROLS : defines
    CONTROLS ||--o{ CONTROL_MAPPINGS : source_of
    CONTROLS ||--o{ CONTROL_MAPPINGS : target_of
    CONTROLS ||--o{ EVIDENCE_LINKS : linked
    EVIDENCE ||--o{ EVIDENCE_LINKS : links_to
    ASSETS ||--o{ SCAN_RESULTS : scanned
    ASSESSMENTS ||--o{ ASSESSMENT_DECISIONS : contains
    CONTROLS ||--o{ ASSESSMENT_DECISIONS : assessed
    CONTROLS ||--o{ RISK_POINTS : inherits_risk
    RISK_POINTS ||--o{ REMEDIATION_TICKETS : spawns
    USERS ||--o{ REMEDIATION_TICKETS : assigned
    AUDIT_LOGS (append-only, hash-chained)
    SETTINGS (key/value)
```

### Data dictionary (key columns)

| Table | Notable columns | Cardinality |
|---|---|---|
| `frameworks` | code (ISO27001/BBICT2015/NISTCSF/OWASP2021), version, publisher, cadence | 4 seeded |
| `controls` | framework_id, code, title, category (canonical), intent, implementation_status, weight | 56 seeded |
| `control_mappings` | source_id→target_id, map_type (EQUIVALENT/RELATED/IMPLEMENTS), rationale | unique pair |
| `assets` | name, asset_type, environment, classification, criticality (1–5) | 8 seeded |
| `scan_results` | asset_id, scanner, finding_type, severity, cvss, status | seeded findings |
| `evidence` | title, artefact_type, file_path, sha256, chain_hash, worm_locked, retention_days | WORM row |
| `evidence_links` | evidence_id→control_id | many-to-many bridge |
| `assessments` | framework_code, method (AUTO/HYBRID/QUESTIONNAIRE), status, result_score, findings_count | history |
| `assessment_decisions` | assessment_id→control_id, status, evidence_ref, note, scored_by | unique per pair |
| `risk_points` | control_id, asset_id, likelihood (1–5), impact (1–5), cvss, raw_score, residual_score, tier, status | register |
| `remediation_tickets` | risk_id, priority, status, sla_hours, due_at, external_ticket, resolved_at | auto-escalated |
| `users` | username, email, password_hash (PBKDF2), role, mfa_enabled, is_active, last_login | 5 seeded |
| `audit_logs` | actor, action, entity, detail(JSON), ip, prev_hash, row_hash | append-only chain |

---

## 3. Canonical Control Object (CCO) — the mapping state

```
CCO = Control(id, framework.code, code, category, intent)
       + ControlMapping[] (EQUIVALENT/RELATED/IMPLEMENTS → target controls)
       + EvidenceLink[]   (evidence artefacts satisfying this control)
       + AssessmentDecision.status (latest per framework)
       + RiskPoint[]      (inherited risk state)
```

- **Category** is the canonical key the mapper uses for rule-based suggestions (`engines/mapper.py::auto_hint`).
- Seeded mappings: ISO27001 & OWASP2021 sources → BBICT2015/NISTCSF targets (non-symmetrical by design).

---

## 4. Platform Settings (key/value state)

| Key | Value (seeded) | Meaning |
|---|---|---|
| `platform.name` | Compliance Automation Suite v1.0.0 | display identity |
| `schema.version` | 1 | migration gate (reset DB on bump) |
| `seed_created_at` | ISO timestamp | provenance of demo data |

`Setting.updated_at` tracks last mutation — reserved for drift alerts.

---

## 5. State Machines

### 5.1 Assessment lifecycle
```
PLANNED ──► IN_PROGRESS ──► COMPLETED ──► REVIEWED
               ▲                  │
               └── re-run (new Assessment row, latest wins) ──┘
```
- Decision statuses: `COMPLIANT · PARTIAL · NON_COMPLIANT · NOT_ASSESSED · NOT_APPLICABLE`.
- `compliance_matrix` reads the *latest* COMPLETED/REVIEWED assessment per framework only.

### 5.2 Risk → ticket lifecycle
```
OPEN ──► MITIGATING / ACCEPTED ──► RESOLVED
  │  (tier CRITICAL/HIGH + OPEN)
  └──► RemediationTicket(OPEN) ──► IN_PROGRESS ──► IN_REVIEW ──► RESOLVED
```

### 5.3 Evidence lifecycle
```
UPLOADED (sha256 verified)
  └─► WORM_LOCKED (immutable)
       └─► LINKED to controls (EvidenceLink)
            └─► RETENTION window (365d default) → purge by policy
```
No update/delete endpoints exist for locked evidence (WORM discipline).

---

## 6. Scoring State (risk engine `engines/risk.py`)

| Metric | Formula | Bounds |
|---|---|---|
| Tier | `likelihood × impact` ≥20 CRITICAL, ≥12 HIGH, ≥6 MEDIUM, else LOW | 1–25 |
| CVSS tier | 0–3.9 LOW, 4–6.9 MEDIUM, 7–8.9 HIGH, ≥9 CRITICAL | 0–10 |
| Raw score | `(L×I/25)*0.6 + (CVSS/10)*0.4` | 0–1 |
| Residual score | `raw * 0.8` (simulated mitigation overlay) | ≤ raw |
| SLA default | CRITICAL 24h · HIGH 72h · MEDIUM 168h | hours |

Seeded open risks carry pre-computed raw/residual so the register is meaningful immediately.

---

## 7. Current Runtime State (reference snapshot)

| Metric | value at seed |
|---|---|
| Frameworks active | 4 |
| Canonical controls | 56 |
| Cross-framework mappings | 57 (ISO/OWASP → BB/NIST) |
| Evidence artefacts | 6 (all WORM-locked) |
| Overlap savings (de-dup) | 16 |
| Open risks | 5 (1 mitigated, 1 accepted) |
| Tickets auto-created | 3 (CRITICAL/HIGH) |
| Summary compliance after demo assessment | ~81% |

---

## 8. Reset / Migration

```powershell
# Recreate schema + seed from scratch
python -m app.seed            # app/seed.py, force=False (no-op if seeded)
python -c "from app.seed import seed; seed(force=True)"
```

- Bump `schema.version` and rerun `seed(force=True)` to migrate demo data.
- Production path: SQLAlchemy `Base.metadata` + Alembic migrations.

> **Doc status:** Reserved & living — regenerate after any model/engine change so the two always agree.