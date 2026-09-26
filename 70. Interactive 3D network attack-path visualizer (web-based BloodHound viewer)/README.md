# PathSphere 3D — Interactive Network Attack-Path Visualizer

Web-based BloodHound viewer implementing the architecture in `ARCHITECTURE.md`.

## Layout

```
apps/web                 React + Three.js (R3F) 3D SPA
services/*               Node-only microservices (zero deps, node:http)
  auth-service           OIDC-lite: login / jwks / validate (HS256 demo)
  graph-query-api        Persisted-query GraphQL allow-list + ABAC scope filter
  path-analysis          Yen's k-shortest paths over weighted graph edge types
  audit-ledger           Append-only hash-chained ledger + /verify tamper check
  ingestion-service      SharpHound-lite ingestion with idempotency keys
  report-engine          Ed25519-signed report artifacts + /verify
  policy-opa             OPA-style ABAC decision endpoint (Rego bundle included)
  notification-service   Channel dispatch stub
  risk-scoring           Node risk scoring stub
  mitre-mapper           Edge-type -> ATT&CK technique mapping stub
  delta-drift            Graph snapshot diff (added/removed/changed)
packages/*               Shared, buildable libraries
  shared-types           Canonical type model (GraphNode/Edge, Path, AuditEvent…)
  security-utils         sha256, auditHash, canonicalize, AES-GCM, path cache keys
  server-kit             Minimal JSON HTTP server + isMain entrypoint helper
  demo-data              Bundled deterministic demo tenant graph (18 nodes, 30 edges)
infra/helm|terraform|policies   Deployment + policy stubs
scripts/devsecops        CI/CD gate entrypoint
tests/                   node:test suites (chain integrity, path engine, signing)
```

## Quickstart

```powershell
npm install
npm test                  # compile packages + run 11 unit tests
npm run build:services    # compile every service to dist/

# Run any service (each exports /service health):
node services/auth-service/dist/main.js          # :8080
node services/graph-query-api/dist/main.js       # :8081
node services/path-analysis/dist/main.js         # :8082
node services/audit-ledger/dist/main.js          # :8083
node services/ingestion-service/dist/main.js     # :8084
node services/report-engine/dist/main.js         # :8085
node services/policy-opa/dist/main.js            # :8181

# Web SPA (proxy /api -> :8081):
npm run dev:web                                   # er4p[0-]
```

Demo walkthrough (PowerShell):

```powershell
# 1. Login
$t = (Invoke-RestMethod -Method Post -Uri http://localhost:8080/login `
  -Body '{"username":"analyst.demo","password":"ChangeMe!123"}' -ContentType application/json).access_token

# 2. Allowed persisted query
Invoke-RestMethod -Method Post -Uri http://localhost:8081/graphql -Headers @{Authorization="Bearer $t"} `
  -Body '{"operation":"GetSubgraph","variables":{"seed":"node-4004","maxDepth":2}}' -ContentType application/json

# 3. Admin-only operation => 403 for Analyst
# 4. Compute attack path ALICE -> DOMAIN ADMINS
Invoke-RestMethod -Method Post -Uri http://localhost:8082/compute-path `
  -Body '{"source":"node-4000","target":"node-2000","k":3}' -ContentType application/json

# 5. Seed + verify the audit chain
Invoke-RestMethod -Method Post -Uri http://localhost:8083/seed
Invoke-RestMethod -Uri http://localhost:8083/verify

# 6. Signed report + signature check
Invoke-RestMethod -Method Post -Uri http://localhost:8085/reports -Body '{"reportType":"attack-path"}' -ContentType application/json
```

## Security posture (from security.md)

- Persisted-query GraphQL allow-list; arbitrary client Cypher never accepted.
- ABAC enforced at decision endpoint (OPA/Rego bundle in `services/policy-opa/policies/`); role + tenant + sensitivity + OU scope all checked.
- Audit events hash-chained (`hash = sha256(prevHash ∥ canonical(event))`); `/verify` walks chain and flags tamper (ISO 27001 A.5.33, A.8.15; NIST AU-3/AU-6).
- Report artifacts signed with Ed25519; public key exported at `/public-key`; verify recomputes digest + signature.
- Ingestion idempotency via deterministic payload fingerprint (no double-apply).

`demo-only` defaults everywhere — replace env secrets (`AUTH_SIGNING_SECRET`, OPA bundle source, keys) before any real use.

## Verification status

- Packages compile (shadow-safe: `tsc -p packages/*`).
- 11 unit tests passing (`npm test`).
- Live smoke tested: login→token, GraphQL allow/deny, path compute (tier0 reached), audit chain seed+verify, report sign+verify, ingest idempotency.