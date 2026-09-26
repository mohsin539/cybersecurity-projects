# AegisLB — Security-Hardened Load Balancer Simulator with Health Checks

**Documentation set for the AegisLB simulation platform.**

AegisLB is a high-fidelity, simulation-grade load balancer and health-checking
engine. It is architected to be *behaviorally realistic* (load-balancing
dynamics, health-state oscillation, draining, circuit breaking, slow start) and
*security-hardened by design*, with demonstrable alignment to:

- **OWASP Top 10 (2021)**
- **NIST SP 800-207** — Zero Trust Architecture
- **NIST SP 800-53 Rev. 5** — Security and Privacy Controls
- **ISO/IEC 27001:2022 Annex A** — Control Set
- **NIST CSF 2.0** — FUNCTIONS (Govern, Identify, Protect, Detect, Respond, Recover)

## Document Index

| Document | Purpose | Audience |
|---|---|---|
| [`docs/01-load-balancer-simulator-architecture.md`](docs/01-load-balancer-simulator-architecture.md) | Canonical system architecture: goals, NFRs, components, algorithms, health-check engine, data flows, interfaces, deployment topologies, observability, DevSecOps gates | Architects, engineers, reviewers |
| [`docs/02-security-architecture-and-threat-model.md`](docs/02-security-architecture-and-threat-model.md) | Security posture: Zero Trust design, STRIDE threat model per component, detailed attack narratives, encryption & key management, IAM, supply chain | Architects, security engineers, SOC, red team |
| [`docs/03-framework-traceability.md`](docs/03-framework-traceability.md) | Formal traceability matrices to OWASP Top 10, NIST 800-207, NIST 800-53 Rev5, ISO/IEC 27001:2022 Annex A, and NIST CSF 2.0, with evidence pointers | Auditors, compliance, reviewers |

## How to Navigate

1. Start with `docs/01-load-balancer-simulator-architecture.md` for the system design.
2. Read `docs/02-security-architecture-and-threat-model.md` for security design and threat model.
3. Use `docs/03-framework-traceability.md` as the compliance/evidence back-bone (traceability matrices with pointers back to docs 01 and 02).

## Quick Reference Card

- **Naming**: AegisLB ("aegis" — the shield).
- **Core subsystems**: `traffic-generator`, `lb-forwarding-engine`, `backend-simulator`, `health-check-controller`, `admin-api/control-plane`, `identity-ca`, `observability stack`.
- **Packaging**: Modular monolith (dev/single-node) and micro-segmented container deployment (lab/production-sim).
- **Primary security mechanism**: Zero Trust (mTLS workload identities, PDP-mediated authorization, network microsegmentation, continuous verification, ephemeral credentials).

## Running the Simulator (Web GUI)

The app is a Python/FastAPI implementation backed by the architecture in `docs/01`.
It serves a dashboard at `http://127.0.0.1:8000` and auto-binds to loopback only.

Quick start, in order of preference:

1. **Double-click `run.py`** — starts the web GUI + API server, auto-opens the
   dashboard in your browser, and keeps the window open so you can read the log
   (close the window or press Ctrl+C to stop).
2. **Double-click `AegisLB.bat`** — same thing, but uses the `py` launcher
   explicitly. Use this when the `.py` file association is broken or opens the
   Microsoft Store python stub.
3. **From a terminal:**
   ```bat
   py run.py serve                :: web GUI + API on http://127.0.0.1:8000
   py run.py serve --port 9000    :: different port (if 8000 is busy)
   py run.py headless --seconds 30 --out .   :: CLI run; writes state.md / memory.md / security.md here
   ```

### If double-clicking `run.py` does nothing

- **Missing/alternate `py` launcher (most common).** Windows may route `.py` files
  to the *Microsoft Store python alias*, which opens the Store instead of running
  anything. Fix once with:
  ```bat
  assoc .py=Python.File
  ftype Python.File="py.exe" "%L" %*
  ```
  (Run in an **Administrator** command prompt.) Then use `AegisLB.bat` as the
  reliable launcher regardless.
- **Port already in use.** Run `py run.py serve --port 9000`, or close the other
  application holding port 8000.

### API keys

Write endpoints require a scoped key via the `X-Aegis-Key` header
(roles: `config`, `ops`, `auditor`). Set them before launch with the env vars
`AEGIS_CONFIG_KEY`, `AEGIS_OPS_KEY`, `AEGIS_AUDITOR_KEY`, or use the generated
random ones (redacted on the Security panel). Without a key the read dashboard
still works; writes return `403`.

## Version

This documentation set is versioned. See Document Control in each artifact.

---
*AegisLB — "Never trust the simulation; verify everything."*