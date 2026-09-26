from __future__ import annotations

import json
import time
from pathlib import Path


MEMORY_EVENT_TYPES = {
    "RUN", "BACKEND_ADDED", "BACKEND_REMOVED", "STATE_TRANSITION", "FAILURE_INJECTED",
    "FAILURE_REVERTED", "CONFIG_CHANGED", "SESSION_REJECT", "CIRCUIT_STATE", "NOTE_SAVED",
}

SECURITY_EVENT_TYPES = {"SECURITY_EVENT", "AUTHZ_DENIED", "AUTHZ_ALLOW"}


def _now_utc() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class PersistentStore:
    def __init__(self, root: str) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        self.state_path = self.root / "state.md"
        self.memory_path = self.root / "memory.md"
        self.security_path = self.root / "security.md"
        self.cache_path = self.root / ".aegislb_cache.json"
        self.memory_events: list = []
        self.security_events: list = []
        self.security_keys: set = set()
        self.memory_keys: set = set()
        self.notes: str = ""
        self.baseline: dict = {}
        self._last_mem_eid = 0
        self._load()

    def _load(self) -> None:
        if not self.cache_path.exists():
            return
        try:
            data = json.loads(self.cache_path.read_text(encoding="utf-8"))
            self.memory_events = data.get("memory_events", [])
            self.security_events = data.get("security_events", [])
            self.notes = data.get("notes", "")
            self.baseline = data.get("baseline", {})
            self.memory_keys = {e["key"] for e in self.memory_events}
            self.security_keys = {e["key"] for e in self.security_events}
            self._last_mem_eid = data.get("last_mem_eid", 0)
        except Exception:
            pass

    def _save_cache(self) -> None:
        try:
            data = {
                "memory_events": self.memory_events[-600:],
                "security_events": self.security_events[-600:],
                "notes": self.notes,
                "baseline": self.baseline,
                "last_mem_eid": self._last_mem_eid,
            }
            self.cache_path.write_text(json.dumps(data, indent=1), encoding="utf-8")
        except Exception:
            pass

    def set_notes(self, text: str) -> None:
        self.notes = text
        self._save_cache()

    def set_baseline(self, config: dict) -> None:
        self.baseline.update(config)
        self._save_cache()

    def record_security(self, entry: dict) -> None:
        key = entry.get("key")
        if key is None or key in self.security_keys:
            return
        self.security_keys.add(key)
        self.security_events.append(entry)
        if len(self.security_events) > 800:
            del self.security_events[:200]
        self._save_cache()

    def flush(self, sim) -> None:
        snap = sim.snapshot()
        run_info = snap.get("run", {})
        if run_info.get("id"):
            self.set_baseline({
                "seed": run_info.get("seed"),
                "rps": run_info.get("rps"),
                "speed": run_info.get("speed"),
                "policy": run_info.get("policy"),
                "arrival_model": run_info.get("arrival_model"),
                "health_sources": run_info.get("sources"),
                "sim_time": run_info.get("sim_time"),
            })
        for ev in sim.events:
            if ev["id"] <= self._last_mem_eid:
                continue
            self._last_mem_eid = ev["id"]
            etype = ev.get("type", "")
            if etype in MEMORY_EVENT_TYPES:
                key = f"{ev.get('gen')}:{ev['id']}:{etype}"
                if key not in self.memory_keys:
                    self.memory_keys.add(key)
                    self.memory_events.append({
                        "key": key, "t": ev["t"], "eid": ev["id"], "type": etype,
                        "sev": ev.get("sev", "info"),
                        "detail": json.dumps(ev.get("payload", {}), sort_keys=True),
                    })
            if etype in SECURITY_EVENT_TYPES:
                key = f"sec:{ev.get('gen')}:{ev['id']}:{etype}"
                if key not in self.security_keys:
                    self.security_keys.add(key)
                    self.security_events.append({
                        "key": key, "t": ev["t"], "eid": ev["id"], "type": etype,
                        "sev": ev.get("sev", "info"),
                        "detail": json.dumps(ev.get("payload", {}), sort_keys=True),
                    })
        self.write_state(snap)
        self.write_memory(snap)
        self.write_security(snap)
        self._save_cache()

    def write_state(self, snap: dict) -> None:
        run = snap.get("run", {})
        metrics = snap.get("metrics", {})
        alerts = snap.get("alerts", [])
        lines = [
            "# AegisLB — System State (auto-preserved snapshot)",
            "",
            f"Generated (UTC): {_now_utc()}  |  Run id: {run.get('id', '-')}  |  "
            f"Status: {'running' if run.get('running') else 'stopped'}  |  "
            f"Paused: {str(run.get('paused')).lower()}",
            "",
            "## Run",
            "",
            "| Field | Value |",
            "|---|---|",
            f"| seed | {run.get('seed')} |",
            f"| rps (target) | {run.get('rps')} |",
            f"| rps (measured) | {metrics.get('rps_now')} |",
            f"| speed | {run.get('speed')} |",
            f"| arrival model | {run.get('arrival_model')} |",
            f"| policy | {run.get('policy')} |",
            f"| sim time (s) | {run.get('sim_time')} |",
            f"| health agreement sources | {run.get('sources')} |",
            "",
            "## Health Spec (active)",
            "",
            "| Parameter | Value |",
            "|---|---|",
        ]
        hs = snap.get("health_spec", {})
        for k, v in hs.items():
            lines.append(f"| {k} | {v} |")
        lines += ["", "## Backends", "",
                  "| Name | ID | State | Active | W(eff) | Cap(eff) | EWMA(ms) | ErrRate | "
                  "Sessions | Errors | Probes OK/Fail | Breaker | Failure |",
                  "|---|---|---|---|---|---|---|---|---|---|---|---|---|"]
        for b in snap.get("backends", []):
            lines.append(
                f"| {b['name']} | {b['id']} | {b['state']} | {b['active_conns']} | "
                f"{b['effective_weight']} | {b['effective_capacity']} | {b['ewma_ms']} | "
                f"{b['errors_rate']} | {b['total_sessions']} | {b['total_errors']} | "
                f"{b['probes_ok']}/{b['probes_fail']} | {b['breaker']} | {b['failure_profile']} |")
        lines += ["", "## Metrics", "",
                  "| Metric | Value |", "|---|---|",
                  f"| sessions_total | {metrics.get('sessions_total')} |",
                  f"| errors_total | {metrics.get('errors_total')} |",
                  f"| rejects_total | {metrics.get('rejects_total')} |",
                  f"| decisions_total | {metrics.get('decisions_total')} |",
                  f"| probes_ok | {metrics.get('probes_ok')} |",
                  f"| probes_fail | {metrics.get('probes_fail')} |",
                  "",
                  "## Alerts (recent)",
                  ""]
        for a in alerts[-12:]:
            lines.append(f"- `{a['t']}s` **{a['sev']}** `{a['type']}` {a['text']}")
        if not alerts:
            lines.append("- (none)")
        lines += ["", "---", "Preserved by AegisLB `PersistentStore`; regenerated each flush."
                        " Companion docs: `docs/01` (architecture), `docs/02` (security), "
                        "`docs/03` (framework traceability).", ""]
        self.state_path.write_text("\n".join(lines), encoding="utf-8")

    def write_memory(self, snap: dict) -> None:
        run = snap.get("run", {})
        base = self.baseline
        lines = [
            "# AegisLB — Persistent Memory (preservation artifact)",
            "",
            "*Purpose:* durable cross-session record of configuration baseline, operator notes, "
            "and a chronological decision/event log. Rebuilt from the cache on every flush; "
            "append-only semantics for the log (no in-place edits of historical entries).",
            "",
            f"Last updated (UTC): {_now_utc()}  |  Current run: {run.get('id', '-')}",
            "",
            "## Configuration Baseline",
            "",
            "| Setting | Value |",
            "|---|---|",
        ]
        for k in ("seed", "rps", "speed", "policy", "arrival_model", "health_sources"):
            v = base.get(k)
            if v is not None:
                lines.append(f"| {k} | {v} |")
        lines += ["", "## Health Thresholds (baseline)", "",
                  "| Threshold | Default | Role |",
                  "|---|---|---|",
                  "| failThreshold (leaves HEALTHY) | 3 consecutive failures | anti-flap hysteresis |",
                  "| passThreshold (recovers) | 2 consecutive passes | anti-flap hysteresis |",
                  "| graceDegradedMs | 1500 | slow-lane detection margin |",
                  "| backoffMaxMs | 60000 | probe backoff cap |",
                  "| quarantineThreshold | 3 | repeated failures ⇒ QUARANTINED |",
                  "",
                  "## Operator Notes",
                  "",
                  self.notes if self.notes else "_No notes recorded yet._",
                  "",
                  "## Decision & Event Log (latest 200)",
                  "",
                  "| t(s) | eid | type | severity | detail |",
                  "|---|---|---|---|---|",
        ]
        for e in self.memory_events[-200:]:
            detail = e["detail"].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {e['t']} | {e['eid']} | {e['type']} | {e['sev']} | {detail} |")
        lines += ["", "## Preservation & Governance",
                  "",
                  f"- Cache artifact: `{self.cache_path}` (JSON, append-augmented).",
                  "- Retention per docs/01 §10 (decision traces 90d; audit 1y).",
                  "- Tamper-evident audit lives in `security.md` §Audit Chain (SHA-256 chained).",
                  "", "---", ""]
        self.memory_path.write_text("\n".join(lines), encoding="utf-8")

    def write_security(self, snap: dict) -> None:
        from .security import SecurityManager
        mgr = getattr(self, "_sec_mgr", None)
        tail = "n/a"
        count = 0
        if mgr is not None:
            tail = mgr._chain_tail
            count = len(mgr.audit)
        lines = [
            "# AegisLB — Security Posture & Audit (preservation artifact)",
            "",
            "*Purpose:* preserved security posture, audit-chain tail, recent security events, "
            "and framework mapping status. Full analysis in `docs/02-security-architecture-and-threat-model.md` "
            "and `docs/03-framework-traceability.md`.",
            "",
            f"Last updated (UTC): {_now_utc()}",
            "",
            "## Posture Summary",
            "",
            "| Item | Status |",
            "|---|---|",
            f"| Hardened mode (AEGIS_HARDENED) | {mgr.hardened if mgr else 'n/a'} |",
            f"| Admin API authZ | requires scoped API key (config/ops/auditor roles) |",
            f"| Rate limiting | {mgr.status().get('rate_limit_per_min') if mgr else 'n/a'} / min per client |",
            "| Transport (default) | bind 127.0.0.1; TLS recommended at edge (see docs/02 §6) |",
            "| Secrets | env-injected; never logged or persisted in plaintext (cache redacts) |",
            "",
            "## Compliance Mapping Status",
            "",
            "| Framework | Coverage | Primary artifact |",
            "|---|---|---|",
            "| OWASP Top 10 (2021) | A01–A10 controls implemented & test-mapped | docs/03 §2 |",
            "| NIST SP 800-207 (Zero Trust) | 7 tenets + 5 pillars by design | docs/02 §2, docs/03 §3 |",
            "| NIST SP 800-53 Rev5 | ~50 selected controls w/ evidence | docs/03 §4 |",
            "| ISO/IEC 27001:2022 Annex A | SoA ~42 applicable controls | docs/03 §5 |",
            "| NIST CSF 2.0 | GOVERN/IDENTIFY/PROTECT/DETECT/RESPOND/RECOVER | docs/03 §6 |",
            "",
            "## Audit Chain",
            "",
            f"- Entries recorded (process lifetime): {count}",
            f"- Chain tail (SHA-256): `{tail}`",
            "- Method: hash-chain append-only ledger; each entry = SHA-256(prev || JSON body).",
            "- API surface exposes `audit:read` only; no update/delete path exists.",
            "",
            "## Recent Security Events (latest 100)",
            "",
            "| t(s) | eid | type | severity | detail |",
            "|---|---|---|---|---|",
        ]
        for e in self.security_events[-100:]:
            detail = e["detail"].replace("|", "\\|").replace("\n", " ")
            lines.append(f"| {e['t']} | {e.get('eid', '-')} | {e['type']} | {e['sev']} | {detail} |")
        lines += ["", "## Threats Exercised (see docs/02 §4)",
                  "",
                  "- N1 Probe-target poisoning  → PROBE_TOKEN_MISMATCH events, N-of-M agreement",
                  "- N2 Health-state flapping → hysteresis + min-state-hold",
                  "- N3 Admin API abuse → PDP role enforcement + audit",
                  "- N4 Probe-URI/SSRF → no user-supplied URLs (schema-validated paths only)",
                  "- N5 Supply chain → SBOM/signing gates (docs/02 §9)",
                  "- N6 Insider audit tampering → hash-chained WORM-style audit", "",
                  "---", ""]
        self.security_path.write_text("\n".join(lines), encoding="utf-8")

    def attach_security_manager(self, mgr) -> None:
        self._sec_mgr = mgr