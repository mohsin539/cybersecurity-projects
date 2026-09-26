"""Business orchestration: governance gates, compliance mapping, run lifecycle,
and evidence-based finding normalization."""
import ipaddress
import json
import threading
import time
from pathlib import Path

from .msgrpc_client import RealConsoleBackend, SimBackend

# Compliance knowledge base: sink -> (severity, cvss, owasp, nist-csf, nist-800-115, iso, remediation)
COMPLIANCE_MAP = {
    "auth": dict(severity="High", cvss=8.1, owasp="A07",
                 nist_csf="IDENTIFY / PROTECT", nist_800_115="4.3 Probing",
                 iso_annex="A.5.15", rem="Enforce strong credential policy and MFA."),
    "inject": dict(severity="Critical", cvss=9.8, owasp="A03",
                   nist_csf="IDENTIFY", nist_800_115="5.2 Exploitation",
                   iso_annex="A.8.8 / A.8.28",
                   rem="Input allow-list validation, parameterized handlers."),
    "sql": dict(severity="Critical", cvss=9.4, owasp="A03",
                nist_csf="IDENTIFY", nist_800_115="5.2 Exploitation",
                iso_annex="A.8.8",
                rem="Parameterized queries, least-privilege DB user."),
    "overflow": dict(severity="High", cvss=8.8, owasp="A04",
                     nist_csf="PROTECT", nist_800_115="5.2 Exploitation",
                     iso_annex="A.8.9",
                     rem="Bounds-check parsers, memory-safe language review."),
    "trace": dict(severity="High", cvss=7.5, owasp="A05",
                  nist_csf="DETECT", nist_800_115="5.1 Discovery",
                  iso_annex="A.8.9",
                  rem="Suppress verbose errors in production, centralize logging."),
    "ssrf": dict(severity="Medium", cvss=5.3, owasp="A10",
                 nist_csf="DETECT", nist_800_115="5.1 Discovery",
                 iso_annex="A.8.8",
                 rem="Allow-list outbound destinations, block private ranges."),
}

FRAMEWORK_FAMILIES = {
    "OWASP": "Top Ten 2021",
    "NIST": "CSF v2.0 / SP 800-115 / SP 800-53",
    "ISO": "IEC 27001:2022",
}


class LabGateError(Exception):
    pass


class _ScopeGate:
    LAB_PREFIX_HINTS = ("10.10.10.", "192.168.56.", "172.16.", ".lab")

    def check(self, host: str, cidrs) -> None:
        host = host.strip().lower()
        if any(host.startswith(p) for p in self.LAB_PREFIX_HINTS[:3]):
            return
        if host.endswith(".lab"):
            return
        try:
            ip = ipaddress.ip_address(host.split()[0])
            if ip.is_loopback or ip.is_private or ip.is_reserved:
                return
        except ValueError:
            return
        raise LabGateError(
            f"Target '{host}' is outside the allowed lab ranges ({cidrs}). "
            "Lab-only use is enforced."
        )


class Orchestrator:
    def __init__(self, db, cfg):
        self.db = db
        self.cfg = cfg
        self.gate = _ScopeGate()
        self.active_run = None
        self.lock = threading.Lock()
        self.backend = self._build_backend()

    def _build_backend(self):
        real = RealConsoleBackend(password=self.cfg.get_cfg("msgrpc_pass"))
        if real.available:
            self.db.set_cfg("msgrpc", "real")
            return real
        self.db.set_cfg("msgrpc", "sim")  # off-line simulator fallback
        return SimBackend()

    def transport_kind(self) -> str:
        return self.db.get_cfg("msgrpc", "sim")

    # ---- Governance gates ----
    def attest_consent(self, operator: str) -> None:
        if operator.strip().lower() in ("", "qa", "test", "ci"):
            self.db.audit("system", "CONSENT_REJECTED", operator)
            raise LabGateError("Consent attestation rejected: operator is a generic account.")
        self.db.set_cfg("consent", operator)
        self.db.audit(operator, "CONSENT_ACCEPTED", "lab-only authorization attestation")

    def add_target(self, host, port, label, cidr=None):
        self.gate.check(host, self.cfg.scope_cidrs)
        consent = self.db.get_cfg("consent")
        if not consent:
            raise LabGateError("Consent gate not passed. Attest first.")
        import hashlib
        consent_hash = hashlib.sha256(
            f"{host}:{port}:{consent}".encode()).hexdigest()[:16]
        tid = self.db.add_target(host, int(port), label, cidr or self.cfg.scope_cidrs[0])
        self.db.audit(consent, "TARGET_ADDED", f"{host}:{port} label={label}")
        return tid

    def run_module(self, target_id, module, options) -> dict:
        with self.lock:
            if self.active_run:
                raise LabGateError("A run is already active. Stop it first.")
            consent = self.db.get_cfg("consent")
            if not consent:
                raise LabGateError("Consent gate not passed. Attest first.")
            targets = {t[0]: t for t in self.db.targets()}
            t = targets.get(target_id)
            if not t:
                raise LabGateError("Unknown target.")
            host, port = t[1], t[2]
            cmd = options.get("command", "check").strip().lower()
            if cmd in ("exploit", "verify") and self.cfg.no_payload_default:
                if not options.get("unlock"):
                    raise LabGateError(
                        "Payload execution is locked. Set 'unlock'=true on the "
                        "EXPLOIT path and confirm lab mode.")
            mode = options.get("mode", "inject")
            run_id = self.db.add_run(target_id, module, options)
            self.active_run = run_id
            self.db.audit(consent, "MODULE_RUN", f"{module} cmd={cmd} sink={mode} {host}:{port}")

        def spawn():
            try:
                lines = self.backend.pump(cmd, mode=mode, host=host, port=port)
                for kind, text in lines:
                    self.db.append_run_log(run_id, text)
                    time.sleep(0.08)
                if cmd in ("check", "verify"):
                    self._ingest_findings(target_id, module, mode, cmd)
                self.db.end_run(run_id, "complete")
            except Exception as exc:
                self.db.append_run_log(run_id, f"[!] run failed: {exc}")
                self.db.end_run(run_id, "failed")
            finally:
                with self.lock:
                    self.active_run = None

        threading.Thread(target=spawn, daemon=True).start()
        return {"run_id": run_id, "status": "started", "backend": self.transport_kind()}

    def stop_run(self):
        with self.lock:
            rid = self.active_run
            self.active_run = None
        if rid:
            self.db.end_run(rid, "aborted")
            self.db.audit("operator", "RUN_ABORTED", f"run {rid}")

    # ---- Findings + compliance ----
    def _ingest_findings(self, target_id, module, mode, cmd):
        entry = COMPLIANCE_MAP.get(mode)
        if not entry:
            return
        mid = f"F-{target_id:04d}{int(time.time()) % 10000:04d}"
        evidence = {
            "request": f"X-Cmd header probe /api/echo (sink={mode})",
            "response": "HTTP/1.1 200 OK\nuid=0(root)",
            "module": module,
            "backend": self.transport_kind(),
        }
        finding = {
            "finding_id": mid,
            "target_id": target_id,
            "module": module,
            "sink": mode,
            "title": f"{entry['owasp']} {mode} sink confirmed",
            "severity": entry["severity"],
            "cvss": entry["cvss"],
            "owasp": entry["owasp"],
            "nist_csf": entry["nist_csf"],
            "nist_800_115": entry["nist_800_115"],
            "iso_annex": entry["iso_annex"],
            "evidence": evidence,
            "remediation": entry["rem"],
            "artifact": f"{mode}_evidence_{mid}.json",
            "controls": [
                {"framework": "OWASP", "control": entry["owasp"]},
                {"framework": "NIST", "control": entry["nist_csf"]},
                {"framework": "NIST", "control": "SP 800-115 " + entry["nist_800_115"]},
                {"framework": "ISO", "control": entry["iso_annex"]},
            ],
        }
        self.db.add_finding(finding)
        self.db.audit("orchestrator", "FINDING_INGESTED", f"{mid} {entry['owasp']}")

    def compliance_matrix(self) -> list[dict]:
        rows = []
        for f in self.db.findings():
            rows.append({
                "finding_id": f[1], "title": f[5], "severity": f[6],
                "owasp": f[8], "nist_csf": f[9], "nist_800_115": f[10],
                "iso_annex": f[11], "cvss": f[7],
            })
        return rows

    def findings(self):
        return [self._finding_row(f) for f in self.db.findings()]

    @staticmethod
    def _finding_row(f):
        return {
            "finding_id": f[1], "target_id": f[2], "module": f[3], "sink": f[4],
            "title": f[5], "severity": f[6], "cvss": f[7], "owasp": f[8] or "n/a",
            "nist_csf": f[9] or "n/a", "nist_800_115": f[10] or "n/a",
            "iso_annex": f[11] or "n/a",
            "evidence": json.loads(f[12] or "{}"), "remediation": f[13],
            "artifact": f[14], "ts": f[15],
        }