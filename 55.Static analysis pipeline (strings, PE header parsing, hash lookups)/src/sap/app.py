"""SAPController — the application shell that wires policy, engines, intel,
aggregation, persistence and reporting into one deterministic scan.

This is the single code path behind both the CLI and the GUI (architecture.md
§6 controller). Fail-closed invariants:
- spec + bundle hash verified before any scan
- PolicyViolation on size/egress/integrity breaches
- engine failures are isolated (status=error), never swallowed silently
"""
from __future__ import annotations

import mmap
import os
import threading
import uuid
from dataclasses import dataclass
from pathlib import Path

from sap import __version__
from sap.data import reporting
from sap.data.sandbox import (
    CUSTODY_ANALYSIS_STARTED,
    CUSTODY_ARTIFACTS_PRODUCED,
    CUSTODY_SAMPLE_SEALED,
    CaseDir,
)
from sap.data.store import CaseStore, utc_now
from sap.engines.hashing import compute_all
from sap.engines.pe_engine import parse_pe
from sap.engines.strings_engine import extract_strings
from sap.intel.lookup import LookupService
from sap.orchestration.aggregator import build_triage_card
from sap.orchestration.scheduler import run_parallel
from sap.orchestration.spec import resolve_spec, verify_spec
from sap.rules import heuristics
from sap.rules.bundle import BUNDLE, verify_bundle
from sap.security import integrity as integrity_svc
from sap.security.audit import (
    ACTION_CARD_GENERATED,
    ACTION_INTEL_DONE,
    ACTION_PE_DONE,
    ACTION_SAMPLE_SEALED,
    ACTION_STRINGS_DONE,
    ACTION_VERIFY_OK,
    AuditLedger,
    AuditTamperedError,
)
from sap.security.policy import (
    DEFAULT_MAX_SAMPLE_BYTES,
    EgressGate,
    PolicyViolation,
    gate_sample_size,
    open_evidence,
)


def bundle_root() -> Path:
    """Frozen-bundle root (_MEIPASS) or the source tree for dev runs."""
    import sys
    meipass = getattr(sys, "_MEIPASS", None)
    if meipass:
        return Path(meipass)
    return Path(__file__).resolve().parents[2]


@dataclass
class ScanConfig:
    analyst: str = "analyst"
    egress_enabled: bool = False
    max_bytes: int = DEFAULT_MAX_SAMPLE_BYTES
    write_reports: bool = True


def _unwrap(results: dict, name: str) -> dict:
    """Flatten a scheduler-wrapped engine result into the engine's own dict."""
    row = results.get(name, {"status": "missing"})
    if row.get("status") == "ok":
        return row.get("result", row)
    if row.get("status") == "error":
        return {"status": "error", "error": row.get("error", "unknown")}
    return {"status": row.get("status", "unknown"), "error": row.get("error")}


class SAPController:
    """Application controller for one case sandbox."""

    def __init__(self, case_dir: str | Path, config: ScanConfig | None = None):
        self.config = config or ScanConfig()
        self.case = CaseDir(case_dir, genesis_actor=self.config.analyst)
        self.spec = resolve_spec()
        self.egress = EgressGate(allowed=self.config.egress_enabled)
        self.store = CaseStore(case_dir)
        self._mismatches = integrity_svc.self_integrity_check(bundle_root())
        if self._mismatches:
            raise PolicyViolation(
                f"self-integrity check failed: {self._mismatches} (fail closed, P9)")

    # ------------------------------------------------------------------ scan
    def scan_sample(self, path: str | Path,
                    cancel_event: threading.Event | None = None) -> dict:
        """Run the full static pipeline over one sample. Returns a triage card."""
        path = Path(path)
        if not path.is_file():
            raise PolicyViolation(f"sample not found: {path}")

        # ---- fail-closed preflight -------------------------------------------
        if not verify_spec(self.spec["spec_id"]):
            raise PolicyViolation("pipeline spec drift detected (spec_id mismatch)")
        if not verify_bundle(BUNDLE["sha256"]):
            raise PolicyViolation("rule bundle drift detected (bundle_sha mismatch)")

        size = path.stat().st_size
        gate_sample_size(size, self.config.max_bytes)
        fd = open_evidence(path)
        try:
            head = os.read(fd, 2)
        finally:
            os.close(fd)

        analyst = self.config.analyst
        started = utc_now()

        # ---- seal (hashes + custody) ------------------------------------------
        digests = compute_all(path)
        digests["size_bytes"] = size
        digests["mz"] = (head == b"MZ")

        self.case.audit.log(analyst, ACTION_SAMPLE_SEALED, {
            "sha256": digests["sha256"], "sha1": digests["sha1"],
            "md5": digests["md5"], "size_bytes": size,
            "original_name": path.name, "mz": digests["mz"],
        })
        self.case.custody_log(analyst, CUSTODY_SAMPLE_SEALED,
                              {"sha256": digests["sha256"]})
        plan_id = self.case.save_plan(self.spec)
        self.case.custody_log(analyst, CUSTODY_ANALYSIS_STARTED,
                              {"plan_id": plan_id, "sample": path.name})

        # ---- engines (bounded parallel) -------------------------------------
        def _strings_task() -> dict:
            with open(path, "rb") as fh:
                view = mmap.mmap(fh.fileno(), 0, access=mmap.ACCESS_READ)
                try:
                    res = extract_strings(view)
                finally:
                    view.close()
            return {"result": res.to_dict()}

        def _pe_task() -> dict:
            return {"result": parse_pe(path, size).to_dict()}

        def _intel_task() -> dict:
            svc = LookupService(
                sandbox_root=self.case.root,
                bloom=self.case.get_bloom(),
                ledger=self.case.audit,
                egress=self.egress,
                actor=analyst,
            )
            return {"result": svc.consult(digests).to_dict()}

        results = run_parallel(
            {"strings": _strings_task, "pe": _pe_task, "intel": _intel_task},
            cancel_event=cancel_event)

        strings = _unwrap(results, "strings")
        pe = _unwrap(results, "pe")
        intel = _unwrap(results, "intel")
        intel.setdefault("highest_verdict", "unknown")

        # ---- stage audit events ----------------------------------------------
        self.case.audit.log(analyst, ACTION_STRINGS_DONE, {
            "status": strings.get("status"),
            "ascii": strings.get("ascii_count"), "utf16": strings.get("utf16_count"),
            "artifacts": (strings.get("artifact_counts") or {})})
        self.case.audit.log(analyst, ACTION_PE_DONE, {
            "status": pe.get("status"), "backend": pe.get("backend"),
            "bitness": pe.get("bitness"), "anomalies": len(pe.get("anomalies") or [])})
        self.case.audit.log(analyst, ACTION_INTEL_DONE, {
            "hits": len(intel.get("hits", [])),
            "egress_used": intel.get("egress_used", 0),
            "cached": intel.get("cached", False)})

        # ---- rules + card ---------------------------------------------------
        findings = heuristics.evaluate(strings, pe, intel.get("highest_verdict", "unknown"))
        finished = utc_now()
        card = build_triage_card(
            sample={"original_name": path.name, "size_bytes": size, "mz": digests["mz"]},
            digests=digests, strings=strings, pe=pe, intel=intel,
            findings=findings, spec=self.spec, bundle_sha=BUNDLE["sha256"],
            ledger_head=self.case.audit.head or "", ledger_events=self.case.audit.count,
            started_utc=started, finished_utc=finished)

        self.case.audit.log(analyst, ACTION_CARD_GENERATED, {
            "card_id": card["card_id"], "sha256": digests["sha256"],
            "risk_score": card["risk"]["score"], "band": card["risk"]["band"],
            "findings": len(findings)})
        card["audit"]["ledger_head"] = self.case.audit.head
        card["audit"]["ledger_events"] = self.case.audit.count

        # ---- persist ----------------------------------------------------------
        sample_id = self.store.upsert_digest(digests, path.name)
        scan_id = self.store.insert_scan(card, sample_id)
        for f in card["findings"]:
            self.store.insert_finding(scan_id, f)
        for a in card.get("strings_summary", {}).get("artifacts", []):
            self.store.insert_artifact(scan_id, a.get("kind", ""),
                                       a.get("value"), a.get("offset", 0),
                                       a.get("entropy"))
        for h in intel.get("hits", []):
            self.store.insert_intel_hit(scan_id, digests["sha256"], h)
        self.store.commit()

        self.case.custody_log(analyst, CUSTODY_ARTIFACTS_PRODUCED, {
            "scan_id": scan_id, "findings": len(findings),
            "risk_score": card["risk"]["score"]})

        # ---- reports ------------------------------------------------------------
        if self.config.write_reports:
            paths = reporting.write_all(self.case.policy, card, scan_id)
            card["_reports"] = {k: str(v) for k, v in paths.items()}
        card["_scan_id"] = scan_id
        return card

    # ------------------------------------------------------------------ IOC
    def add_ioc(self, sha256_hex: str, verdict: str, reference: str = "") -> None:
        if verdict not in ("malicious", "suspicious", "benign"):
            raise PolicyViolation(f"invalid verdict: {verdict}")
        self.case.add_ioc(sha256_hex, verdict, reference, actor=self.config.analyst)

    # ------------------------------------------------------------------ verify / seal
    def verify(self, rehash_path: str | Path | None = None) -> dict:
        report = self.case.verify()
        report["self_integrity"] = {
            "ok": not self._mismatches, "mismatches": self._mismatches}
        report["spec"] = {"ok": verify_spec(self.spec["spec_id"]),
                          "spec_id": self.spec["spec_id"]}
        report["bundle"] = {"ok": verify_bundle(BUNDLE["sha256"]),
                            "sha256": BUNDLE["sha256"]}
        if rehash_path is not None:
            current = integrity_svc.sha256_file(rehash_path)
            stored = self.store.get_last_scan()
            report["rehash"] = {
                "ok": bool(stored and stored.get("sha256") == current),
                "current_sha256": current,
                "stored_sha256": stored.get("sha256") if stored else None,
            }
        report["ok"] = all([
            report["audit"]["ok"], report["custody"]["ok"],
            report["self_integrity"]["ok"], report["spec"]["ok"],
            report["bundle"]["ok"],
        ])
        if report["ok"]:
            self.case.audit.log(self.config.analyst, ACTION_VERIFY_OK, {
                "audit_head": report["audit"]["head"]})
        return report

    def seal(self, password: str | None = None) -> dict:
        seals = self.case.seal(self.config.analyst)
        package = self.case.export_package(self.config.analyst, password=password)
        return {"seals": seals, "package": str(package)}

    # ------------------------------------------------------------------ info / doctor
    @staticmethod
    def info() -> dict:
        spec = resolve_spec()
        return {
            "app": "SAP", "version": __version__,
            "spec": spec, "bundle": dict(BUNDLE),
            "backends": _backend_availability(),
            "sample_cap_bytes": DEFAULT_MAX_SAMPLE_BYTES,
            "egress_default": "deny (hashed-only, allowlisted, capped when enabled)",
            "max_workers": 4,
        }

    @staticmethod
    def doctor() -> dict:
        checks = {
            "python": {"ok": True},
            "spec": {"ok": verify_spec(resolve_spec()["spec_id"])},
            "bundle": {"ok": verify_bundle(BUNDLE["sha256"])},
            "self_integrity": {
                "ok": not integrity_svc.self_integrity_check(bundle_root()),
                "mismatches": integrity_svc.self_integrity_check(bundle_root())},
            "backends": _backend_availability(),
        }
        checks["ok"] = all(
            c.get("ok", True) for k, c in checks.items() if isinstance(c, dict))
        return checks


def _backend_availability() -> dict:
    def _has(mod: str) -> bool:
        try:
            __import__(mod)
            return True
        except Exception:
            return False
    return {
        "pefile": _has("pefile"),
        "lief": _has("lief"),
        "yara": _has("yara"),
        "cryptography": _has("cryptography"),
        "PySide6": _has("PySide6"),
    }