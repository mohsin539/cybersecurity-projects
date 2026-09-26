"""Graph, analysis, findings, compliance, and audit API routes.

Every route requires a bearer token; mutating routes require analyst/admin
roles (auditors are read-only) — enforced via FastAPI dependencies.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from fastapi.responses import Response
from pydantic import BaseModel, Field

from app.analysis import engine, tiers, whatif, rescan
from app.api.deps import rate_limit_api
from app.compliance import mapper as compliance_mapper
from app.core import audit
from app.core.config import settings
from app.core.security import require_role
from app.findings import rules as findings_engine
from app.graph import importer as sharp_importer
from app.graph import lab_seed
from app.graph.store import STORE
from app.reports import exporters, tickets

router = APIRouter(dependencies=[Depends(rate_limit_api)])


# ------------------------------------------------------------------ graph ---
@router.get("/graph")
def get_graph(user: dict = Depends(require_role("analyst", "admin",
                                                "auditor"))) -> dict:
    nodes = [n.to_dict(props=False) for n in STORE.nodes()]
    edges = [e.to_dict() for e in STORE.edges()]
    return {"nodes": nodes, "edges": edges, "stats": STORE.stats()}


@router.get("/graph/stats")
def graph_stats(user: dict = Depends(require_role("analyst", "admin",
                                                  "auditor"))) -> dict:
    return STORE.stats()


class SeedIn(BaseModel):
    reset: bool = Field(default=False, description="Clear graph first")


@router.post("/graph/seed")
def seed_domain(body: SeedIn,
                user: dict = Depends(require_role("analyst", "admin"))) -> dict:
    if body.reset:
        STORE.clear()
    lab_seed.seed_lab_domain()
    tiers.classify_tiers(STORE)
    audit.record("graph.seed", actor=user["username"], reset=body.reset)
    return STORE.stats()


class ImportResult(BaseModel):
    nodes: int
    edges: int
    skipped: int


@router.post("/graph/import")
async def import_collection(file: UploadFile = File(...),
                            user: dict = Depends(
                                require_role("analyst", "admin"))
                            ) -> dict:
    """Import a SharpHound ZIP / bloodhound-python JSON collection."""
    if not file.filename or not (
            file.filename.endswith(".zip")
            or file.filename.endswith(".json")):
        raise HTTPException(422, "Only .zip or .json collections accepted")
    data = await file.read()
    if len(data) > sharp_importer.MAX_FILE_BYTES:
        raise HTTPException(413, "Archive exceeds size limit")
    import tempfile, os  # local scope
    suffix = ".zip" if file.filename.endswith(".zip") else ".json"
    with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
        tmp.write(data)
        tmp_path = tmp.name
    try:
        if suffix == ".zip":
            counters = sharp_importer.import_sharphound_zip(tmp_path)
        else:
            import json
            try:
                payload = json.loads(data.decode("utf-8", "replace"))
            except json.JSONDecodeError:
                raise HTTPException(422, "Malformed JSON collection")
            counters = sharp_importer.import_sharphound_json(payload)
    finally:
        os.unlink(tmp_path)
    tiers.classify_tiers(STORE)
    return counters


# --------------------------------------------------------------- analysis ---
@router.get("/analysis/summary")
def analysis_summary(user: dict = Depends(require_role(
        "analyst", "admin", "auditor"))) -> dict:
    tiers.classify_tiers(STORE)
    return engine.domain_summary(STORE)


class PathRequest(BaseModel):
    source: str = Field(min_length=3, max_length=200)
    max_hops: int = Field(default=5, ge=1, le=8)
    limit: int = Field(default=10, ge=1, le=50)


@router.post("/analysis/paths")
def attack_paths(body: PathRequest,
                 user: dict = Depends(require_role("analyst", "admin",
                                                   "auditor"))) -> dict:
    if STORE.node(body.source) is None:
        raise HTTPException(404, f"Unknown node: {body.source}")
    tiers.classify_tiers(STORE)
    paths = engine.find_attack_paths(STORE, body.source, body.max_hops,
                                     body.limit)
    br = engine.blast_radius(STORE, body.source)
    return {"source": body.source, "paths": [p.to_dict() for p in paths],
            "blast_radius": br.to_dict()}


@router.get("/analysis/choke-points")
def choke_points(user: dict = Depends(require_role("analyst", "admin",
                                                   "auditor"))) -> dict:
    return {"choke_points": engine.choke_points(STORE)}


@router.get("/analysis/tier0-exposure")
def tier0_exposure(user: dict = Depends(require_role(
        "analyst", "admin", "auditor"))) -> dict:
    tiers.classify_tiers(STORE)
    return {"tier0": [n.to_dict(props=False) for n in tiers.tier0_nodes(STORE)],
            "exposure": engine.shortest_paths_to_tier0(STORE)}


# --------------------------------------------------------------- findings ---
@router.get("/findings")
def list_findings(user: dict = Depends(require_role(
        "analyst", "admin", "auditor"))) -> dict:
    findings = findings_engine.run_all_rules(STORE)
    return {"findings": [f.to_dict() for f in findings],
            "summary": findings_engine.findings_summary(findings)}


# ------------------------------------------------------------ compliance ---
@router.get("/compliance")
def compliance(framework: str | None = None,
               user: dict = Depends(require_role(
                   "analyst", "admin", "auditor"))) -> dict:
    frameworks = [framework] if framework else None
    return compliance_mapper.compliance_posture(STORE, frameworks)


@router.get("/compliance/frameworks")
def framework_list(user: dict = Depends(require_role(
        "analyst", "admin", "auditor"))) -> dict:
    return {
        "frameworks": [
            {"id": fid, "name": meta["name"],
             "description": meta["description"],
             "controls": len(meta["controls"])}
            for fid, meta in compliance_mapper.FRAMEWORKS.items()
        ]
    }


# --------------------------------------------------------------- what-if ---
class WhatIfRequest(BaseModel):
    finding_ids: list[str] = Field(min_length=1, max_length=25)


@router.get("/analysis/what-if")
def what_if_catalog(user: dict = Depends(require_role(
        "analyst", "admin", "auditor"))) -> dict:
    """Finding ids that support remediation simulation."""
    return {"mitigations": whatif.available_mitigations()}


@router.post("/analysis/what-if")
def what_if(body: WhatIfRequest,
            user: dict = Depends(require_role("analyst", "admin",
                                              "auditor"))) -> dict:
    """Simulate fixing findings (edge/prop filtering — store never mutated)."""
    unknown = [fid for fid in body.finding_ids
               if fid not in whatif.MITIGATIONS]
    if unknown:
        raise HTTPException(422, f"Unknown finding ids: {', '.join(unknown)}")
    tiers.classify_tiers(STORE)
    result = whatif.simulate_batch(STORE, body.finding_ids)
    audit.record("analysis.what_if", actor=user["username"],
                 findings=body.finding_ids)
    return result


# ---------------------------------------------------------------- reports ---
@router.get("/reports/findings")
def report_findings(format: str = "pdf",
                    user: dict = Depends(require_role(
                        "analyst", "admin", "auditor"))) -> Response:
    """GRC export: findings report (pdf|csv)."""
    fmt = format.lower()
    if fmt == "csv":
        data = exporters.findings_csv(STORE)
        media, name = "text/csv", "sentinelgraph-findings.csv"
    elif fmt == "pdf":
        data = exporters.findings_pdf(STORE)
        media, name = "application/pdf", "sentinelgraph-findings.pdf"
    else:
        raise HTTPException(422, "format must be pdf or csv")
    audit.record("report.export", actor=user["username"],
                 report="findings", format=fmt)
    return Response(
        content=data, media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.get("/reports/compliance")
def report_compliance(format: str = "pdf",
                      user: dict = Depends(require_role(
                          "analyst", "admin", "auditor"))) -> Response:
    """GRC export: compliance posture report (pdf|csv)."""
    fmt = format.lower()
    if fmt == "csv":
        data = exporters.compliance_csv(STORE)
        media, name = "text/csv", "sentinelgraph-compliance.csv"
    elif fmt == "pdf":
        data = exporters.compliance_pdf(STORE)
        media, name = "application/pdf", "sentinelgraph-compliance.pdf"
    else:
        raise HTTPException(422, "format must be pdf or csv")
    audit.record("report.export", actor=user["username"],
                 report="compliance", format=fmt)
    return Response(
        content=data, media_type=media,
        headers={"Content-Disposition": f'attachment; filename="{name}"'})


# ---------------------------------------------------------------- tickets ---
@router.get("/reports/tickets/{system}")
def report_tickets(system: str, format: str = "csv",
                   sev_min: str | None = None,
                   user: dict = Depends(require_role(
                       "analyst", "admin", "auditor"))) -> Response:
    """Per-finding ITSM ticket export: jira | servicenow."""
    sys_l = system.lower()
    if sys_l not in {"jira", "servicenow"}:
        raise HTTPException(422, "system must be jira or servicenow")
    if format.lower() != "csv":
        raise HTTPException(422, "only csv is supported for ticket exports")
    data = (tickets.tickets_jira_csv(STORE, sev_min=sev_min) if sys_l == "jira"
            else tickets.tickets_servicenow_csv(STORE, sev_min=sev_min))
    audit.record("report.export", actor=user["username"],
                 report=f"tickets-{sys_l}", format="csv")
    return Response(
        content=data, media_type="text/csv",
        headers={"Content-Disposition":
                 f'attachment; filename="sentinelgraph-tickets-{sys_l}.csv"'})


# ----------------------------------------------------------------- rescan ---
@router.post("/analysis/rescan/run")
def rescan_run(user: dict = Depends(require_role("analyst", "admin"))) -> dict:
    """Run a scan now and diff against the persisted baseline."""
    tiers.classify_tiers(STORE)
    result = rescan.run_scan_now(STORE, trigger="manual",
                                 actor=user["username"])
    return result


@router.get("/analysis/rescan/status")
def rescan_status(user: dict = Depends(require_role(
        "analyst", "admin", "auditor"))) -> dict:
    return rescan.status(settings.rescan_interval_minutes)


class RescanInterval(BaseModel):
    minutes: int = Field(ge=0, le=1440)


@router.post("/analysis/rescan/interval")
def rescan_interval(body: RescanInterval,
                    user: dict = Depends(require_role("admin"))) -> dict:
    """Update the scheduled re-scan interval (0 disables). Admin only."""
    settings.rescan_interval_minutes = body.minutes
    rescan.stop_scheduler()
    rescan.start_scheduler(body.minutes, STORE)
    audit.record("rescan.interval_changed", actor=user["username"],
                 minutes=body.minutes)
    return rescan.status(body.minutes)


@router.post("/analysis/rescan/reset")
def rescan_reset(user: dict = Depends(require_role("admin"))) -> dict:
    """Delete the persisted baseline (next scan reports everything as new)."""
    rescan.reset_baseline()
    return {"status": "baseline_cleared"}


# ------------------------------------------------------------------ audit ---
@router.get("/audit")
def audit_tail(limit: int = 100,
               user: dict = Depends(require_role("admin", "auditor"))) -> dict:
    limit = max(1, min(limit, 500))
    return {"events": audit.tail(limit)}


# --------------------------------------------------------------- metadata ---
@router.get("/meta")
def meta() -> dict:
    return {"app": settings.app_name, "version": settings.version,
            "environment": settings.environment}
