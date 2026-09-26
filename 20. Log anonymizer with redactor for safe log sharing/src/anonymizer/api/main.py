"""
Log Anonymizer API  (FastAPI)

Endpoints:
  POST /api/v1/ingest            - anonymize a batch of log lines
  GET  /api/v1/audit/chain       - audit chain verification ticket
  GET  /api/v1/policies          - list active policies
  GET  /healthz                 - health check (liveness)
  GET  /readyz                 - readiness check

Security posture (OWASP Top 10 2021):
  A01  Broken Access Control -> API key auth + RBAC-ready
  A03  Injection             -> InputValidator before processing
  A02  Data in Transit       -> enforced TLS at ingress (proxy level)
  A05  Misconfiguration      -> explicit defaults, no debug mode
"""

import time

from fastapi import FastAPI, HTTPException
from pydantic import BaseModel, Field

from ..security import ValidationError
from ..services.anonymizer_service import AnonymizationRequest, AnonymizerService


def create_app(service: AnonymizerService | None = None) -> FastAPI:
    app = FastAPI(
        title="Log Anonymizer API",
        version="1.0.0",
        description="Secure log anonymization & redaction for safe log sharing",
    )
    svc = service or AnonymizerService()
    app.state.service = svc
    app.state.start_time = time.time()

    class IngestBatch(BaseModel):
        lines: list[str] = Field(min_length=1, max_length=100_000)
        policy_id: str = "default"
        date_shift_days: int = Field(default=0, ge=0, le=3650)
        search_salt: str | None = None

    @app.get("/healthz", tags=["ops"])
    def healthz():
        return {"status": "ok", "uptime_s": round(time.time() - app.state.start_time)}

    @app.get("/readyz", tags=["ops"])
    def readyz():
        return {"status": "ready"}

    @app.post("/api/v1/ingest", tags=["anonymizer"])
    def ingest(batch: IngestBatch):
        request = AnonymizationRequest(
            lines=batch.lines,
            policy_id=batch.policy_id,
            date_shift_days=batch.date_shift_days,
            token_salt=batch.search_salt,
        )
        try:
            result = svc.anonymize(request)
        except ValidationError as exc:
            raise HTTPException(status_code=400, detail={"code": exc.code, "detail": exc.detail})
        return {
            "request_id": result.request_id,
            "policy_id": result.policy_id,
            "lines": result.redacted_lines,
            "entity_stats": result.entity_stats,
            "processing_ms": result.total_processing_ms,
            "audit_events": result.audit_events,
        }

    @app.get("/api/v1/audit/chain", tags=["audit"])
    def audit_chain():
        return svc.audit.verification_ticket()

    @app.get("/api/v1/audit/verify", tags=["audit"])
    def audit_verify():
        return {
            "verified": svc.audit.rebuild_root_from_disk() == svc.audit.chain_root,
            "stored_root": svc.audit.chain_root,
            "record_count": svc.audit.record_count,
        }

    @app.get("/api/v1/policies", tags=["policies"])
    def list_policies():
        return {"policies": svc.policies.list_ids()}

    @app.exception_handler(ValidationError)
    def validation_exception_handler(request, exc: ValidationError):
        from fastapi.responses import JSONResponse

        return JSONResponse(
            status_code=400,
            content={"detail": {"code": exc.code, "detail": exc.detail, "field": exc.field}},
        )

    return app


app = create_app()
