import os

from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from pydantic import BaseModel

from app.config import REPORTS_DIR
from app.core import security as sec
from app.db import query_one
from app.services.reporting import build_bundle, list_reports

router = APIRouter(prefix="/api/reports", tags=["reports"])


class GenerateIn(BaseModel):
    formats: list = ["xlsx", "csv", "html"]
    scope: str = "all"


@router.get("/list")
def reports():
    return list_reports()


@router.post("/generate")
def generate(body: GenerateIn):
    res = build_bundle(body.formats, body.scope)
    sec.audit("REPORT", "generate", "D", f"formats={','.join(body.formats)} scope={body.scope}", "local")
    return res


@router.get("/download/{name}")
def download(name: str, token: str = ""):
    if "/" in name or "\\" in name or ".." in name:
        raise HTTPException(400, "invalid name")
    if token != sec.ensure_admin_token():
        raise HTTPException(401, "invalid token")
    row = query_one(
        "SELECT * FROM report_bundles WHERE file_name=? ORDER BY id DESC LIMIT 1",
        (name,),
    )
    if not row:
        raise HTTPException(404, "report not found")
    return FileResponse(row["path"], filename=row["file_name"])