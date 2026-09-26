"""Tests: what-if remediation simulation + PDF/CSV GRC exports."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.graph.store import STORE
from app.core import rate_limit


@pytest.fixture()
def client():
    from app.graph import lab_seed
    from app.analysis import tiers
    rate_limit.clear()
    STORE.clear()
    lab_seed.seed_lab_domain()
    tiers.classify_tiers(STORE)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    rate_limit.clear()


@pytest.fixture()
def auth(client):
    res = client.post("/api/v1/auth/login",
                      json={"username": "analyst",
                            "password": "Analyst!Lab2024"})
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


# ---------------------------------------------------------------- what-if ---
def test_what_if_catalog(client, auth):
    data = client.get("/api/v1/analysis/what-if", headers=auth).json()
    assert "F-DCSYNC-001" in data["mitigations"]
    assert "F-ESC1-001" in data["mitigations"]


def test_what_if_single_fix_reduces_risk(client, auth):
    # Baseline (risk_raw is the uncapped score the simulator deltas on)
    base = client.get("/api/v1/findings", headers=auth).json()["summary"]
    # Simulate removing DCSync rights (critical finding)
    res = client.post("/api/v1/analysis/what-if",
                      json={"finding_ids": ["F-DCSYNC-001"]},
                      headers=auth)
    assert res.status_code == 200, res.text
    data = res.json()
    assert data["before"]["risk_index"] == base["risk_raw"]
    single = next(s for s in data["singles"]
                  if s["finding_id"] == "F-DCSYNC-001")
    assert single["delta"]["critical_removed"] >= 1
    assert single["after"]["risk_index"] < data["before"]["risk_index"]
    assert single["delta"]["edges_hidden"] >= 1


def test_what_if_flag_fix_kerberoast(client, auth):
    res = client.post("/api/v1/analysis/what-if",
                      json={"finding_ids": ["F-KRB-001"]}, headers=auth)
    data = res.json()
    single = next(s for s in data["singles"]
                  if s["finding_id"] == "F-KRB-001")
    assert single["delta"]["nodes_patched"] >= 1
    assert single["after"]["by_severity"]["high"] \
        < data["before"]["by_severity"]["high"]


def test_what_if_roadmap_cumulative(client, auth):
    res = client.post("/api/v1/analysis/what-if",
                      json={"finding_ids": ["F-DCSYNC-001", "F-ESC1-001",
                                            "F-DELEG-004"]},
                      headers=auth)
    data = res.json()
    assert len(data["roadmap_steps"]) == 3
    # Cumulative effect never worsens
    risks = [s["risk_index"] for s in data["roadmap_steps"]]
    assert risks[-1] <= risks[0]
    assert data["total_delta"]["risk_index"] <= 0


def test_what_if_unknown_id_422(client, auth):
    res = client.post("/api/v1/analysis/what-if",
                      json={"finding_ids": ["F-NOPE-999"]}, headers=auth)
    assert res.status_code == 422


def test_what_if_never_mutates_store(client, auth):
    before = STORE.stats()
    client.post("/api/v1/analysis/what-if",
                json={"finding_ids": ["F-DCSYNC-001", "F-KRB-001"]},
                headers=auth)
    assert STORE.stats() == before


# ---------------------------------------------------------------- reports ---
def test_findings_csv(client, auth):
    res = client.get("/api/v1/reports/findings?format=csv", headers=auth)
    assert res.status_code == 200
    assert res.headers["content-type"].startswith("text/csv")
    body = res.content.decode("utf-8-sig")
    assert body.splitlines()[0].startswith("finding_id")
    assert "F-DCSYNC-001" in body
    assert "F-ESC1-001" in body


def test_compliance_csv(client, auth):
    res = client.get("/api/v1/reports/compliance?format=csv", headers=auth)
    assert res.status_code == 200
    body = res.content.decode("utf-8-sig")
    assert "pci_dss_40" in body
    assert "iso27001_2022" in body


def test_findings_pdf(client, auth):
    res = client.get("/api/v1/reports/findings?format=pdf", headers=auth)
    assert res.status_code == 200
    assert res.headers["content-type"] == "application/pdf"
    assert res.content[:5] == b"%PDF-"
    assert len(res.content) > 2000  # real content, not a blank page


def test_compliance_pdf(client, auth):
    res = client.get("/api/v1/reports/compliance?format=pdf", headers=auth)
    assert res.status_code == 200
    assert res.content[:5] == b"%PDF-"


def test_reports_bad_format_422(client, auth):
    res = client.get("/api/v1/reports/findings?format=xls", headers=auth)
    assert res.status_code == 422


def test_reports_require_auth(client):
    assert client.get("/api/v1/reports/findings").status_code == 401
