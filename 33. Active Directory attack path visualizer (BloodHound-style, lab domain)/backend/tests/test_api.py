"""Pytest fixtures and tests for auth, graph, analysis, findings, compliance."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from app.main import app
from app.graph.store import STORE
from app.core import rate_limit


@pytest.fixture(autouse=True)
def _reset_rate_limiter():
    rate_limit.clear()
    yield
    rate_limit.clear()


@pytest.fixture()
def client():
    from app.graph import lab_seed
    from app.analysis import tiers
    STORE.clear()
    lab_seed.seed_lab_domain()
    tiers.classify_tiers(STORE)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c


@pytest.fixture()
def auth(client):
    res = client.post("/api/v1/auth/login",
                      json={"username": "analyst",
                            "password": "Analyst!Lab2024"})
    assert res.status_code == 200, res.text
    token = res.json()["access_token"]
    return {"Authorization": f"Bearer {token}"}


@pytest.fixture()
def admin_auth(client):
    res = client.post("/api/v1/auth/login",
                      json={"username": "admin",
                            "password": "ChangeMe!Lab2024"})
    assert res.status_code == 200
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


# ------------------------------------------------------------------ auth ----
def test_login_success_and_me(client):
    res = client.post("/api/v1/auth/login",
                      json={"username": "analyst",
                            "password": "Analyst!Lab2024"})
    assert res.status_code == 200
    me = client.get("/api/v1/auth/me",
                    headers={"Authorization":
                             f"Bearer {res.json()['access_token']}"})
    assert me.status_code == 200
    assert me.json()["role"] == "analyst"


def test_login_failure(client):
    res = client.post("/api/v1/auth/login",
                      json={"username": "analyst", "password": "wrong"})
    assert res.status_code == 401


def test_routes_require_auth(client):
    for path in ("/api/v1/graph", "/api/v1/findings", "/api/v1/compliance",
                 "/api/v1/analysis/summary"):
        assert client.get(path).status_code == 401, path


def test_auditor_readonly(client):
    res = client.post("/api/v1/auth/login",
                      json={"username": "auditor",
                            "password": "Auditor!Lab2024"})
    token = res.json()["access_token"]
    h = {"Authorization": f"Bearer {token}"}
    assert client.get("/api/v1/graph", headers=h).status_code == 200
    assert client.post("/api/v1/graph/seed",
                       json={"reset": False},
                       headers=h).status_code == 403


# ----------------------------------------------------------------- graph ----
def test_graph_present(client, auth):
    g = client.get("/api/v1/graph", headers=auth).json()
    assert g["stats"]["nodes_total"] > 10
    assert g["stats"]["edges_total"] > 10


def test_seed_reset(client, admin_auth):
    res = client.post("/api/v1/graph/seed",
                      json={"reset": True}, headers=admin_auth)
    assert res.status_code == 200
    assert res.json()["nodes_total"] > 10


# -------------------------------------------------------------- analysis ----
def test_attack_paths_from_helpdesk(client, auth):
    body = {"source": "user:helpdesk_bob", "max_hops": 5, "limit": 10}
    res = client.post("/api/v1/analysis/paths", json=body, headers=auth)
    assert res.status_code == 200
    data = res.json()
    assert data["blast_radius"]["reachable_tier0"] is True
    assert len(data["paths"]) >= 1
    assert data["paths"][0]["target_tier0"] is True


def test_tier0_exposure(client, auth):
    res = client.get("/api/v1/analysis/tier0-exposure", headers=auth)
    assert res.status_code == 200
    data = res.json()
    assert any(t["attacker_count"] > 0 for t in data["exposure"])


def test_choke_points(client, auth):
    res = client.get("/api/v1/analysis/choke-points", headers=auth)
    assert res.status_code == 200
    assert len(res.json()["choke_points"]) >= 1


# -------------------------------------------------------------- findings ----
def test_findings_detect_planted_issues(client, auth):
    data = client.get("/api/v1/findings", headers=auth).json()
    ids = {f["id"] for f in data["findings"]}
    for expected in ("F-KRB-001", "F-ASREP-001", "F-DCSYNC-001",
                     "F-DELEG-001", "F-GPP-001", "F-TIER-001",
                     "F-SESS-001",
                     # ADCS ESC coverage
                     "F-ESC1-001", "F-ESC2-001", "F-ESC4-001",
                     "F-ESC5-001", "F-ESC7-001", "F-ESC9-001",
                     # delegation coverage
                     "F-DELEG-002", "F-DELEG-003", "F-DELEG-004"):
        assert expected in ids, f"missing {expected}"
    assert data["summary"]["by_severity"]["critical"] >= 6
    assert "adcs" in data["summary"]["by_category"]


# ------------------------------------------------------------ compliance ----
def test_compliance_all_frameworks(client, auth):
    data = client.get("/api/v1/compliance", headers=auth).json()
    for fw in ("owasp_top10_2021", "iso27001_2022", "nist_csf_20",
               "nist_80053_r5", "pci_dss_40", "cis_controls_v8"):
        assert fw in data["frameworks"], fw
        assert 0 <= data["frameworks"][fw]["score"] <= 100


def test_audit_visibility(client, admin_auth):
    res = client.get("/api/v1/audit?limit=50", headers=admin_auth)
    assert res.status_code == 200
    events = res.json()["events"]
    assert any(e["event"] == "app.start" for e in events)
