"""Tests: scheduled re-scan + baseline diffing + ITSM ticket exports."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from app.analysis import rescan
from app.core import rate_limit
from app.graph.store import STORE
from app.main import app


@pytest.fixture()
def client(tmp_path, monkeypatch):
    from app.graph import lab_seed
    from app.analysis import tiers
    monkeypatch.setenv("SG_DATA_DIR", str(tmp_path))  # isolate baseline files
    rate_limit.clear()
    STORE.clear()
    lab_seed.seed_lab_domain()
    tiers.classify_tiers(STORE)
    with TestClient(app, raise_server_exceptions=False) as c:
        yield c
    rate_limit.clear()
    rescan.reset_baseline()


@pytest.fixture()
def auth(client):
    res = client.post("/api/v1/auth/login",
                      json={"username": "analyst",
                            "password": "Analyst!Lab2024"})
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


@pytest.fixture()
def admin_auth(client):
    res = client.post("/api/v1/auth/login",
                      json={"username": "admin",
                            "password": "ChangeMe!Lab2024"})
    return {"Authorization": f"Bearer {res.json()['access_token']}"}


# ---------------------------------------------------------------- rescan ----
def test_first_scan_reports_all_new(client, auth):
    data = client.post("/api/v1/analysis/rescan/run", headers=auth).json()
    assert data["counts"]["new"] == data["counts"]["total"]
    assert data["counts"]["new"] >= 15
    assert data["counts"]["resolved"] == 0


def test_unchanged_rescan_reports_no_new(client, auth):
    client.post("/api/v1/analysis/rescan/run", headers=auth)
    again = client.post("/api/v1/analysis/rescan/run", headers=auth).json()
    assert again["counts"]["new"] == 0
    assert again["counts"]["resolved"] == 0
    assert again["counts"]["changed"] == 0
    assert again["counts"]["unchanged"] == again["counts"]["total"]


def test_diff_detects_changed_after_graph_change(client, auth):
    client.post("/api/v1/analysis/rescan/run", headers=auth)
    # F-DCSYNC-001 already exists (banking_app); a new DCSync grant must
    # surface as a CHANGE with a larger affected list, not as "new".
    from app.graph.model import Edge
    STORE.add_edge(Edge("user:jdoe", "domain:CORP.LAB", "dcsync"))
    second = client.post("/api/v1/analysis/rescan/run", headers=auth).json()
    assert second["counts"]["changed"] >= 1
    ch = next(c for c in second["changed"]
              if c["finding_id"] == "F-DCSYNC-001")
    assert ch["new_affected"] > ch["old_affected"]


def test_diff_snapshots_new_resolved_changed():
    """Unit: the diff primitive itself (new / resolved / fingerprint change)."""
    old = {
        "F-A": {"id": "F-A", "title": "A", "severity": "high",
                "category": "c", "mitre": [], "affected_ids": ["x"],
                "affected_count": 1, "fingerprint": "aaa"},
        "F-B": {"id": "F-B", "title": "B", "severity": "low",
                "category": "c", "mitre": [], "affected_ids": ["y"],
                "affected_count": 1, "fingerprint": "bbb"},
        "F-C": {"id": "F-C", "title": "C", "severity": "medium",
                "category": "c", "mitre": [], "affected_ids": ["z"],
                "affected_count": 1, "fingerprint": "ccc"},
    }
    new = {
        "F-A": {**old["F-A"]},                              # unchanged
        "F-C": {**old["F-C"], "affected_ids": ["z", "w"],
                "affected_count": 2, "fingerprint": "ccd"},  # changed
        "F-D": {"id": "F-D", "title": "D", "severity": "critical",
                 "category": "c", "mitre": [], "affected_ids": ["q"],
                 "affected_count": 1, "fingerprint": "ddd"},   # new
    }
    d = rescan.diff_snapshots(old, new)
    assert [f["id"] for f in d["new"]] == ["F-D"]
    assert [f["id"] for f in d["resolved"]] == ["F-B"]
    assert [c["finding_id"] for c in d["changed"]] == ["F-C"]
    assert d["counts"] == {"new": 1, "resolved": 1, "changed": 1,
                           "unchanged": 1, "total": 3}
    assert d["critical_new"] == 1


def test_baseline_persists_across_isolated_scans(client, auth, tmp_path):
    client.post("/api/v1/analysis/rescan/run", headers=auth)
    path = rescan._baseline_path()
    assert path.is_file()
    payload = json.loads(path.read_text(encoding="utf-8"))
    assert payload["version"] == 1
    assert "F-ESC1-001" in payload["findings"]
    assert len(payload["history"]) == 1


def test_status_and_history(client, auth):
    client.post("/api/v1/analysis/rescan/run", headers=auth)
    st = client.get("/api/v1/analysis/rescan/status", headers=auth).json()
    assert st["baseline_findings"] >= 15
    assert len(st["history"]) == 1
    assert st["history"][0]["trigger"] == "manual"


def test_rescan_requires_write_role(client):
    res = client.post("/api/v1/auth/login",
                      json={"username": "auditor",
                            "password": "Auditor!Lab2024"})
    h = {"Authorization": f"Bearer {res.json()['access_token']}"}
    assert client.post("/api/v1/analysis/rescan/run", headers=h).status_code \
        == 403


def test_interval_change_admin_only(client, auth, admin_auth):
    assert client.post("/api/v1/analysis/rescan/interval",
                       json={"minutes": 0}, headers=auth).status_code == 403
    res = client.post("/api/v1/analysis/rescan/interval",
                      json={"minutes": 0}, headers=admin_auth)
    assert res.status_code == 200
    assert res.json()["enabled"] is False


# --------------------------------------------------------------- tickets ----
def test_jira_csv_shape(client, auth):
    res = client.get("/api/v1/reports/tickets/jira?format=csv", headers=auth)
    assert res.status_code == 200
    lines = res.content.decode("utf-8-sig").splitlines()
    assert lines[0] == ("Summary,Description,Issue Type,Priority,Labels,"
                        "External ID")
    assert "F-DCSYNC-001" in res.content.decode("utf-8-sig")
    assert ",Highest," in res.content.decode("utf-8-sig")  # critical mapping


def test_servicenow_csv_shape(client, auth):
    res = client.get("/api/v1/reports/tickets/servicenow?format=csv",
                     headers=auth)
    body = res.content.decode("utf-8-sig")
    assert body.splitlines()[0].startswith(
        "Short description,Description,Priority,Impact,Urgency")
    assert "1 - Critical" in body


def test_tickets_sev_filter(client, auth):
    res = client.get("/api/v1/reports/tickets/jira?sev_min=critical",
                     headers=auth)
    body = res.content.decode("utf-8-sig")
    assert "F-DCSYNC-001" in body       # critical present
    assert "F-RDP-001" not in body      # medium filtered out


def test_tickets_bad_system_422(client, auth):
    res = client.get("/api/v1/reports/tickets/rocket?format=csv", headers=auth)
    assert res.status_code == 422
