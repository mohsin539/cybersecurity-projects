import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from fastapi.testclient import TestClient

from app.main import app

client = TestClient(app)


def banner(text):
    print("\n" + "=" * 60)
    print(text)
    print("=" * 60)


def main():
    banner("HEALTH")
    r = client.get("/health")
    assert r.status_code == 200, r.text
    print(r.json())

    banner("LOGIN (admin)")
    r = client.post(
        "/api/v1/auth/token",
        json={"username": "admin", "password": "Admin@12345"},
    )
    assert r.status_code == 200, r.text
    token = r.json()["access_token"]
    print("ok, role:", r.json()["user"]["role"])
    h = {"Authorization": "Bearer " + token}

    banner("LOGIN RATE LIMIT - weak password")
    for _ in range(3):
        r = client.post(
            "/api/v1/auth/token",
            json={"username": "admin", "password": "wrong-pass-1"},
        )
        assert r.status_code == 401
    print("rejected 3 bad logins")

    banner("DASHBOARD")
    r = client.get("/api/v1/dashboard", headers=h)
    assert r.status_code == 200, r.text
    d = r.json()
    print(
        "employees=%d campaigns=%d sent=%d clicked=%d avg_SE=%s"
        % (
            d["total_employees"],
            d["total_campaigns"],
            d["total_sent"],
            d["total_clicked"],
            d["avg_se_index"],
        )
    )
    assert d["total_employees"] >= 12
    assert d["total_campaigns"] >= 1

    banner("CREATE CAMPAIGN")
    r = client.get("/api/v1/templates", headers=h)
    templates = r.json()
    r = client.get("/api/v1/landing-pages", headers=h)
    lands = r.json()
    r = client.post(
        "/api/v1/campaigns",
        headers=h,
        json={
            "name": "Smoke Test Campaign",
            "vector": "email",
            "templates": [templates[0]["id"]],
            "landing_pages": [lands[0]["id"]],
            "branches": ["Motijheel"],
            "divisions": [],
        },
    )
    assert r.status_code == 201, r.text
    camp = r.json()
    cid = camp["id"]
    print("created campaign", cid, camp["status"])

    banner("APPROVE (dual)")
    r = client.post("/api/v1/campaigns/%d/approve" % cid, headers=h)
    assert r.status_code == 200, r.text
    print("approve#1 ->", r.json()["status"])

    r2 = client.post(
        "/api/v1/auth/token",
        json={"username": "security", "password": "Security@12345"},
    )
    assert r2.status_code == 200, r2.text
    hsec = {"Authorization": "Bearer " + r2.json()["access_token"]}
    r = client.post("/api/v1/campaigns/%d/approve" % cid, headers=hsec)
    assert r.status_code == 200 and r.json()["status"] == "approved", r.text
    print("dual-approved ->", r.json()["status"])

    banner("LAUNCH")
    r = client.post("/api/v1/campaigns/%d/launch" % cid, headers=h)
    assert r.status_code == 200, r.text
    print("launched, status:", r.json()["status"])

    banner("DELIVERIES + TRACKING WALKTHROUGH")
    time.sleep(2)
    r = client.get("/api/v1/campaigns/%d/deliveries" % cid, headers=h)
    assert r.status_code == 200, r.text
    deliveries = [x for x in r.json() if x["status"] != "pending"]
    assert deliveries, "expected some sent deliveries"
    d0 = deliveries[0]
    print("sample delivery:", d0["employee_code"], d0["status"])

    r = client.get(d0["open_url"])
    assert r.status_code == 200 and r.headers["content-type"] == "image/png"
    r = client.get(d0["click_url"], follow_redirects=False)
    assert r.status_code in (302, 307), r.status_code
    landing = client.get(r.headers["location"])
    assert landing.status_code == 200
    print("open + click + landing ok")

    banner("SUBMIT + REPORT (masked/hashed)")
    token = d0["click_url"].split("/")[-1]
    r = client.post(
        "/t/s/" + token,
        data={"username": "rahim.uddin", "password": "Bank@2026!secret"},
        follow_redirects=False,
    )
    assert r.status_code == 303, (r.status_code, r.headers.get("location"))
    print("submit redirected:", r.headers["location"])
    r = client.get("/t/e/" + token)
    assert r.status_code == 200

    banner("REPORT EXPORTS")
    for fmt in ("xlsx", "csv", "html"):
        r = client.post("/api/v1/reports", headers=h, json={"fmt": fmt})
        assert r.status_code == 201, r.text
        rtoken = r.json()["url_token"]
        r = client.get("/api/v1/reports/%s/download" % rtoken, headers=h)
        assert r.status_code == 200, r.text
        print(fmt, "->", r.headers["content-type"], len(r.content), "bytes")

    banner("AUDIT CHAIN")
    r = client.get("/api/v1/audit?limit=20", headers=h)
    logs = r.json()
    assert logs, "expected audit entries"
    for entry in logs:
        assert entry["hash"]
    print(
        "audit entries:",
        len(logs),
        "latest:",
        logs[0]["action"],
        "hash:",
        logs[0]["hash"][:12] + "...",
    )

    banner("RISK / TRAINING")
    r = client.post(
        "/api/v1/training/enroll",
        headers=h,
        json={"employee_id": 1, "title": "Phishing101 - Spot the Lure", "score": 0},
    )
    assert r.status_code == 201, r.text
    r = client.post("/api/v1/training/auto-assign", headers=h)
    assert r.status_code == 200
    print("training ok:", r.json())

    print("\nSMOKE TEST PASSED")


if __name__ == "__main__":
    client.__enter__()
    try:
        main()
    finally:
        client.__exit__(None, None, None)