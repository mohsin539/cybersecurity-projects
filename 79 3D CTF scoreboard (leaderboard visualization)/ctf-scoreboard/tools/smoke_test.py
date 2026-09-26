"""End-to-end smoke test against a real uvicorn process."""

from __future__ import annotations

import hashlib
import hmac
import json
import os
import subprocess
import sys
import time
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

PORT = int(os.environ.get("SMOKE_PORT", "8099"))
BASE = f"http://127.0.0.1:{PORT}"
DB = ROOT / "smoke.db"
PASSWORD = "scoreboard-demo"

for suffix in ("", "-wal", "-shm"):
    target = Path(str(DB) + suffix)
    if target.exists():
        target.unlink()

env = {
    **os.environ,
    "SCOREBOARD_DB": str(DB),
    "SCOREBOARD_SEED": "1",
    "SCOREBOARD_SIMULATE": "0.4",
    "SCOREBOARD_SECRET_KEY": "smoke-test-secret-key-0123456789",
}
proc = subprocess.Popen(
    [sys.executable, "-m", "uvicorn", "app.main:app", "--port", str(PORT), "--log-level", "warning"],
    cwd=str(ROOT),
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
    text=True,
)

failures: list[str] = []


def check(label: str, condition: bool, detail: str = "") -> None:
    print(f"{'PASS' if condition else 'FAIL'}  {label}{(' — ' + detail) if detail else ''}")
    if not condition:
        failures.append(label)


def secret(client: httpx.Client) -> str:
    from app.config import Settings
    from app.database import init_db

    db = init_db(DB)
    with db.read() as conn:
        return conn.execute(
            "SELECT key_secret FROM webhook_clients WHERE client_id = 'platform-demo'"
        ).fetchone()["key_secret"]
    db.close()


def signed(client: httpx.Client, payload: dict, *, key: str, client_id: str = "platform-demo") -> httpx.Response:
    body = json.dumps(payload).encode()
    ts = str(int(time.time()))
    signature = hmac.new(key.encode(), body, hashlib.sha256).hexdigest()
    return client.post(
        "/api/webhooks/ctf",
        content=body,
        headers={
            "content-type": "application/json",
            "x-client-id": client_id,
            "x-timestamp": ts,
            "x-signature": signature,
        },
    )


try:
    with httpx.Client(base_url=BASE, timeout=30.0) as client:
        deadline = time.time() + 60
        while time.time() < deadline:
            try:
                if client.get("/api/health").status_code == 200:
                    break
            except httpx.HTTPError:
                time.sleep(0.5)
        else:
            raise SystemExit("server did not become healthy")

        health = client.get("/api/health").json()
        check("health reports ok", health.get("status") == "ok", json.dumps(health)[:160])

        board = client.get("/api/leaderboard").json()
        check("board has 24 teams and 12 challenges", len(board["teams"]) == 24 and len(board["challenges"]) == 12)
        check("ranks are 1..n with no gaps", [t["rank"] for t in board["teams"]] == list(range(1, 25)))
        check("scores are non-increasing", all(
            board["teams"][i]["score"] >= board["teams"][i + 1]["score"] for i in range(len(board["teams"]) - 1)
        ))
        check("board names its scoring model", str(board["scoring_model"]).startswith("scoring-v"),
              str(board["scoring_model"]))

        for path in ("/", "/static/css/theme.css", "/static/js/app.js", "/static/js/scene.js",
                     "/static/js/gl.js", "/favicon.svg"):
            response = client.get(path)
            check(f"static {path}", response.status_code == 200 and len(response.content) > 0,
                  f"{response.status_code} {len(response.content)}B")
        index_html = client.get("/").text
        check("index references only existing assets",
              all(asset in index_html for asset in ("/static/css/theme.css", "/static/js/app.js",
                                                    "/favicon.svg"))
              and "/js/app.js" not in index_html.replace("/static/js/app.js", ""))

        invariants = client.get("/api/invariants").json()
        check("invariants healthy on a live board", invariants["healthy"] is True,
              f"{len(invariants['invariants'])} checks")

        integrity = client.get("/api/integrity").json()
        check("event chain verifies", integrity["event_chain"]["ok"] is True)
        check("audit chain verifies", integrity["audit_chain"]["ok"] is True)

        csv_body = client.get("/api/leaderboard.csv")
        check("csv export", csv_body.status_code == 200 and csv_body.text.startswith("rank,team,slug"),
              f"{len(csv_body.text.splitlines())} lines")

        team = client.get(f"/api/teams/{board['teams'][0]['slug']}").json()
        check("team history", team["team"]["slug"] == board["teams"][0]["slug"] and len(team["solves"]) > 0,
              f"{len(team['solves'])} solves")

        # --- auth ------------------------------------------------------------
        bad = client.post("/api/auth/login", json={"handle": "admin", "password": "nope"})
        check("bad login is 401", bad.status_code == 401)
        denied = client.get("/api/audit?action=security.login").json()
        check("bad login is audited as denied",
              any(r["outcome"] == "denied" for r in denied["records"]),
              f"{denied['count']} records")

        login = client.post("/api/auth/login", json={"handle": "referee-1", "password": PASSWORD})
        check("referee can log in", login.status_code == 200 and login.json()["role"] == "referee")
        cookie = login.headers.get("set-cookie", "")
        check("session cookie is set", "scoreboard_session" in cookie, cookie.split(";")[0])
        me = client.get("/api/auth/me").json()
        check("me identifies the session", me["handle"] == "referee-1" and me["is_staff"] is True)

        forbidden = client.get("/api/admin/audit/export.csv")
        check("audit export needs step-up", forbidden.status_code == 403, str(forbidden.status_code))
        step = client.post("/api/auth/step-up", json={"password": PASSWORD})
        check("step-up succeeds with the right password", step.status_code == 200)
        allowed = client.get("/api/admin/audit/export.csv")
        check("audit export opens after step-up", allowed.status_code == 200 and "action" in allowed.text)

        # --- signed webhook --------------------------------------------------
        key = secret(client)
        solved = {s for t in board["teams"] for s in t["solved_slugs"]}
        team_slug, challenge_slug = next(
            (t["slug"], c["slug"])
            for t in board["teams"]
            for c in board["challenges"]
            if c["slug"] not in solved
        )
        accepted = signed(client, {"type": "solve.recorded", "id": "smoke-1", "team": team_slug,
                                   "challenge": challenge_slug}, key=key)
        check("signed webhook accepted", accepted.status_code == 202, accepted.text[:120])
        replay = signed(client, {"type": "solve.recorded", "id": "smoke-1", "team": team_slug,
                                 "challenge": challenge_slug}, key=key)
        check("redelivery is an idempotent replay",
              replay.status_code == 202 and replay.json().get("idempotent_replay") is True)
        forged = signed(client, {"type": "ping"}, key="whsec_wrong")
        check("forged signature rejected", forged.status_code == 401)

        # --- two-person rule -------------------------------------------------
        proposal = client.post("/api/admin/adjustments",
                               json={"team": team_slug, "delta": -25, "reason": "smoke test adjustment"})
        check("adjustment proposed", proposal.status_code == 200, proposal.text[:120])
        adjustment_id = proposal.json()["id"]
        self_approve = client.post(f"/api/admin/adjustments/{adjustment_id}/decision", json={"approve": True})
        check("proposer cannot approve", self_approve.status_code == 403
              and self_approve.json()["error"] == "separation_of_duties")
        client.post("/api/auth/logout")
        client.post("/api/auth/login", json={"handle": "referee-2", "password": PASSWORD})
        approved = client.post(f"/api/admin/adjustments/{adjustment_id}/decision", json={"approve": True})
        check("second referee approves", approved.status_code == 200 and approved.json()["status"] == "approved")

        # --- sse -------------------------------------------------------------
        frames: list[str] = []
        with client.stream("GET", "/api/stream", timeout=45.0) as stream:
            deadline = time.time() + 40
            for line in stream.iter_lines():
                if line.startswith("data:"):
                    frames.append(line[5:].strip())
                if len(frames) >= 2 or time.time() > deadline:
                    break
        check("sse delivers frames", len(frames) >= 1, f"{len(frames)} frames")
        if frames:
            first = json.loads(frames[0])
            check("first sse frame is a board or notice", first.get("type") in {"board", "notice", "resync", "snapshot"},
                  str(first.get("type")))  # a stream opens with a snapshot

        final = client.get("/api/invariants").json()
        check("invariants still healthy after traffic", final["healthy"] is True)
        integrity = client.get("/api/integrity").json()
        check("chains still verify after traffic", integrity["event_chain"]["ok"] is True
              and integrity["audit_chain"]["ok"] is True)
finally:
    proc.terminate()
    try:
        out, _ = proc.communicate(timeout=15)
    except subprocess.TimeoutExpired:
        proc.kill()
        out, _ = proc.communicate()
    if out and out.strip():
        tail = "\n".join(out.strip().splitlines()[-25:])
        print("\n--- server output ---\n" + tail)
    # The server may still be releasing the file; the database is a throwaway.
    for suffix in ("", "-wal", "-shm"):
        target = Path(str(DB) + suffix)
        for _ in range(20):
            try:
                target.unlink()
                break
            except FileNotFoundError:
                break
            except PermissionError:
                time.sleep(0.25)

print()
if failures:
    print(f"{len(failures)} FAILED: {failures}")
    raise SystemExit(1)
print("smoke test passed")
