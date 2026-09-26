from __future__ import annotations

"""Scan orchestration. Distributing jobs to a ThreadPoolExecutor and watching
jobs table state; persists results into the graph/inventory stores + audit
chain. Runs as FastAPI dependency-scoped background job.
"""

import json
import sqlite3
import threading
import time
import uuid

from . import db
from .audit import AUDIT
from .util import now_ts

LOCK = threading.Lock()
JOBS: dict[str, dict] = {}

MAX_PATH = 16  # traceroute max hops (scoped algorithm)


def launch_sim_scan(scope: str, agent: str = "sim",
                    budget_items: int = 6000) -> str:
    job_id = "sim-" + uuid.uuid4().hex[:8]
    JOBS[job_id] = {
        "id": job_id, "mode": "sim", "scope": scope, "state": "running",
        "progress": 0, "started_at": now_ts(), "message": "simulating evidence",
        "created_count": 0,
    }
    db.upsert_job(JOBS[job_id])
    _spawn(make_sim_job(job_id, agent, scope, budget_items))
    return job_id


def make_sim_job(job_id, agent, scope, budget_items):
    from .simulator import SimNetwork
    net = SimNetwork()
    obs = net.observations(observer=agent)
    def _probe():
        time.sleep(1.2)
        return obs, {"devices": len(net.devices),
                     "observations": len(obs),
                     "sample": obs[:1]}
    return job_id, "sim", agent, scope, budget_items, _probe


def _spawn(plan) -> None:
    def _runner():
        job_id, mode, agent, scope, budget, probe = plan
        job = JOBS.get(job_id)
        try:
            if job:
                job["state"] = "running"
            obs, stat = probe()
            obs = obs[:budget]
            _persist(job_id, obs, mode, scope, stat)
            if job:
                job["state"] = "done"
                job["progress"] = 100
                job["message"] = "complete"
                job["stat"] = stat
        except Exception as e:  # noqa: BLE001
            if job:
                job["state"] = "error"
                job["message"] = str(e)
        finally:
            if job:
                job["finished_at"] = now_ts()
                db.upsert_job(job)
                del JOBS[job_id]
    t = threading.Thread(target=_runner, daemon=True)
    t.start()


def _persist(job_id, obs, mode, scope, stat) -> None:
    with LOCK:
        conn = db.get_conn()
        try:
            conn.executemany(
                "INSERT OR REPLACE INTO observations"
                "(id,kind,source,observer,payload,observed_at)"
                " VALUES(?,?,?,?,?,?)",
                [(f"{job_id}-{i}", o.get("kind", "?"), o.get("source", "?"),
                  o.get("observer", "?"), json.dumps(o.get("payload", {})),
                  now_ts()) for i, o in enumerate(obs)],
            )
            conn.commit()
        finally:
            conn.close()


def get_job(job_id: str) -> dict | None:
    j = JOBS.get(job_id)
    if j:
        return j
    row = db.q1("SELECT id,mode,scope,state,message,progress,started_at,finished_at,counts FROM jobs WHERE id=?", (job_id,))
    return row
