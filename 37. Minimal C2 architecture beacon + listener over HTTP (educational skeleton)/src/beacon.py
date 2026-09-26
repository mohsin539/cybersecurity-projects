"""Beacon (agent) - polls the listener, executes whitelisted tasks, reports back.

Guardrails (education/detection-testing only):
- Self-identifying beacon ID + local info; no persistence, no propagation,
  no arbitrary command execution.
- Task execution is a strict allowlist of pure-Python functions.
- Communication is encrypted at the application layer (Fernet).
"""
import json
import platform
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from uuid import uuid4

from .config import ALLOWED_TASKS, AUTH_HEADER, CHECKIN_INTERVAL_SEC
from .crypto import PayloadCrypto


# ---------------------------------------------------------------------------
# Whitelisted task executor (pure Python, no subprocess).
# ---------------------------------------------------------------------------
def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


def task_get_timestamp() -> dict:
    return {"utc": _now_utc(), "epoch": time.time()}


def task_get_uptime() -> dict:
    """Process/beacon uptime - pure Python, no shell."""
    return {"uptime_sec": round(time.time() - Beacon._started_ts)}


_EXECUTORS = {
    "get-sysinfo": lambda bid, p: {"os": platform.platform(), "hostname": socket.gethostname(),
                                   "machine": platform.machine(), "python": platform.python_version()},
    "get-timestamp": lambda bid, p: {"utc": _now_utc(), "epoch": time.time()},
    "get-uptime": lambda bid, p: task_get_uptime(),
    "heartbeat-test": lambda bid, p: {"ok": True, "ts": _now_utc()},
}


class Beacon:
    """Minimal HTTP beacon. Only runs allowlisted tasks (see ALLOWED_TASKS)."""

    _started_ts = time.time()

    def __init__(
        self,
        beacon_id: str | None = None,
        server_url: str = "http://127.0.0.1:8080",
        token: str | None = None,
        interval: float | None = None,
        key_b64: str | None = None,
        logger=None,
    ):
        from .config import BEACON_TOKEN
        self.beacon_id = beacon_id or f"beacon-{uuid4().hex[:8]}"
        self.server_url = server_url.rstrip("/")
        self.token = token or BEACON_TOKEN
        self.interval = float(interval or CHECKIN_INTERVAL_SEC)
        self.crypto = PayloadCrypto(key_b64)
        self.logger = logger
        self._stop = threading.Event()
        self.checkins = 0
        self.results = 0

    # ---- transport --------------------------------------------------------
    def _post(self, path: str, body: dict) -> dict:
        payload = {"payload": self.crypto.encrypt(json.dumps(body, default=str))}
        req = urllib.request.Request(
            self.server_url + path,
            data=json.dumps(payload).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                AUTH_HEADER: f"Bearer {self.token}",
            },
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    def _get(self, path: str) -> dict:
        req = urllib.request.Request(
            self.server_url + path,
            headers={AUTH_HEADER: f"Bearer {self.token}"},
            method="GET",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return json.loads(resp.read().decode("utf-8"))

    @staticmethod
    def _sysinfo() -> dict:
        return {
            "hostname": socket.gethostname(),
            "platform": platform.platform(),
            "system": platform.system(),
            "release": platform.release(),
            "machine": platform.machine(),
            "python": platform.python_version(),
        }

    # ---- one cycle --------------------------------------------------------
    def checkin(self) -> list[dict]:
        resp = self._post("/api/v1/checkin",
                          {"beacon_id": self.beacon_id, "meta": self._sysinfo()})
        self.checkins += 1
        return (resp.get("result") or {}).get("tasks") or []

    def execute(self, task: dict):
        name = task.get("name")
        if name not in ALLOWED_TASKS:
            return False, {"error": f"task '{name}' not in allowlist"}
        params = task.get("params") or {}
        try:
            fn = _EXECUTORS[name]
            out = fn(self.beacon_id, params)
            return True, out
        except Exception as exc:  # defensive: never crash the loop
            return False, {"error": str(exc)}

    def report(self, task_id: str, ok: bool, output: dict) -> dict:
        resp = self._post("/api/v1/result",
                          {"beacon_id": self.beacon_id, "task_id": task_id,
                           "ok": ok, "output": output})
        self.results += 1
        return resp

    # ---- loop -------------------------------------------------------------
    def run_cycle(self):
        try:
            tasks = self.checkin()
            if self.logger:
                self.logger.info("beacon %s checkin OK (%d task(s))", self.beacon_id, len(tasks))
            for task in tasks:
                ok, out = self.execute(task)
                self.report(task["task_id"], ok, out)
                if self.logger:
                    self.logger.info("task %s -> %s", task["task_id"], "OK" if ok else "FAILED")
        except urllib.error.HTTPError as exc:
            if self.logger:
                self.logger.warning("beacon %s HTTP %s from %s", self.beacon_id, exc.code, self.server_url)
        except urllib.error.URLError as exc:
            if self.logger:
                self.logger.warning("beacon %s cannot reach %s (%s)", self.beacon_id, self.server_url, exc.reason)
        except Exception as exc:  # never kill the loop
            if self.logger:
                self.logger.error("beacon %s unexpected error: %s", self.beacon_id, exc)

    def run_forever(self):
        if self.logger:
            self.logger.info("beacon %s started -> %s (interval %.0fs)", self.beacon_id, self.server_url, self.interval)
        while not self._stop.is_set():
            self.run_cycle()
            self._stop.wait(self.interval)  # interruptible sleep

    def stop(self):
        self._stop.set()