from __future__ import annotations

import threading
import time
import uuid
from typing import Dict, List, Optional

from .domain import (ArrivalModel, Backend, BackendState, FailureProfile, HealthSpec,
                     LatencyModel, Policy, PoolConfig, ProbeType, STATE_INDEX)
from .health import HealthController
from .policy import make_selector
from .randomstream import RngStream
from .traffic import Arrivals

TICK_REAL = 0.05
DEFAULT_METRICS = {
    "sessions_total": 0,
    "errors_total": 0,
    "rejects_total": 0,
    "rejects_no_eligible": 0,
    "rejects_over_capacity": 0,
    "probes_total": 0,
    "probes_ok": 0,
    "probes_fail": 0,
    "decisions_total": 0,
    "per_policy": {},
}


class Simulator:
    def __init__(self, store_root: str = ".") -> None:
        self.mu = threading.RLock()
        self.store_root = store_root
        self.running = False
        self.started = False
        self.paused = False
        self.sim_time = 0.0
        self.seed = 0xA1B2
        self.rps = 60.0
        self.speed = 1.0
        self.arrival_model = ArrivalModel.POISSON
        self.policy = Policy.LEAST_CONNECTIONS
        self.pool = PoolConfig()
        self.health_spec = HealthSpec()
        self.sources = 2
        self.backends: Dict[str, Backend] = {}
        self.events: List[dict] = []
        self.alerts: List[dict] = []
        self.metrics = dict(DEFAULT_METRICS)
        self.run_id = ""
        self.manifest = {}
        self._next_eid = 1
        self.lag_mult = 6.0
        self._sel: Optional[object] = None
        self._sel_key = None
        self._thread: Optional[threading.Thread] = None
        self._pending: List[dict] = []
        self._failure_reverts: List[tuple] = []
        self._sessions_window: List[tuple] = []
        self._last_history = 0.0
        self._last_flush = 0.0
        self._rng = RngStream(self.seed)
        self._traf_rng = self._rng.child("traffic")
        self._probe_rng = self._rng.child("probe")
        self._lat_rng = self._rng.child("latency")
        self._fail_rng = self._rng.child("failure")
        self._tok_rng = self._rng.child("token")
        self.arrivals = Arrivals(self._traf_rng, self.rps)
        self.health = HealthController(self.health_spec, self._emit, self._eval_probe,
                                       self._probe_rng, self.sources)
        self._store = None
        try:
            from .state_store import PersistentStore
            self._store = PersistentStore(self.store_root)
        except Exception:
            self._store = None

    def _emit(self, etype: str, payload: dict, sev: str = "info") -> None:
        ev = {"id": self._next_eid, "gen": self.run_id, "t": round(self.sim_time, 3),
              "type": etype, "sev": sev, "payload": payload}
        self._next_eid += 1
        self.events.append(ev)
        if len(self.events) > 8000:
            del self.events[:2000]
        if sev in ("warn", "high", "critical"):
            self.alerts.append({"id": ev["id"], "t": ev["t"], "sev": sev,
                                "type": etype, "text": f"{etype} {payload.get('detail', '')}"})
            if len(self.alerts) > 200:
                del self.alerts[:50]

    def _new_rng(self, seed: int) -> None:
        self._rng = RngStream(seed)
        self._traf_rng = self._rng.child("traffic")
        self._probe_rng = self._rng.child("probe")
        self._lat_rng = self._rng.child("latency")
        self._fail_rng = self._rng.child("failure")
        self._tok_rng = self._rng.child("token")
        self.arrivals = Arrivals(self._traf_rng, self.rps, self.arrival_model)

    def start(self, manifest: Optional[dict] = None, threaded: bool = True) -> dict:
        with self.mu:
            if self.running:
                return {"ok": False, "error": "already_running"}
            m = manifest or {}
            self.seed = int(m.get("seed", 0xA1B2))
            self.rps = float(m.get("rps", 60.0))
            self.speed = float(m.get("speed", 1.0))
            self.arrival_model = ArrivalModel(m.get("arrival_model", "POISSON") or "POISSON")
            self.policy = Policy(m.get("policy", "LEAST_CONNECTIONS"))
            hs = m.get("health", {})
            self.health_spec = HealthSpec(
                probe_type=ProbeType(hs.get("probe_type", "HTTP_GET")),
                interval_ms=int(hs.get("interval_ms", 5000)),
                timeout_ms=int(hs.get("timeout_ms", 2000)),
                fail_threshold=int(hs.get("fail_threshold", 3)),
                pass_threshold=int(hs.get("pass_threshold", 2)),
                grace_degraded_ms=int(hs.get("grace_degraded_ms", 1500)),
                jitter_pct=int(hs.get("jitter_pct", 10)),
                backoff_max_ms=int(hs.get("backoff_max_ms", 60000)),
                min_state_hold_ms=int(hs.get("min_state_hold_ms", 2000)),
                circuit_cooldown_s=float(hs.get("circuit_cooldown_s", 10.0)),
                passive_window=int(hs.get("passive_window", 50)),
                min_passive_samples=int(hs.get("min_passive_samples", 10)),
                error_rate_degrade=float(hs.get("error_rate_degrade", 0.5)),
                error_rate_escalate=float(hs.get("error_rate_escalate", 0.9)),
                quarantine_threshold=int(hs.get("quarantine_threshold", 3)),
            )
            self.sources = max(1, int(m.get("health_sources", 2)))
            self.pool = PoolConfig(policy=self.policy, health_spec=self.health_spec,
                                   health_sources=self.sources)
            self.sim_time = 0.0
            self.paused = False
            self._next_eid = 1
            self.events.clear()
            self.alerts.clear()
            self.metrics = dict(DEFAULT_METRICS)
            self._pending.clear()
            self._failure_reverts.clear()
            self._sessions_window.clear()
            self._last_history = 0.0
            self._last_flush = 0.0
            self.backends.clear()
            self.run_id = uuid.uuid4().hex[:12]
            self._new_rng(self.seed)
            specs = m.get("backends")
            if specs:
                for s in specs:
                    self._add_backend(**s)
            else:
                self._default_backends()
            self._sel_key = None
            self._sel = None
            self.health = HealthController(self.health_spec, self._emit, self._eval_probe,
                                           self._probe_rng, self.sources)
            self.running = True
            self.started = True
            self.manifest = m
            if threaded:
                self._thread = threading.Thread(target=self._loop, name="sim-loop", daemon=True)
                self._thread.start()
            self._emit("RUN", {"action": "started", "seed": self.seed, "rps": self.rps,
                               "speed": self.speed, "policy": self.policy.value,
                               "health_sources": self.sources, "run_id": self.run_id}, "info")
            return {"ok": True, "run_id": self.run_id}

    def stop(self) -> dict:
        with self.mu:
            if not self.running:
                return {"ok": False, "error": "not_running"}
            self.running = False
        if self._thread is not None:
            self._thread.join(timeout=3.0)
        with self.mu:
            self._emit("RUN", {"action": "stopped", "run_id": self.run_id}, "info")
            self.flush_persistent()
        return {"ok": True}

    def advance_sync(self, steps: int = 1) -> None:
        with self.mu:
            if not self.running:
                return
            for _ in range(steps):
                dt = TICK_REAL * self.speed
                self.sim_time += dt
                try:
                    self._step(dt)
                except Exception as exc:
                    self._emit("ALERT", {"code": "SIM_LOOP_ERROR", "detail": str(exc)}, "high")

    def _default_backends(self) -> None:
        self._add_backend(name="web-1", weight=100, capacity=800, latency_base_ms=38,
                          latency_model="EXP", severity_error_p=0.004)
        self._add_backend(name="web-2", weight=100, capacity=900, latency_base_ms=42,
                          latency_model="NORMAL", severity_error_p=0.004)
        self._add_backend(name="web-3", weight=60, capacity=700, latency_base_ms=55,
                          latency_model="EXP", severity_error_p=0.006)
        self._add_backend(name="api-1", weight=40, capacity=600, latency_base_ms=70,
                          latency_model="PARETO", severity_error_p=0.008)

    def _add_backend(self, name: str, weight: int = 100, capacity: int = 1000,
                     latency_base_ms: int = 40, latency_model: str = "EXP",
                     severity_error_p: float = 0.005) -> str:
        bid = "b-" + uuid.uuid4().hex[:8]
        b = Backend(id=bid, name=str(name), weight=int(weight), capacity=int(capacity),
                    latency_base_ms=int(latency_base_ms),
                    latency_model=LatencyModel(latency_model),
                    severity_error_p=float(severity_error_p))
        b.slow_warmup_s = self.pool.warmup_s
        b.next_probe_at = self.sim_time + self._probe_rng.uniform(0.0, self.health.interval_s)
        self.backends[bid] = b
        self._emit("BACKEND_ADDED", {"backend": bid, "name": b.name,
                                     "weight": b.weight, "capacity": b.capacity,
                                     "latency_base_ms": b.latency_base_ms,
                                     "latency_model": b.latency_model.value}, "info")
        return bid

    def add_backend(self, name: str, weight: int = 100, capacity: int = 1000,
                    latency_base_ms: int = 40, latency_model: str = "EXP",
                    severity_error_p: float = 0.005) -> dict:
        with self.mu:
            bid = self._add_backend(name, weight, capacity, latency_base_ms, latency_model,
                                    severity_error_p)
            return {"ok": True, "id": bid}

    def remove_backend(self, backend_id: str) -> dict:
        with self.mu:
            b = self.backends.get(backend_id)
            if b is None:
                return {"ok": False, "error": "not_found"}
            if b.state == BackendState.REMOVED:
                return {"ok": False, "error": "already_removed"}
            b.state = BackendState.REMOVED
            b.active_conns = 0
            self._emit("BACKEND_REMOVED", {"backend": backend_id, "name": b.name}, "warn")
            return {"ok": True}

    def set_failure(self, backend_id: str, profile: str, until: Optional[float] = None) -> dict:
        with self.mu:
            b = self.backends.get(backend_id)
            if b is None:
                return {"ok": False, "error": "not_found"}
            try:
                prof = FailureProfile(profile)
            except ValueError:
                return {"ok": False, "error": "invalid_profile"}
            prev = b.failure_profile
            b.failure_profile = prof
            b.failure_set_at = self.sim_time
            self._failure_reverts[:] = [r for r in self._failure_reverts if r[1] != backend_id]
            if until is not None and prof != FailureProfile.NONE:
                self._failure_reverts.append((self.sim_time + float(until), backend_id, prev))
            self._emit("FAILURE_INJECTED", {"backend": backend_id, "profile": prof.value,
                                            "until": until, "from": prev.value}, "warn")
            return {"ok": True}

    def set_run(self, rps: Optional[float] = None, speed: Optional[float] = None,
                policy: Optional[str] = None, arrival_model: Optional[str] = None) -> dict:
        with self.mu:
            changed = {}
            if rps is not None and float(rps) != self.rps:
                self.rps = max(0.0, float(rps))
                self.arrivals.set_rps(self.rps)
                changed["rps"] = self.rps
            if speed is not None:
                self.speed = max(0.1, float(speed))
                changed["speed"] = self.speed
            if policy is not None and Policy(policy) != self.policy:
                self.policy = Policy(policy)
                self.pool.policy = self.policy
                self._sel = None
                self._sel_key = None
                changed["policy"] = self.policy.value
            if arrival_model is not None:
                self.arrival_model = ArrivalModel(arrival_model)
                self.arrivals.set_model(self.arrival_model)
                changed["arrival_model"] = self.arrival_model.value
            if changed:
                self._emit("CONFIG_CHANGED", changed, "info")
            return {"ok": True, "changed": changed}

    def set_paused(self, paused: bool) -> dict:
        with self.mu:
            self.paused = bool(paused)
            self._emit("RUN", {"action": "paused" if self.paused else "resumed"}, "info")
            return {"ok": True, "paused": self.paused}

    def drain(self, backend_id: str) -> dict:
        with self.mu:
            b = self.backends.get(backend_id)
            if b is None:
                return {"ok": False, "error": "not_found"}
            self.health.drain(b, self.sim_time, self.pool.drain_timeout_s)
            self._emit("ADMIN_ACTION", {"action": "drain", "backend": backend_id}, "info")
            return {"ok": True}

    def cancel_drain(self, backend_id: str) -> dict:
        with self.mu:
            b = self.backends.get(backend_id)
            if b is None:
                return {"ok": False, "error": "not_found"}
            self.health.cancel_drain(b, self.sim_time)
            return {"ok": True}

    def rearm(self, backend_id: str) -> dict:
        with self.mu:
            b = self.backends.get(backend_id)
            if b is None:
                return {"ok": False, "error": "not_found"}
            self.health.rearm(b, self.sim_time)
            return {"ok": True}

    def _selector(self):
        if self._sel is None or self._sel_key != self.policy:
            self._sel = make_selector(self.policy)
            self._sel_key = self.policy
        return self._sel

    def _eval_probe(self, b: Backend):
        prof = b.failure_profile
        if prof == FailureProfile.CRASH:
            return (False, 0.0, "unreachable", True)
        if prof == FailureProfile.PROBE_NO_TOKEN:
            lat = max(1.0, b.latency_base_ms * (0.8 + self._probe_rng.random() * 0.4))
            return (True, round(lat, 1), "200", False)
        if prof == FailureProfile.FLAP:
            if self._probe_rng.random() < 0.40:
                return (False, 0.0, "connect_timeout", True)
            lat = max(1.0, b.latency_base_ms * (0.8 + self._probe_rng.random() * 0.4))
            return (True, round(lat, 1), "200", True)
        lat = max(1.0, b.latency_base_ms * (0.8 + self._probe_rng.random() * 0.4))
        return (True, round(lat, 1), "200", True)

    def _sample_latency(self, b: Backend) -> float:
        base = b.latency_base_ms
        m = b.latency_model
        if m == LatencyModel.FIXED:
            v = base
        elif m == LatencyModel.EXP:
            v = base * self._lat_rng.expovariate(1.0)
        elif m == LatencyModel.NORMAL:
            v = base + self._lat_rng.gauss(0.0, base * 0.3)
        elif m == LatencyModel.PARETO:
            u = max(0.0001, self._lat_rng.random())
            v = base / (u ** (1.0 / 1.5))
        else:
            v = base
        return max(1.0, round(v, 1))

    def _eligible(self, b: Backend, now: float) -> bool:
        return self.health.eligible(b, now)

    def _decide(self, token: str, now: float) -> None:
        eligible = [b for b in self.backends.values()
                    if b.state in (BackendState.HEALTHY, BackendState.DEGRADED)]
        eligible = [b for b in eligible if self._eligible(b, now)]
        sel = None
        reason = "no_eligible"
        if eligible:
            eligible_sorted = sorted(eligible, key=lambda b: b.id)
            sel = self._selector().select(eligible_sorted, {"token": token, "now": now}, self._probe_rng)
            reason = self.policy.value.lower()
        if sel is None:
            self.metrics["rejects_total"] += 1
            self.metrics["rejects_no_eligible"] += 1
            self._emit("SESSION_REJECT", {"token": token, "reason": "no_eligible",
                                          "status": 503}, "warn")
            return
        cap = sel.effective_capacity(now)
        if sel.active_conns >= cap:
            self.metrics["rejects_total"] += 1
            self.metrics["rejects_over_capacity"] += 1
            self._emit("SESSION_REJECT", {"token": token, "reason": "over_capacity",
                                          "backend": sel.id, "status": 503}, "warn")
            return
        sel.active_conns += 1
        ok, lat, status = self._session_outcome(sel, now)
        due = now + lat / 1000.0
        self._pending.append({"due": due, "backend": sel.id, "token": token, "ok": ok,
                              "latency": lat, "status": status})
        self.metrics["decisions_total"] += 1
        self.metrics["per_policy"][self.policy.value] = self.metrics["per_policy"].get(
            self.policy.value, 0) + 1
        self._emit("DECISION", {"token": token, "backend": sel.id, "policy": self.policy.value,
                                "reason": reason, "latency_ms": round(lat, 1),
                                "status": status, "eligible": len(eligible_sorted)}, "info")

    def _session_outcome(self, b: Backend, now: float):
        prof = b.failure_profile
        lat = self._sample_latency(b)
        status = 200
        ok = True
        if prof == FailureProfile.LAG:
            lat = lat * self.lag_mult
            status = 200
        if prof == FailureProfile.FLAP and self._fail_rng.random() < 0.40:
            ok = False
            status = 500
            lat = 5.0
        if ok and self._fail_rng.random() < b.severity_error_p:
            ok = False
            status = 500
            lat = max(3.0, lat)
        if prof == FailureProfile.CRASH:
            ok = False
            status = 500
            lat = 0.5
        return ok, lat, status

    def _complete(self, now: float) -> None:
        kept = []
        for s in self._pending:
            if s["due"] <= now:
                b = self.backends.get(s["backend"])
                if b is None:
                    continue
                b.active_conns = max(0, b.active_conns - 1)
                b.total_sessions += 1
                if s["ok"]:
                    self.metrics["sessions_total"] += 1
                else:
                    b.total_errors += 1
                    self.metrics["errors_total"] += 1
                    self.metrics["sessions_total"] += 1
                self.health.observe(b, s["ok"], s["latency"], now)
                self._emit("SESSION_COMPLETE", {"token": s["token"], "backend": s["backend"],
                                                "ok": s["ok"], "latency_ms": round(s["latency"], 1),
                                                "status": s["status"]}, "info")
            else:
                kept.append(s)
        self._pending[:] = kept

    def _step(self, dt: float) -> None:
        now = self.sim_time
        n = self.arrivals.advance(now)
        self._sessions_window.append((now, self.metrics["sessions_total"]))
        if len(self._sessions_window) > 200:
            del self._sessions_window[:50]
        for _ in range(n):
            token = f"CLI-{self._tok_rng.randrange(0, 1 << 32):08x}"
            self._decide(token, now)
        self._complete(now)
        self.health.tick(now, self.backends)
        reverts = []
        for due, bid, prev in self._failure_reverts:
            if now >= due:
                b = self.backends.get(bid)
                if b is not None and b.failure_profile != FailureProfile.NONE:
                    b.failure_profile = prev
                    self._emit("FAILURE_REVERTED", {"backend": bid, "profile": prev.value}, "info")
            else:
                reverts.append((due, bid, prev))
        self._failure_reverts[:] = reverts
        if now - self._last_history >= 0.25:
            self._last_history = now
            for b in self.backends.values():
                b.history.append((round(b.ewma_ms, 1), STATE_INDEX[b.state]))
        if now - self._last_flush >= 2.0 and self._store is not None:
            self._last_flush = now
            self.flush_persistent()

    def flush_persistent(self) -> None:
        if self._store is None:
            return
        try:
            self._store.flush(self)
        except Exception as e:
            self._emit("ALERT", {"code": "PERSIST_STORE_ERROR", "detail": str(e)}, "high")

    def _loop(self) -> None:
        while self.running:
            t0 = time.monotonic()
            with self.mu:
                if not self.paused:
                    dt = TICK_REAL * self.speed
                    self.sim_time += dt
                    try:
                        self._step(dt)
                    except Exception as exc:
                        self._emit("ALERT", {"code": "SIM_LOOP_ERROR", "detail": str(exc)}, "high")
            el = time.monotonic() - t0
            sleep = max(0.0, TICK_REAL / self.speed - el)
            if sleep > 0:
                time.sleep(sleep)

    def events_after(self, cursor: int) -> List[dict]:
        with self.mu:
            out = [e for e in self.events if e["id"] > cursor]
            tail = self.events[-1]["id"] if self.events else 0
            return out, tail

    def recent_alerts(self, limit: int = 12) -> List[dict]:
        with self.mu:
            return list(self.alerts[-limit:])

    def rps_now(self) -> float:
        with self.mu:
            if len(self._sessions_window) < 2:
                return 0.0
            (t0, s0), (t1, s1) = self._sessions_window[0], self._sessions_window[-1]
            span = t1 - t0
            if span <= 0:
                return 0.0
            return max(0.0, (s1 - s0) / span)

    def snapshot(self) -> dict:
        with self.mu:
            metrics = dict(self.metrics)
            metrics["rps_now"] = round(self.rps_now(), 1)
            backends = []
            for b in self.backends.values():
                cap = round(b.effective_capacity(self.sim_time), 1)
                w = b.effective_weight(self.sim_time)
                hist = [[v[0], v[1]] for v in b.history]
                backends.append({
                    "id": b.id, "name": b.name, "state": b.state.value,
                    "weight": b.weight, "effective_weight": w, "capacity": b.capacity,
                    "effective_capacity": cap, "active_conns": b.active_conns,
                    "total_sessions": b.total_sessions, "total_errors": b.total_errors,
                    "ewma_ms": round(b.ewma_ms, 1), "consecutive_fail": b.consecutive_fail,
                    "consecutive_pass": b.consecutive_pass,
                    "probes_sent": b.probes_sent, "probes_ok": b.probes_ok,
                    "probes_fail": b.probes_fail, "partial_agreements": b.partial_agreements,
                    "breaker": b.breaker.value, "failure_profile": b.failure_profile.value,
                    "latency_base_ms": b.latency_base_ms, "latency_model": b.latency_model.value,
                    "quarantine_count": b.quarantine_count, "history": hist[-90:],
                    "errors_rate": self._error_rate(b),
                })
            last_event = self.events[-1] if self.events else None
            return {
                "run": {
                    "id": self.run_id, "running": self.running, "paused": self.paused,
                    "seed": self.seed, "rps": self.rps, "speed": self.speed,
                    "arrival_model": self.arrival_model.value, "policy": self.policy.value,
                    "sim_time": round(self.sim_time, 2), "sources": self.sources,
                },
                "manifest": self.manifest,
                "metrics": metrics,
                "backends": backends,
                "alerts": self.recent_alerts(12),
                "last_event_id": last_event["id"] if last_event else 0,
                "health_spec": {
                    "interval_ms": self.health_spec.interval_ms,
                    "fail_threshold": self.health_spec.fail_threshold,
                    "pass_threshold": self.health_spec.pass_threshold,
                    "grace_degraded_ms": self.health_spec.grace_degraded_ms,
                    "backoff_max_ms": self.health_spec.backoff_max_ms,
                    "circuit_cooldown_s": self.health_spec.circuit_cooldown_s,
                    "quarantine_threshold": self.health_spec.quarantine_threshold,
                },
            }

    def _error_rate(self, b: Backend) -> float:
        w = list(b.passive_window)
        if not w:
            return 0.0
        return round(sum(1 for ok, _ in w if not ok) / len(w), 3)