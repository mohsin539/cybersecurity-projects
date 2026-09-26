from __future__ import annotations

import tempfile
import time
import unittest
from pathlib import Path

from pydantic import ValidationError

from aegislb.domain import BackendState, CircuitState, FailureProfile
from aegislb.engine import Simulator
from aegislb.security import SecurityManager
from aegislb.api import BackendCreate, RunUpdate
from aegislb.state_store import PersistentStore


FAST_HEALTH = {
    "interval_ms": 300,
    "timeout_ms": 1000,
    "fail_threshold": 2,
    "pass_threshold": 2,
    "grace_degraded_ms": 800,
    "jitter_pct": 5,
    "backoff_max_ms": 4000,
    "min_state_hold_ms": 200,
    "circuit_cooldown_s": 2.0,
    "quarantine_threshold": 2,
}


def manifest(seed=0xABCD, rps=200, speed=10.0, policy="LEAST_CONNECTIONS", **kw):
    m = {"seed": seed, "rps": rps, "speed": speed, "policy": policy, "health": FAST_HEALTH}
    m.update(kw)
    return m


class SimTestCase(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.store = self.tmp.name

    def tearDown(self):
        self.tmp.cleanup()

    def make_sim(self, **kw):
        return Simulator(store_root=self.store)

    def _first_id(self, sim):
        return next(iter(sim.backends))

    def run_to(self, sim, target_sim, wall_timeout=30.0):
        wall_end = time.monotonic() + wall_timeout
        while time.monotonic() < wall_end:
            s = sim.snapshot()
            if s["run"]["sim_time"] >= target_sim:
                return s
            time.sleep(0.01)
        raise AssertionError(f"did not reach {target_sim}s sim time (stopped at {sim.sim_time})")

    def wait_state(self, sim, backend_id, state, wall_timeout=30.0):
        wall_end = time.monotonic() + wall_timeout
        while time.monotonic() < wall_end:
            for b in sim.snapshot()["backends"]:
                if b["id"] == backend_id and b["state"] == state:
                    return True
            time.sleep(0.02)
        return False

    def wait_any_state(self, sim, backend_id, states, wall_timeout=30.0):
        wall_end = time.monotonic() + wall_timeout
        while time.monotonic() < wall_end:
            for b in sim.snapshot()["backends"]:
                if b["id"] == backend_id and b["state"] in states:
                    return b["state"]
            time.sleep(0.02)
        return None

    def crash_and_stabilize(self, sim, bid):
        sim.set_failure(bid, "CRASH")
        reached = self.wait_any_state(sim, bid, {"UNHEALTHY", "QUARANTINED"})
        self.assertIsNotNone(reached, "backend never left healthy after CRASH")
        sim.set_failure(bid, "NONE")
        if sim.backends[bid].state == BackendState.QUARANTINED:
            sim.rearm(bid)
        return reached

    def wait_healthy(self, sim):
        wall_end = time.monotonic() + 40.0
        while time.monotonic() < wall_end:
            backends = sim.snapshot()["backends"]
            if backends and all(b["state"] == "HEALTHY" for b in backends):
                return backends
            time.sleep(0.02)
        raise AssertionError("backends never became healthy")

    def decisions(self, sim):
        return [e for e in sim.events if e["type"] == "DECISION"]


class TestDeterminism(SimTestCase):
    def test_same_seed_same_decisions(self):
        a = self.make_sim()
        b = self.make_sim()
        try:
            a.start(manifest(seed=42, rps=500, speed=50, policy="LEAST_CONNECTIONS"), threaded=False)
            b.start(manifest(seed=42, rps=500, speed=50, policy="LEAST_CONNECTIONS"), threaded=False)
            a.advance_sync(8)
            b.advance_sync(8)
            amap = {x["id"]: x["name"] for x in a.snapshot()["backends"]}
            bmap = {x["id"]: x["name"] for x in b.snapshot()["backends"]}
            da = [(e["payload"]["token"], amap.get(e["payload"]["backend"], "?"))
                  for e in self.decisions(a)]
            db = [(e["payload"]["token"], bmap.get(e["payload"]["backend"], "?"))
                  for e in self.decisions(b)]
            self.assertGreater(len(da), 100)
            self.assertEqual(len(da), len(db))
            self.assertEqual(da, db)
        finally:
            a.stop()
            b.stop()


def stable_backends(n=2, base=30):
    return [{"name": f"w{i}", "weight": 100, "capacity": 2000,
             "latency_base_ms": base + 5 * i, "latency_model": "FIXED",
             "severity_error_p": 0.0001} for i in range(n)]


class TestHealthLifecycle(SimTestCase):
    def test_crash_unhealthy_then_recovery(self):
        sim = self.make_sim()
        sim.start(manifest(seed=7, rps=60, backends=stable_backends(2)))
        try:
            self.wait_healthy(sim)
            bid = self._first_id(sim)
            reached = self.crash_and_stabilize(sim, bid)
            self.assertTrue(self.wait_state(sim, bid, "HEALTHY", wall_timeout=40))
            self.assertEqual(sim.backends[bid].failure_profile, FailureProfile.NONE)
        finally:
            sim.stop()

    def test_passive_degrade_no_crash(self):
        sim = self.make_sim()
        sim.start(manifest(seed=13, rps=400, speed=20, policy="LEAST_CONNECTIONS"))
        try:
            self.wait_healthy(sim)
            bid = self._first_id(sim)
            sim.set_failure(bid, "LAG")
            deps = [b for b in sim.snapshot()["backends"] if b["id"] == bid]
            self.assertEqual(deps[0]["state"], "HEALTHY")
            sim.stop()
        finally:
            if sim.running:
                sim.stop()


class TestQuarantine(SimTestCase):
    def test_repeated_crash_drives_quarantine(self):
        sim = self.make_sim()
        sim.start(manifest(seed=5, rps=60, backends=stable_backends(2)))
        try:
            self.wait_healthy(sim)
            bid = self._first_id(sim)
            quarantined = False
            for _ in range(4):
                reached = self.crash_and_stabilize(sim, bid)
                if reached == "QUARANTINED":
                    quarantined = True
                    break
                self.assertTrue(self.wait_state(sim, bid, "HEALTHY", wall_timeout=40))
            self.assertTrue(quarantined, "repeated crashes never drove quarantine")
        finally:
            sim.stop()


class TestEligibilityAndDrain(SimTestCase):
    def test_drain_excludes_from_rotation(self):
        sim = self.make_sim()
        sim.start(manifest(seed=3, rps=60, backends=stable_backends(2)))
        try:
            self.wait_healthy(sim)
            bid = self._first_id(sim)
            sim.drain(bid)
            self.assertTrue(self.wait_state(sim, bid, "DRAINING"))
            marker = len(sim.events)
            self.run_to(sim, sim.sim_time + 2.0)
            chosen = set(e["payload"]["backend"]
                        for e in sim.events[marker:] if e["type"] == "DECISION")
            self.assertNotIn(bid, chosen)
            self.assertTrue(self.wait_state(sim, bid, "REMOVED", wall_timeout=40))
        finally:
            sim.stop()


class TestSlowStart(SimTestCase):
    def test_weight_ramps(self):
        sim = self.make_sim()
        sim.start(manifest(seed=9, rps=60, backends=stable_backends(2)))
        try:
            self.wait_healthy(sim)
            bid = self._first_id(sim)
            self.crash_and_stabilize(sim, bid)
            self.assertTrue(self.wait_state(sim, bid, "HEALTHY", wall_timeout=40))
            s = sim.snapshot()
            b_early = next(x for x in s["backends"] if x["id"] == bid)
            self.assertEqual(b_early["state"], "HEALTHY")
            warm = sim.backends[bid].slow_warmup_s
            self.assertLess(b_early["effective_weight"], b_early["weight"])
            self.run_to(sim, sim.sim_time + warm + 1.0)
            b_late = next(x for x in sim.snapshot()["backends"] if x["id"] == bid)
            self.assertGreaterEqual(b_late["effective_weight"], b_late["weight"])
        finally:
            sim.stop()


class TestRoundRobinDistribution(SimTestCase):
    def test_rr_near_balanced(self):
        sim = self.make_sim()
        sim.start(manifest(seed=11, rps=500, speed=30, policy="ROUND_ROBIN",
                           backends=[
                               {"name": "a1", "weight": 100, "capacity": 1000,
                                "latency_base_ms": 30, "latency_model": "FIXED",
                                "severity_error_p": 0.0001},
                               {"name": "a2", "weight": 100, "capacity": 1000,
                                "latency_base_ms": 40, "latency_model": "FIXED",
                                "severity_error_p": 0.0001},
                           ]))
        try:
            self.wait_healthy(sim)
            self.run_to(sim, sim.sim_time + 5.0)
            chosen = [e["payload"]["backend"] for e in self.decisions(sim)]
            counts = {}
            for c in chosen:
                counts[c] = counts.get(c, 0) + 1
            total = sum(counts.values())
            self.assertGreater(total, 100)
            ratio = counts[min(counts, key=counts.get)] / total
            self.assertAlmostEqual(ratio, 0.5, delta=0.08)
        finally:
            sim.stop()


class TestCircuitBreaker(SimTestCase):
    def test_breaker_opens(self):
        sim = self.make_sim()
        sim.start(manifest(seed=17, rps=600, speed=30, policy="LEAST_CONNECTIONS",
                           backends=[
                               {"name": "ok1", "weight": 100, "capacity": 100000,
                                "latency_base_ms": 10, "latency_model": "FIXED",
                                "severity_error_p": 0.0001},
                               {"name": "bad1", "weight": 100, "capacity": 100000,
                                "latency_base_ms": 10, "latency_model": "FIXED",
                                "severity_error_p": 0.0001},
                           ]))
        try:
            self.wait_healthy(sim)
            bid = next(x["id"] for x in sim.snapshot()["backends"] if x["name"] == "bad1")
            sim.set_failure(bid, "CRASH")
            wall_end = time.monotonic() + 40
            opened = False
            while time.monotonic() < wall_end:
                b = sim.backends[bid]
                if b.breaker == CircuitState.OPEN:
                    opened = True
                    break
                time.sleep(0.02)
            self.assertTrue(opened, "circuit breaker did not open")
        finally:
            sim.stop()


class TestSecurity(SimTestCase):
    def test_authz_and_audit_chain(self):
        mgr = SecurityManager(emit=None)
        ok, reason = mgr.authorize(mgr.tokens["config"], "config", "POST", "/api/v1/runs/start")
        self.assertTrue(ok)
        ok2, reason2 = mgr.authorize("wrong-key", "config", "POST", "/api/v1/runs/start")
        self.assertFalse(ok2)
        self.assertEqual(reason2, "invalid_key")
        self.assertGreaterEqual(len(mgr.audit), 2)
        self.assertEqual(len(mgr.audit[-1]["chain"]), 64)
        ok3, _ = mgr.authorize(mgr.tokens["ops"], "ops", "POST", "/api/v1/backends/-/drain")
        self.assertTrue(ok3)
        self.assertNotEqual(mgr.audit[-1]["chain"], mgr.audit[-2]["chain"])

    def test_rate_limit(self):
        mgr = SecurityManager(emit=None)
        client = "10.0.0.1"
        granted = 0
        for _ in range(mgr._rate_limit + 5):
            if mgr.rate_allow(client):
                granted += 1
        self.assertGreaterEqual(granted, mgr._rate_limit)
        self.assertFalse(mgr.rate_allow(client))

    def test_exhausted_rate_blocks(self):
        import time as _time
        mgr = SecurityManager(emit=None)
        mgr._rate_buckets["c"].extend([_time.monotonic()] * mgr._rate_limit)
        self.assertFalse(mgr.rate_allow("c"))


class TestValidation(SimTestCase):
    def test_backend_name_reject(self):
        with self.assertRaises(ValidationError):
            BackendCreate(name="x<script>")

    def test_policy_allowlist(self):
        with self.assertRaises(ValidationError):
            RunUpdate(policy="NEVER_TRUST")

    def test_unknown_policy_reject(self):
        with self.assertRaises(ValidationError):
            RunUpdate(policy="MAGIC_ROUTING")


class TestPersistentStore(SimTestCase):
    def test_preservation_files(self):
        sim = self.make_sim()
        sim.start(manifest(seed=2, rps=200, speed=50))
        try:
            self.run_to(sim, 4.0)
        finally:
            sim.stop()
        sim.flush_persistent()
        for f in ("state.md", "memory.md", "security.md"):
            p = Path(self.store) / f
            self.assertTrue(p.exists(), f)
            self.assertGreater(p.stat().st_size, 200)
        cache = Path(self.store) / ".aegislb_cache.json"
        self.assertTrue(cache.exists())

    def test_notes_roundtrip(self):
        store = PersistentStore(self.tmp.name)
        store.set_notes("preserve me")
        store2 = PersistentStore(self.tmp.name)
        self.assertEqual(store2.notes, "preserve me")


if __name__ == "__main__":
    unittest.main(verbosity=2)