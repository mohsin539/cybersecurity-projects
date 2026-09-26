from __future__ import annotations

import random
import statistics
from typing import Callable, Dict, List, Optional, Tuple

from .domain import Backend, BackendState, CircuitState, FailureProfile, HealthSpec


class HealthController:
    def __init__(self, spec: HealthSpec, emit: Callable[[str, dict, str], None],
                 probe_evaluator: Callable[[Backend], Tuple[bool, float, str, bool]],
                 rng: random.Random, sources: int = 2) -> None:
        self.spec = spec
        self.emit = emit
        self.eval_probe = probe_evaluator
        self.rng = rng
        self.sources = max(1, sources)
        self.interval_s = self.spec.interval_ms / 1000.0
        self.min_hold_s = self.spec.min_state_hold_ms / 1000.0
        self.max_backoff = max(1.0, self.spec.backoff_max_ms / max(1, self.spec.interval_ms))

    def tick(self, now: float, backends: Dict[str, Backend]) -> None:
        for b in backends.values():
            if b.state == BackendState.REMOVED:
                continue
            if now >= b.next_probe_at:
                self._probe(b, now)
        for b in backends.values():
            if b.state == BackendState.DRAINING and b.drain_until is not None and now >= b.drain_until:
                self._transition(b, BackendState.REMOVED, now, "drain_timeout")
            if b.breaker == CircuitState.OPEN and now >= b.breaker_cooldown_until:
                b.breaker = CircuitState.HALF_OPEN
                b.half_open_trial_used = False
                self.emit("CIRCUIT_STATE", {"backend": b.id, "state": CircuitState.HALF_OPEN.value,
                                            "detail": "cooldown_elapsed"}, "info")

    def _jitter(self) -> float:
        j = self.spec.jitter_pct / 100.0
        return 1.0 + self.rng.uniform(-j / 2.0, j / 2.0)

    def _probe(self, b: Backend, now: float) -> None:
        b.probes_sent += 1
        results = [self.eval_probe(b) for _ in range(self.sources)]
        ok_count = sum(1 for r in results if r[0])
        partial = 0 < ok_count < self.sources
        all_ok = ok_count == self.sources
        lat = statistics.mean([r[1] for r in results]) if results else 0.0
        token_ok = bool(results) and all(r[3] for r in results)

        if partial:
            b.partial_agreements += 1
            self.emit("PROBE_RESULT",
                      {"backend": b.id, "ok": False, "latency_ms": round(lat, 1),
                       "ok_sources": ok_count, "sources": self.sources,
                       "detail": "partial_agreement"}, "warn")

        if not token_ok and not all_ok:
            self.emit("SECURITY_EVENT",
                      {"code": "PROBE_TOKEN_MISMATCH", "backend": b.id,
                       "detail": "probe response missing valid verification token"}, "high")

        ok = all_ok and token_ok
        b.last_probe_ok = ok
        b.probes_ok += 1 if ok else 0
        b.probes_fail += 0 if ok else 1

        if ok:
            b.consecutive_pass += 1
            b.consecutive_fail = 0
            b.probe_backoff = 1.0
            self._recover(b, now, lat)
        else:
            b.consecutive_fail += 1
            b.consecutive_pass = 0
            b.probe_backoff = min(self.max_backoff, max(1.0, 2.0 ** min(6, b.consecutive_fail)))
            self._fail(b, now, lat)

        mult = self.max_backoff if b.probe_backoff > self.max_backoff else b.probe_backoff
        b.next_probe_at = now + self.interval_s * mult * self._jitter()

    def _recover(self, b: Backend, now: float, lat: float) -> None:
        th = self.spec.pass_threshold
        if b.state == BackendState.UNHEALTHY and b.consecutive_pass >= th:
            self._transition(b, BackendState.BOOTING, now, "recovery_probe_pass")
        elif b.state == BackendState.BOOTING and b.consecutive_pass >= th:
            self._transition(b, BackendState.HEALTHY, now, "probes_stable")
            b.slow_start_started = now
            self._clear_signal(b)
        elif b.state == BackendState.DEGRADED and b.consecutive_pass >= th:
            if self._passive_ok(b):
                self._transition(b, BackendState.HEALTHY, now, "recovered_margin")
                b.slow_start_started = now
                self._clear_signal(b)

    @staticmethod
    def _clear_signal(b: Backend) -> None:
        b.passive_window.clear()
        b.ewma_ms = 0.0
        b.breaker_consecutive_errors = 0
        b.half_open_trial_used = False

    def _fail(self, b: Backend, now: float, lat: float) -> None:
        th = self.spec.fail_threshold
        if b.state in (BackendState.HEALTHY, BackendState.DEGRADED, BackendState.BOOTING) \
                and b.consecutive_fail >= th:
            b.quarantine_count += 1
            if b.quarantine_count >= self.spec.quarantine_threshold:
                self._transition(b, BackendState.QUARANTINED, now, "repeated_failures")
            else:
                self._transition(b, BackendState.UNHEALTHY, now, "active_probe_fail")

    def _passive_ok(self, b: Backend) -> bool:
        w = list(b.passive_window)
        if len(w) < 5:
            return True
        err = sum(1 for ok, _ in w if not ok) / len(w)
        return err < 0.2

    def _transition(self, b: Backend, to_state: BackendState, now: float, reason: str) -> bool:
        if to_state == b.state:
            return False
        if self.spec.min_state_hold_ms > 0 and (now - b.last_state_change) < self.min_hold_s:
            if to_state in (BackendState.HEALTHY, BackendState.DEGRADED, BackendState.UNHEALTHY):
                return False
        old = b.state
        b.state = to_state
        b.last_state_change = now
        sev = "warn"
        if to_state in (BackendState.UNHEALTHY, BackendState.QUARANTINED):
            sev = "high"
        if to_state == BackendState.HEALTHY:
            sev = "info"
        self.emit("STATE_TRANSITION",
                  {"backend": b.id, "from": old.value, "to": to_state.value, "reason": reason}, sev)
        if to_state == BackendState.QUARANTINED:
            self.emit("ALERT", {"code": "BACKEND_QUARANTINED", "backend": b.id,
                                "detail": "quarantine threshold reached, operator action required"}, "critical")
        elif to_state == BackendState.UNHEALTHY:
            self.emit("ALERT", {"code": "BACKEND_UNHEALTHY", "backend": b.id,
                                "detail": reason}, "high")
        return True

    def observe(self, b: Backend, ok: bool, latency_ms: float, now: float) -> None:
        b.passive_window.append((ok, latency_ms))
        if ok:
            a = 0.125
            b.ewma_ms = a * latency_ms + (1.0 - a) * b.ewma_ms
            b.breaker_consecutive_errors = 0
        else:
            b.breaker_consecutive_errors += 1

        w = list(b.passive_window)
        if len(w) < self.spec.min_passive_samples:
            return

        err = sum(1 for o, _ in w if not o) / len(w)
        p95 = statistics.quantiles([l for _, l in w], n=100)[94] if len(w) >= 20 else max(l for _, l in w)
        margin = max(b.ewma_ms + self.spec.grace_degraded_ms, b.ewma_ms * 1.8)
        degraded = err >= self.spec.error_rate_degrade or p95 > margin

        self._breaker(b, ok, err, now)

        if degraded and b.state == BackendState.HEALTHY:
            self._transition(b, BackendState.DEGRADED, now,
                             "passive_slowlane" if p95 > margin else f"error_rate_{err:.2f}")
        if err >= self.spec.error_rate_escalate and b.state in (BackendState.HEALTHY, BackendState.DEGRADED):
            b.quarantine_count += 1
            if b.quarantine_count >= self.spec.quarantine_threshold:
                self._transition(b, BackendState.QUARANTINED, now, "passive_error_escalation")
            else:
                self._transition(b, BackendState.UNHEALTHY, now, "passive_error_escalation")

    def _breaker(self, b: Backend, ok: bool, err: float, now: float) -> None:
        if b.breaker == CircuitState.CLOSED:
            if err >= 0.5 or b.breaker_consecutive_errors >= 5:
                b.breaker = CircuitState.OPEN
                b.breaker_cooldown_until = now + self.spec.circuit_cooldown_s
                self.emit("CIRCUIT_STATE",
                          {"backend": b.id, "state": CircuitState.OPEN.value,
                           "detail": f"err_rate_{err:.2f}_consec_{b.breaker_consecutive_errors}"}, "warn")
                self.emit("ALERT", {"code": "CIRCUIT_OPEN", "backend": b.id,
                                    "detail": "circuit breaker opened"}, "high")
        elif b.breaker == CircuitState.HALF_OPEN:
            if b.half_open_trial_used:
                if ok:
                    b.breaker = CircuitState.CLOSED
                    b.breaker_consecutive_errors = 0
                    self.emit("CIRCUIT_STATE",
                              {"backend": b.id, "state": CircuitState.CLOSED.value,
                               "detail": "trial_success"}, "info")
                else:
                    b.breaker = CircuitState.OPEN
                    b.breaker_cooldown_until = now + self.spec.circuit_cooldown_s
                    self.emit("CIRCUIT_STATE",
                              {"backend": b.id, "state": CircuitState.OPEN.value,
                               "detail": "trial_failed"}, "warn")

    def drain(self, b: Backend, now: float, timeout_s: float) -> None:
        if b.state == BackendState.DRAINING:
            return
        self._transition(b, BackendState.DRAINING, now, "operator_drain")
        b.drain_until = now + timeout_s

    def cancel_drain(self, b: Backend, now: float) -> None:
        if b.state == BackendState.DRAINING:
            b.drain_until = None
            self._transition(b, BackendState.HEALTHY, now, "drain_cancelled")

    def rearm(self, b: Backend, now: float) -> None:
        if b.state == BackendState.REMOVED:
            self._reset(b, now, BackendState.BOOTING, "re-registered")
            return
        self._reset(b, now, BackendState.BOOTING, "rearmed")

    def _reset(self, b: Backend, now: float, to_state: BackendState, reason: str) -> None:
        b.quarantine_count = 0
        b.consecutive_fail = 0
        b.consecutive_pass = 0
        b.probe_backoff = 1.0
        b.slow_start_started = None
        b.drain_until = None
        b.breaker = CircuitState.CLOSED
        b.breaker_consecutive_errors = 0
        b.half_open_trial_used = False
        b.active_conns = 0
        b.passive_window.clear()
        b.next_probe_at = now
        old = b.state
        b.state = to_state
        b.last_state_change = now
        self.emit("STATE_TRANSITION",
                  {"backend": b.id, "from": old.value, "to": to_state.value, "reason": reason}, "info")

    def eligible(self, b: Backend, now: float) -> bool:
        if b.state not in (BackendState.HEALTHY, BackendState.DEGRADED):
            return False
        if b.breaker != CircuitState.CLOSED:
            if b.breaker == CircuitState.HALF_OPEN and not b.half_open_trial_used:
                return True
            return False
        return b.active_conns < b.effective_capacity(now)