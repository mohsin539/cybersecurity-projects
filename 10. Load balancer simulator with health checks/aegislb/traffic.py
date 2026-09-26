from __future__ import annotations

import random

from .domain import ArrivalModel


class Arrivals:
    def __init__(self, rng: random.Random, rps: float = 60.0, model: ArrivalModel = ArrivalModel.POISSON,
                 mmpp_low: float = 10.0, mmpp_high: float = 200.0, mmpp_switch: float = 0.4) -> None:
        self.rng = rng
        self.rps = max(0.0, float(rps))
        self.model = ArrivalModel(model)
        self.mmpp_low = mmpp_low
        self.mmpp_high = mmpp_high
        self.mmpp_switch = mmpp_switch
        self.mmpp_high_state = False
        self._next = 0.0
        self._last_now = 0.0
        self._gap = self._draw_gap()

    def set_rps(self, rps: float) -> None:
        self.rps = max(0.0, float(rps))
        self._gap = min(self._gap, self._draw_gap())

    def set_model(self, model: ArrivalModel) -> None:
        self.model = ArrivalModel(model)
        self._gap = self._draw_gap()

    def _state_rate(self) -> float:
        if self.model != ArrivalModel.MMPP:
            return self.rps
        return self.mmpp_high if self.mmpp_high_state else self.mmpp_low

    def _draw_gap(self) -> float:
        rate = self._state_rate()
        if rate <= 0:
            return float("inf")
        if self.model == ArrivalModel.CONSTANT:
            return 1.0 / rate
        return self.rng.expovariate(rate)

    def advance(self, now: float) -> int:
        dt = max(0.0, now - self._last_now)
        self._last_now = now
        if self.model == ArrivalModel.MMPP and dt > 0:
            p_flip = min(1.0, self.mmpp_switch * dt)
            if self.rng.random() < p_flip:
                self.mmpp_high_state = not self.mmpp_high_state
                self._gap = self._draw_gap()
        n = 0
        while self._next <= now:
            n += 1
            self._gap = self._draw_gap()
            self._next += self._gap
        return n