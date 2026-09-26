from __future__ import annotations

import hashlib
import bisect

from .domain import Backend, Policy


class BaseSelector:
    def __init__(self) -> None:
        self.name = "BASE"

    def select(self, eligible, ctx, rng):
        raise NotImplementedError


class RoundRobinSelector(BaseSelector):
    def __init__(self) -> None:
        super().__init__()
        self.name = Policy.ROUND_ROBIN.value
        self._i = 0

    def select(self, eligible, ctx, rng):
        if not eligible:
            return None
        b = eligible[self._i % len(eligible)]
        self._i += 1
        return b


class WeightedRoundRobinSelector(BaseSelector):
    def __init__(self) -> None:
        super().__init__()
        self.name = Policy.WEIGHTED_ROUND_ROBIN.value
        self._current = {}
        self._total = 0

    def select(self, eligible, ctx, rng):
        if not eligible:
            return None
        now = ctx.get("now", 0.0)
        weights = {b.id: b.effective_weight(now) for b in eligible}
        total = sum(weights.values())
        for b in eligible:
            self._current[b.id] = self._current.get(b.id, 0) + weights[b.id]
        best = max(eligible, key=lambda b: self._current[b.id])
        self._current[best.id] -= total
        return best


class LeastConnectionsSelector(BaseSelector):
    def __init__(self) -> None:
        super().__init__()
        self.name = Policy.LEAST_CONNECTIONS.value
        self._epoch = 0
        self._last_epoch = {}

    def select(self, eligible, ctx, rng):
        if not eligible:
            return None
        now = ctx.get("now", 0.0)
        cands = []
        for b in eligible:
            cap = max(1.0, b.effective_capacity(now))
            cands.append((b.active_conns / cap, b.active_conns, self._last_epoch.get(b.id, 0), b.id))
        cands.sort(key=lambda t: (t[0], t[1], t[2]))
        picked_id = cands[0][3]
        self._epoch += 1
        self._last_epoch[picked_id] = self._epoch
        return next(b for b in eligible if b.id == picked_id)


class LeastResponseTimeSelector(BaseSelector):
    def __init__(self) -> None:
        super().__init__()
        self.name = Policy.LEAST_RESPONSE_TIME.value

    def select(self, eligible, ctx, rng):
        if not eligible:
            return None
        return min(eligible, key=lambda b: b.ewma_ms)


class PowerOfTwoChoicesSelector(BaseSelector):
    def __init__(self) -> None:
        super().__init__()
        self.name = Policy.POWER_OF_TWO_CHOICES.value

    def select(self, eligible, ctx, rng):
        if not eligible:
            return None
        if len(eligible) == 1:
            return eligible[0]
        a, b = rng.sample(eligible, 2)
        if (a.active_conns, a.id) <= (b.active_conns, b.id):
            return a
        return b


class RandomSelector(BaseSelector):
    def __init__(self) -> None:
        super().__init__()
        self.name = Policy.RANDOM.value

    def select(self, eligible, ctx, rng):
        if not eligible:
            return None
        return rng.choice(eligible)


class IpHashSelector(BaseSelector):
    def __init__(self) -> None:
        super().__init__()
        self.name = Policy.IP_HASH.value

    def select(self, eligible, ctx, rng):
        if not eligible:
            return None
        token = ctx.get("token", "CLI-0")
        h = int.from_bytes(hashlib.sha256(token.encode("utf-8")).digest(), "big")
        return eligible[h % len(eligible)]


class ConsistentHashSelector(BaseSelector):
    def __init__(self, vnodes: int = 128) -> None:
        super().__init__()
        self.name = Policy.CONSISTENT_HASH.value
        self.vnodes = vnodes
        self._ids = ()
        self._ring = []
        self._ring_map = {}
        self._keys = []

    def _rebuild(self, eligible):
        ring = []
        ring_map = {}
        for b in eligible:
            for v in range(self.vnodes):
                d = hashlib.sha256(f"{b.id}:{v}".encode("utf-8")).digest()
                pos = int.from_bytes(d[:8], "big")
                ring.append((pos, b.id))
        ring.sort(key=lambda t: t[0])
        self._ring = ring
        self._ring_map = ring_map
        self._keys = [pos for pos, _ in ring]
        self._ids = tuple(sorted(b.id for b in eligible))

    def select(self, eligible, ctx, rng):
        if not eligible:
            return None
        token = ctx.get("token", "CLI-0")
        ids = tuple(sorted(b.id for b in eligible))
        if ids != self._ids:
            self._rebuild(eligible)
        h = int.from_bytes(hashlib.sha256(f"tk:{token}".encode("utf-8")).digest(), "big")
        idx = bisect.bisect_left(self._keys, h) % len(self._keys)
        b_id = self._ring[idx][1]
        return next(b for b in eligible if b.id == b_id)


def make_selector(policy: Policy):
    if policy == Policy.ROUND_ROBIN:
        return RoundRobinSelector()
    if policy == Policy.WEIGHTED_ROUND_ROBIN:
        return WeightedRoundRobinSelector()
    if policy == Policy.LEAST_CONNECTIONS:
        return LeastConnectionsSelector()
    if policy == Policy.LEAST_RESPONSE_TIME:
        return LeastResponseTimeSelector()
    if policy == Policy.POWER_OF_TWO_CHOICES:
        return PowerOfTwoChoicesSelector()
    if policy == Policy.RANDOM:
        return RandomSelector()
    if policy == Policy.IP_HASH:
        return IpHashSelector()
    if policy == Policy.CONSISTENT_HASH:
        return ConsistentHashSelector()
    return RoundRobinSelector()