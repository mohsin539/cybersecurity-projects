"""TTL-aware resolver cache with provenance/audit tags (architecture.md section 8)."""

import time
from dataclasses import dataclass, field

from .packets import TYPE_NS, to_fqdn


@dataclass
class CacheEntry:
    name: str
    qtype: int
    rdata: list
    ttl: int
    deadline: float
    origin_zone: str
    from_addr: str
    from_port: int = 53
    forged: bool = False
    kind: str = 'answer'  # answer | negative | glue | delegation

    def to_dict(self):
        return {
            'name': self.name,
            'qtype': self.qtype,
            'rtype': self.qtype,
            'rdata': list(self.rdata),
            'ttl': self.ttl,
            'deadline': round(self.deadline, 3),
            'origin_zone': self.origin_zone,
            'from_addr': self.from_addr,
            'from_port': self.from_port,
            'forged': bool(self.forged),
            'kind': self.kind,
        }


@dataclass
class Delegation:
    zone: str
    nss: list
    glue: dict  # lower(nsname) -> [ips]
    ttl: int
    deadline: float
    from_addr: str

    def to_dict(self):
        return {
            'name': self.zone,
            'qtype': TYPE_NS,
            'rdata': list(self.nss),
            'ttl': self.ttl,
            'deadline': round(self.deadline, 3),
            'origin_zone': self.zone,
            'from_addr': self.from_addr,
            'from_port': 53,
            'forged': False,
            'kind': 'delegation',
        }


class Cache:
    def __init__(self, ttl_floor=0, now_fn=None):
        self.entries = {}
        self.delegations = {}
        self.ttl_floor = int(ttl_floor or 0)
        self._now_fn = now_fn
        self.mutations = []

    def _now(self):
        return self._now_fn() if self._now_fn else time.time()

    def _ttl(self, ttl):
        return max(int(ttl), self.ttl_floor)

    def _key(self, name, qtype):
        return (to_fqdn(name).lower(), qtype)

    def put_answer(self, name, qtype, rdata, ttl, origin_zone, from_addr, from_port=53,
                   forged=False, kind='answer'):
        t = self._ttl(ttl)
        now = self._now()
        entry = CacheEntry(to_fqdn(name), qtype, list(rdata), t, now + t,
                           origin_zone, from_addr, from_port, forged, kind)
        key = self._key(name, qtype)
        self.entries[key] = entry
        self.mutations.append(f'cached {to_fqdn(name)}/{qtype} {rdata}')
        return entry

    def put_negative(self, name, qtype, soa_ttl, from_addr, origin_zone=''):
        t = self._ttl(soa_ttl)
        now = self._now()
        entry = CacheEntry(to_fqdn(name), qtype, [], t, now + t, origin_zone,
                           from_addr, 53, False, 'negative')
        self.entries[self._key(name, qtype)] = entry
        self.mutations.append(f'cached negative {to_fqdn(name)}/{qtype}')
        return entry

    def put_delegation(self, zone, nss, glue, ttl, from_addr):
        z = to_fqdn(zone).lower()
        t = self._ttl(ttl)
        now = self._now()
        self.delegations[z] = Delegation(to_fqdn(zone), list(nss), dict(glue), t, now + t, from_addr)
        self.mutations.append(f'cached delegation {to_fqdn(zone)} -> {nss}')
        return self.delegations[z]

    def lookup(self, name, qtype):
        e = self.entries.get(self._key(name, qtype))
        if e is None:
            return None
        if e.deadline < self._now():
            del self.entries[self._key(name, qtype)]
            return None
        if not e.rdata and e.kind == 'negative':
            return e  # negative hit: resolver treats as "known absence"
        return e

    def nearest_delegation(self, name):
        n = to_fqdn(name).lower()
        now = self._now()
        best = None
        best_len = 0
        for zone, d in self.delegations.items():
            if d.deadline < now:
                continue
            if self._is_subdomain(n, zone) and len(zone) > best_len:
                best = d
                best_len = len(zone)
        return best

    @staticmethod
    def _is_subdomain(name_lower, zone_lower):
        if zone_lower == '.':
            return True
        if not name_lower.endswith(zone_lower):
            return False
        if len(name_lower) == len(zone_lower):
            return True
        return name_lower[-len(zone_lower) - 1] == '.'

    def drop_delegation(self, zone):
        self.delegations.pop(to_fqdn(zone).lower(), None)

    def flush(self):
        self.entries.clear()
        self.delegations.clear()
        self.mutations.append('cache flushed')

    def dump(self):
        rows = [e.to_dict() for e in self.entries.values()]
        for d in self.delegations.values():
            rows.append(d.to_dict())
        return rows