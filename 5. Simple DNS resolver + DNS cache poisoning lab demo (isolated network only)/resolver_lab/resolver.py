"""Recursive, caching DNS resolver (the component under attack).

Defenses (see architecture.md section 10), all toggleable per trial:
  random_id      - random 16-bit transaction ID (on by default)
  random_port    - per-query ephemeral source port
  use_0x20       - random-case query names that the response must echo
  bailiwick_check- only cache in-scope additional records
  ttl_floor      - minimum TTL for cached entries
"""

import secrets
import random

from . import config
from .cache import Cache
from .packets import (DnsError, TYPE_A, TYPE_NS, TYPE_SOA, Question, RCODE_NXDOMAIN,
                      make_query, to_fqdn, DnsMessage)
from .transport import SimNetwork


class Resolver:
    def __init__(self, ip, net, root_ip, zones_map, defenses, rng=None, now_fn=None):
        self.ip = ip
        self.net = net
        self.root = root_ip
        self.zones_map = zones_map
        self.defenses = dict(defenses or {})
        self.rng = rng if rng is not None else random.Random()
        self.cache = Cache(ttl_floor=self.defenses.get('ttl_floor', 0), now_fn=now_fn)
        self.pending = None
        self._got = None
        self._ask_token = 0
        self.events = []
        self.queries_sent = 0
        net.node(ip, self)

    # ---- defense helpers -------------------------------------------------
    def _d(self, name, default):
        return self.defenses.get(name, default)

    def _next_id(self):
        if not self._d('random_id', True):
            return 0xBEEF
        return self.rng.randint(0, 65535)

    def _next_port(self):
        if not self._d('random_port', False):
            return 32255
        return self.rng.randint(49152, 65535)

    @staticmethod
    def _randomize_case(name):
        # 0x20: each letter randomly upper/lower; uses secrets (unguessable),
        # independent of the scenario seed (see reference/memory.md ADR-004).
        out = []
        for ch in name:
            if ch.isalpha():
                out.append(ch.upper() if secrets.randbits(1) else ch.lower())
            else:
                out.append(ch)
        return ''.join(out)

    # ---- wire I/O --------------------------------------------------------
    def handle(self, pkt):
        try:
            msg = DnsMessage.parse(pkt.data)
        except DnsError:
            return
        if msg.qr != 1:
            return
        sent = self.pending
        if sent is None:
            return
        if not self._check(msg, sent, pkt):
            return
        self._got = (sent, msg, pkt)
        self.pending = None

    def _check(self, msg, sent, pkt):
        if msg.id != sent['id']:
            return False
        if pkt.src[0] != sent['target']:
            return False
        if pkt.dst[1] != sent['port']:
            return False
        if not msg.questions:
            return False
        rq = msg.questions[0]
        sq = sent['question']
        if rq.qtype != sq.qtype:
            return False
        if self._d('use_0x20', False):
            if to_fqdn(rq.name) != to_fqdn(sq.name):
                return False
        elif to_fqdn(rq.name).lower() != to_fqdn(sq.name).lower():
            return False
        return True

    def _ask(self, target_ip, name, qtype):
        token = self._ask_token + 1
        self._ask_token = token
        qid = self._next_id()
        port = self._next_port()
        send_name = name
        if self._d('use_0x20', False):
            send_name = self._randomize_case(name)
        q = make_query(qid, send_name, qtype)
        sent = {'token': token, 'id': qid, 'port': port,
                'target': target_ip, 'question': Question(to_fqdn(send_name), qtype)}
        self.pending = sent
        self._got = None
        self.net.emit(q.encode(), (self.ip, port), (target_ip, config.PORT), latency=0)
        self.queries_sent += 1
        start = self.net.clock

        def stop():
            if self._got is not None and self._got[0]['token'] == token:
                return True
            return (self.net.clock - start) > 200

        self.net.run(stop=stop, max_msgs=200000)
        got = self._got
        self.pending = None
        if got is None or got[0]['token'] != token:
            return None
        _, msg, pkt = got
        return {'msg': msg, 'src': pkt.src[0]}

    # ---- resolution ------------------------------------------------------
    def resolve(self, name, qtype, max_hops=14):
        name = to_fqdn(name)
        hit = self.cache.lookup(name, qtype)
        if hit is not None:
            if hit.kind == 'negative':
                return [], True
            return list(hit.rdata), True

        target = self.root
        for _ in range(max_hops):
            deleg = self.cache.nearest_delegation(name)
            if deleg is not None:
                ns = deleg.nss[0]
                glue = deleg.glue.get(to_fqdn(ns).lower()) or deleg.glue.get(to_fqdn(ns))
                if glue:
                    target = glue[0]
                else:
                    self.cache.drop_delegation(deleg.zone)
                    self.events.append('unusable delegation dropped: ' + deleg.zone)
                    target = self.root

            got = self._ask(target, name, qtype)
            if got is None:
                self.events.append(f'timeout querying {target}')
                target = self.root
                continue
            msg = got['msg']
            src = got['src']

            if msg.rcode == RCODE_NXDOMAIN:
                ttl = self._soa_ttl(msg)
                self.cache.put_negative(name, qtype, ttl, from_addr=src,
                                        origin_zone=self.zones_map.get(src, ''))
                return [], False

            ans = [r for r in msg.answers
                   if to_fqdn(r.name).lower() == name.lower() and r.rtype == qtype]
            if ans:
                ttl = min(r.ttl for r in ans)
                rds = [r.rdata for r in ans]
                self.cache.put_answer(name, qtype, rds, ttl,
                                      self.zones_map.get(src, ''), src)
                self._maybe_cache_extra(msg, src, name)
                return rds, False

            ref_zone = self._best_referral(msg, name)
            if ref_zone is not None:
                zone, nss, ttl, glue, _extra = self._referral_data(msg, ref_zone)
                self.cache.put_delegation(zone, nss, glue, ttl, src)
                ns = nss[0]
                g = glue.get(to_fqdn(ns).lower()) or glue.get(ns)
                if g:
                    target = g[0]
                    continue
                self.cache.drop_delegation(zone)
                self.events.append('referral without usable glue: ' + ns)
                target = self.root
                continue

            target = self.root

        self.events.append(f'resolution failed for {name}')
        return [], False

    # ---- cache policy ----------------------------------------------------
    @staticmethod
    def _best_referral(msg, name):
        n = to_fqdn(name).lower()
        best = None
        blen = -1
        for r in msg.authority:
            if r.rtype != TYPE_NS:
                continue
            z = to_fqdn(r.name).lower()
            if z == '.' or not n.endswith(z):
                continue
            if len(z) > blen:
                best = z
                blen = len(z)
        return best

    def _referral_data(self, msg, zone):
        nss = []
        ttl = config.DEFAULT_TTL
        for r in msg.authority:
            if r.rtype == TYPE_NS and to_fqdn(r.name).lower() == zone:
                nss.append(r.rdata)
                ttl = min(ttl, r.ttl)
        glue = {}
        extra = []
        ns_lower = {to_fqdn(x).lower() for x in nss}
        for a in msg.additional:
            if a.rtype != TYPE_A:
                continue
            an = to_fqdn(a.name).lower()
            if an in ns_lower:
                glue.setdefault(an, []).append(a.rdata)
            else:
                extra.append(a)
        return zone, nss, ttl, glue, extra

    def _maybe_cache_extra(self, msg, from_addr, query_name):
        """Bailiwick policy for out-of-scope additional records.

        OFF  -> out-of-zone additional A records are cached (the vulnerability
                demonstrated by scenario 04).
        ON   -> ignored.
        """
        if self._d('bailiwick_check', True):
            return
        qn = to_fqdn(query_name).lower()
        for a in msg.additional:
            if a.rtype != TYPE_A:
                continue
            an = to_fqdn(a.name).lower()
            if an == qn:
                continue
            self.cache.put_answer(an, TYPE_A, [a.rdata], a.ttl,
                                  self.zones_map.get(from_addr, ''), from_addr)

    @staticmethod
    def _soa_ttl(msg):
        for r in msg.authority:
            if r.rtype == TYPE_SOA:
                return int(r.rdata.split()[-1])
        return config.NEG_TTL