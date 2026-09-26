"""Cache-poisoning attacker node.

Two knowledge models are intentionally separated (reference/memory.md ADR-002/ADR-005):

- "eavesdrop" : observes the query on the wire (same L2 segment). It learns id, port,
  qname and, if enabled, the full 0x20 case. Everything it sees it can echo back, so
  entropy defenses do NOT stop it (an on-path attacker beats them).
- "blind"     : does NOT see the query. It must guess the id (+ port + 0x20 case).
  Success is modelled as a seeded probabilistic race: P = 1 - (1/p)^attempts where
  p = id_space * port_space * case_space. On a win it pushes a matching spoof packet.

"serve" extends the attacker so it can *authoritatively answer* for the zone it stole
(the Kaminsky end-game): every A query under the evil zone gets the poisoned record.
"""

import random

from . import config
from .packets import (TYPE_A, TYPE_NS, Question, RR, QCLASS_IN, RCODE_OK,
                      to_fqdn, DnsMessage, make_query, DnsError)


# payload spec helper: each item = dict(name, rtype, ttl, rdata, section)
def _rr_from(item):
    return RR(to_fqdn(item['name']), item['rtype'], item.get('ttl', config.EVIL_TTL),
              item['rdata'], QCLASS_IN)


class Attacker:
    def __init__(self, ip, net, mode='eavesdrop', spoof_ip=None, payload=None,
                 rng=None, know_case=True):
        self.ip = ip
        self.net = net
        self.mode = mode
        self.spoof_ip = spoof_ip or config.AUTH_IP
        self.payload = [dict(p) for p in (payload or [])]
        self.rng = rng if rng is not None else random.Random()
        self.know_case = know_case
        self.serve_zone = None
        self.evil_a = config.EVIL_A
        self.stats = {'races': 0, 'wins': 0, 'spoofs_sent': 0, 'guesses_rolled': 0}

        self._armed = {}   # lower qname -> {'win': bool, 'once': bool, 'payload': ..., 'spoof_ip': ...}
        if mode in ('eavesdrop', 'blind'):
            net.tap(self._observe)
        net.node(ip, self)

    # ---- event handling (live node: only in serve mode) ----------------
    def handle(self, pkt):
        try:
            msg = DnsMessage.parse(pkt.data)
        except DnsError:
            return
        if msg.qr != 0 or not msg.questions:
            return
        q = msg.questions[0]
        qn = to_fqdn(q.name).lower()
        if self.serve_zone and config.is_subdomain(qn, self.serve_zone):
            if q.qtype == TYPE_A:
                rds = self.evil_a if qn != to_fqdn(config.EVIL_NS).lower() else config.EVIL_GLUE_ADDR
                resp = msg.reply(aa=True, answers=[RR(q.fqdn, TYPE_A, config.EVIL_TTL, rds)])
                self.net.emit(resp.encode(), (self.ip, config.PORT), pkt.src, latency=0)

    # ---- tap on every transport emit ----------------------------------
    def _observe(self, src, dst, data):
        if src[0] != config.RESOLVER_IP:
            return
        try:
            msg = DnsMessage.parse(data)
        except DnsError:
            return
        if msg.qr != 0 or not msg.questions:
            return
        q = msg.questions[0]
        key = to_fqdn(q.name).lower()
        armed = self._armed.get(key)
        if armed is None:
            return
        if self.mode == 'blind':
            if not armed['win']:
                return  # modelled loss: stay silent
        # The spoof must arrive at the resolver, echoing its ephemeral port.
        self._spoof_for(msg, (src[0], src[1]), armed)

    def _spoof_for(self, resp_template, requested_dst, armed):
        self.stats['spoofs_sent'] += 1
        q = resp_template.questions[0]
        resp = DnsMessage(
            id=resp_template.id, qr=1, ra=True,
            questions=[Question(q.name, q.qtype)],
        )
        for item in armed['payload']:
            rr = _rr_from(item)
            sec = item.get('section', 'answer')
            if rr.name.lower() == to_fqdn(q.name).lower() and q.qtype != rr.rtype:
                continue
            target = {'answer': resp.answers, 'authority': resp.authority,
                      'additional': resp.additional}[sec]
            target.append(rr)
        src = (armed['spoof_ip'], config.PORT)
        self.net.emit(resp.encode(), src, requested_dst, latency=0)

    # ---- arming ---------------------------------------------------------
    def arm(self, qname, payload=None, spoof_ip=None, attempts=0, entropy_bits=0,
            race_label=''):
        """Arm for one query name.

        For blind mode, `attempts` and `entropy_bits` drive the seeded race.
        """.strip()
        key = to_fqdn(qname).lower()
        win = True
        if self.mode == 'blind':
            if entropy_bits <= 0:
                p = 1.0
            else:
                p = 1.0 / (2 ** entropy_bits)
            prob = 1.0 - (1.0 - p) ** max(attempts, 1)
            win = self.rng.random() < prob
            self.stats['races'] += 1
            self.stats['guesses_rolled'] += max(attempts, 1)
            if win:
                self.stats['wins'] += 1
        self._armed[key] = {
            'win': win,
            'payload': [dict(p) for p in (payload if payload is not None else self.payload)],
            'spoof_ip': spoof_ip if spoof_ip is not None else self.spoof_ip,
        }
        return win, prob if self.mode == 'blind' else 1.0

    def arm_serve_zone(self, zone, evil_a=None):
        self.serve_zone = to_fqdn(zone)
        if evil_a is not None:
            self.evil_a = evil_a
        self.mode = 'serve'

    def clear(self):
        self._armed.clear()