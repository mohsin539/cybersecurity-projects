"""Authoritative name servers (root/TLD/auth) hosting the "truth" zone.

Behavior per RFC-mode iterative resolution:
- name inside served zone             -> authoritative answer (AA=1)
- name under a hosted delegation zone -> referral (NS authority + glue additional, AA=0)
- absent name in zone                 -> NXDOMAIN with SOA in authority (negative TTL)
"""

from . import config
from .packets import (DnsError, TYPE_A, TYPE_NS, TYPE_SOA, QCLASS_IN, RR, RCODE_NXDOMAIN,
                      RCODE_OK, to_fqdn, DnsMessage)


class AuthServer:
    def __init__(self, ip, net, spec, latency=None):
        self.ip = ip
        self.net = net
        self.zone = to_fqdn(spec['zone'])
        self.records = spec['records']
        self.delegations = spec['delegations']
        self.soa = RR(self.zone, TYPE_SOA, config.DEFAULT_TTL, spec['soa'])
        self.soa_minttl = int(spec['soa'].split()[-1])
        self.latency = config.LEGIT_LATENCY if latency is None else latency
        net.node(ip, self)

    def handle(self, pkt):
        try:
            msg = DnsMessage.parse(pkt.data)
        except DnsError:
            return
        if not msg.questions:
            return
        q = msg.questions[0]
        qn = to_fqdn(q.name)
        resp = None

        for zone, dl in self.delegations.items():
            fz = to_fqdn(zone)
            if qn == fz or qn.endswith(fz) or qn.endswith(zone.rstrip('.') + '.'):
                resp = self._referral(msg, fz, dl)
                break

        if resp is None and config.is_subdomain(qn, self.zone):
            rec = self.records.get(qn.lower())
            if rec:
                rtype, rdatas = rec
                if rtype == q.qtype:
                    rrs = [RR(qn, rtype, config.DEFAULT_TTL, rd, QCLASS_IN) for rd in rdatas]
                    resp = msg.reply(aa=True, answers=rrs)
                else:
                    resp = msg.reply(aa=True, authority=[self.soa])
            else:
                resp = msg.reply(aa=True, rcode=RCODE_NXDOMAIN, authority=[self.soa])

        if resp is None:
            resp = msg.reply(rcode=RCODE_NXDOMAIN, authority=[self.soa])

        self.net.emit(resp.encode(), (self.ip, config.PORT), pkt.src, latency=self.latency)

    def _referral(self, msg, zone, dl):
        nss = dl['ns']
        glue = dl['glue']
        authority = [RR(zone, TYPE_NS, min(config.DEFAULT_TTL, 120), ns) for ns in nss]
        additional = [
            RR(ns, TYPE_A, config.DEFAULT_TTL, ip)
            for ns, ips in glue.items()
            for ip in ips
        ]
        return msg.reply(rcode=RCODE_OK, authority=authority, additional=additional)