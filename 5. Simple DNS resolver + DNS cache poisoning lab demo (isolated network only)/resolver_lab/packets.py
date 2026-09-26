"""Minimal wire-correct DNS codec (RFC 1035 subset) used by the whole lab.

Security note (see security.md A08/A03): the parser is strictly bounds-checked and
pointer-loop guarded; malformed input raises DnsError, never an uncaught exception.
"""

import ipaddress
import struct
from dataclasses import dataclass, field

TYPE_A = 1
TYPE_NS = 2
TYPE_CNAME = 5
TYPE_SOA = 6
TYPE_TXT = 16
TYPE_AAAA = 28

TYPE_NAMES = {1: 'A', 2: 'NS', 5: 'CNAME', 6: 'SOA', 16: 'TXT', 28: 'AAAA'}
NAME_TO_TYPE = {v: k for k, v in TYPE_NAMES.items()}

QCLASS_IN = 1

RCODE_OK = 0
RCODE_FORMERR = 1
RCODE_SERVFAIL = 2
RCODE_NXDOMAIN = 3
RCODE_NAMES = {0: 'NOERROR', 1: 'FORMERR', 2: 'SERVFAIL', 3: 'NXDOMAIN', 5: 'REFUSED'}


class DnsError(Exception):
    pass


def to_fqdn(name):
    if not name or name == '.':
        return '.'
    return name if name.endswith('.') else name + '.'


def encode_name(name):
    name = to_fqdn(name)
    if name == '.':
        return b'\x00'
    out = bytearray()
    for label in name[:-1].split('.'):
        if not label:
            continue
        b = label.encode('ascii', 'replace')
        if len(b) > 63:
            raise DnsError('label too long')
        out.append(len(b))
        out += b
    out.append(0)
    return bytes(out)


def decode_name(data, off):
    """Return (fqdn, next_offset). Pointer-loop guarded (max 128 jumps)."""
    p = off
    labels = []
    jumped = False
    end = off
    jumps = 0
    while True:
        if p >= len(data):
            raise DnsError('truncated name')
        b = data[p]
        if b == 0:
            if not jumped:
                end = p + 1
            break
        if (b & 0xC0) == 0xC0:
            if p + 1 >= len(data):
                raise DnsError('bad pointer')
            jumps += 1
            if jumps > 128:
                raise DnsError('pointer loop')
            if not jumped:
                end = p + 2
                jumped = True
            p = ((b & 0x3F) << 8) | data[p + 1]
            continue
        if b > 63:
            raise DnsError('bad label length')
        if p + 1 + b > len(data):
            raise DnsError('label out of bounds')
        labels.append(data[p + 1:p + 1 + b].decode('ascii', 'replace'))
        p += 1 + b
    name = '.'.join(labels) + '.' if labels else '.'
    return name, end


def encode_rdata(rtype, rdata):
    if rtype == TYPE_A:
        return ipaddress.IPv4Address(rdata).packed
    if rtype == TYPE_AAAA:
        return ipaddress.IPv6Address(rdata).packed
    if rtype in (TYPE_NS, TYPE_CNAME):
        return encode_name(rdata)
    if rtype == TYPE_TXT:
        b = rdata.encode('utf-8')[:255]
        return bytes([len(b)]) + b
    if rtype == TYPE_SOA:
        parts = rdata.split()
        if len(parts) != 7:
            raise DnsError('SOA needs 7 fields')
        ints = [int(x) for x in parts[2:]]
        return encode_name(parts[0]) + encode_name(parts[1]) + struct.pack('>IIIII', *ints)
    raise DnsError(f'unsupported rtype {rtype}')


def decode_rdata(rtype, raw):
    if rtype == TYPE_A:
        return str(ipaddress.IPv4Address(raw))
    if rtype == TYPE_AAAA:
        return str(ipaddress.IPv6Address(raw))
    if rtype in (TYPE_NS, TYPE_CNAME):
        n, _ = decode_name(raw, 0)
        return n
    if rtype == TYPE_TXT:
        return raw[1:1 + raw[0]].decode('utf-8', 'replace') if raw else ''
    if rtype == TYPE_SOA:
        mname, o = decode_name(raw, 0)
        nname, o = decode_name(raw, o)
        if len(raw) < o + 20:
            raise DnsError('SOA truncated')
        a, b, c, d, e = struct.unpack_from('>IIIII', raw, o)
        return f'{mname} {nname} {a} {b} {c} {d} {e}'
    return raw.hex()


@dataclass
class Question:
    name: str
    qtype: int
    qclass: int = QCLASS_IN

    @property
    def fqdn(self):
        return to_fqdn(self.name)

    @property
    def key(self):
        return (self.fqdn.lower(), self.qtype)

    def to_bytes(self):
        return encode_name(self.fqdn) + struct.pack('>HH', self.qtype, self.qclass)


@dataclass
class RR:
    name: str
    rtype: int
    ttl: int
    rdata: str
    rclass: int = QCLASS_IN

    @property
    def fqdn(self):
        return to_fqdn(self.name)

    def to_bytes(self):
        rd = encode_rdata(self.rtype, self.rdata)
        return encode_name(self.fqdn) + struct.pack('>HHIH', self.rtype, self.rclass, self.ttl, len(rd)) + rd


def parse_rr(data, off):
    name, off = decode_name(data, off)
    if off + 10 > len(data):
        raise DnsError('rr header bounds')
    rtype, rclass, ttl, rdlen = struct.unpack_from('>HHIH', data, off)
    off += 10
    if off + rdlen > len(data):
        raise DnsError('rdlen bounds')
    raw = data[off:off + rdlen]
    off += rdlen
    rdata = decode_rdata(rtype, raw)
    return RR(name, rtype, ttl, rdata, rclass), off


@dataclass
class DnsMessage:
    id: int
    qr: int = 0
    opcode: int = 0
    aa: bool = False
    tc: bool = False
    rd: bool = False
    ra: bool = False
    z: int = 0
    rcode: int = 0
    questions: list = field(default_factory=list)
    answers: list = field(default_factory=list)
    authority: list = field(default_factory=list)
    additional: list = field(default_factory=list)

    @property
    def rcode_name(self):
        return RCODE_NAMES.get(self.rcode, str(self.rcode))

    def _flags(self):
        return (
            (self.qr << 15)
            | ((self.opcode & 0xF) << 11)
            | (int(self.aa) << 10)
            | (int(self.tc) << 9)
            | (int(self.rd) << 8)
            | (int(self.ra) << 7)
            | ((self.z & 0x7) << 4)
            | (self.rcode & 0xF)
        )

    def encode(self):
        head = struct.pack(
            '>HHHHHH',
            self.id, self._flags(),
            len(self.questions), len(self.answers), len(self.authority), len(self.additional),
        )
        body = b''.join(q.to_bytes() for q in self.questions)
        body += b''.join(r.to_bytes() for r in self.answers)
        body += b''.join(r.to_bytes() for r in self.authority)
        body += b''.join(r.to_bytes() for r in self.additional)
        return head + body

    @classmethod
    def parse(cls, data):
        if len(data) < 12:
            raise DnsError('truncated header')
        mid, flags, qd, an, nsct, ar = struct.unpack_from('>HHHHHH', data, 0)
        off = 12
        questions = []
        for _ in range(qd):
            name, off = decode_name(data, off)
            if off + 4 > len(data):
                raise DnsError('question bounds')
            qt, qc = struct.unpack_from('>HH', data, off)
            off += 4
            questions.append(Question(name, qt, qc))

        def read(count):
            out = []
            cur = off
            for _ in range(count):
                rr, cur = parse_rr(data, cur)
                out.append(rr)
            return out, cur

        answers, off = read(an)
        authority, off = read(nsct)
        additional, off = read(ar)
        return cls(
            mid,
            qr=(flags >> 15) & 1,
            opcode=(flags >> 11) & 0xF,
            aa=bool((flags >> 10) & 1),
            tc=bool((flags >> 9) & 1),
            rd=bool((flags >> 8) & 1),
            ra=bool((flags >> 7) & 1),
            z=(flags >> 4) & 7,
            rcode=flags & 0xF,
            questions=questions,
            answers=answers,
            authority=authority,
            additional=additional,
        )

    def reply(self, rcode=0, aa=False, ra=True, answers=None, authority=None, additional=None,
              questions=None):
        return DnsMessage(
            id=self.id, qr=1, rd=self.rd, ra=ra, aa=aa, rcode=rcode,
            questions=list(questions) if questions is not None else list(self.questions),
            answers=list(answers) if answers is not None else [],
            authority=list(authority) if authority is not None else [],
            additional=list(additional) if additional is not None else [],
        )


def make_query(qid, name, qtype, rd=True):
    return DnsMessage(id=qid, rd=rd, questions=[Question(to_fqdn(name), qtype)])


def msg_label(payload):
    """Human-readable one-liner for the timeline."""
    try:
        m = DnsMessage.parse(payload)
    except DnsError:
        return 'MALFORMED'
    q = m.questions[0] if m.questions else None
    kind = 'Q' if m.qr == 0 else 'R'
    if q:
        return f'{kind} {m.id:#06x} {q.name} {TYPE_NAMES.get(q.qtype, q.qtype)} rcode={m.rcode_name}'
    if m.qr == 1:
        rds = ','.join(r.rdata for r in m.answers[:3])
        return f'R {m.id:#06x} rcode={m.rcode_name} ans=[{rds}]'
    return f'{kind} empty'