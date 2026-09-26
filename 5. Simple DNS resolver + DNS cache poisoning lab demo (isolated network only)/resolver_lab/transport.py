"""In-process simulated datagram transport with a hard isolation tripwire.

Every "packet" is routed only inside the lab prefix (172.16.238.*), never on real
sockets. Any packet aimed outside the prefix is dropped and counted; the orchestrator
treats a nonzero drop count as a safety failure (see architecture.md section 3, 15).
"""

import heapq

from . import config


class Packet:
    __slots__ = ('seq', 't', 'src', 'dst', 'data')

    def __init__(self, seq, t, src, dst, data):
        self.seq = seq
        self.t = t
        self.src = src  # (ip, port)
        self.dst = dst  # (ip, port)
        self.data = data


class SimNetwork:
    def __init__(self, prefix=None, safe=True):
        self.nodes = {}      # ip -> Node
        self.taps = []       # observe(src, dst, data) hooks (used by attacker shadow)
        self.pq = []
        self.clock = 0
        self.seq = 0
        self.packets = []    # delivered, in processing order
        self.dropped = []    # (src, dst) safety violations
        self.safe = safe
        self.prefix = prefix if prefix is not None else config.LAB_PREFIX

    def node(self, ip, n):
        self.nodes[ip] = n

    def tap(self, fn):
        self.taps.append(fn)

    def emit(self, data, src, dst, latency=0):
        if self.safe:
            for ip in (src[0], dst[0]):
                if not ip.startswith(self.prefix):
                    self.dropped.append((src, dst))
                    return False
        self.seq += 1
        heapq.heappush(self.pq, (self.clock + max(0, int(latency)), self.seq, src, dst, data))
        for tap in self.taps:
            tap(src, dst, data)
        return True

    def run(self, stop=None, max_msgs=300000):
        while self.pq:
            if len(self.packets) >= max_msgs:
                break
            t, seq, src, dst, data = heapq.heappop(self.pq)
            self.clock = max(self.clock, t)
            node = self.nodes.get(dst[0])
            pkt = Packet(seq, t, src, dst, data)
            if node is None:
                self.dropped.append((src, dst))
                continue
            node.handle(pkt)
            self.packets.append(pkt)
            if stop and stop():
                break
        return len(self.packets)

    def packet_count(self):
        return len(self.packets)