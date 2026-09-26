"""C2 agent / implant simulator (architecture L2 - client side).

Each agent runs in its own daemon thread, beaconing on the configured
interval + jitter to the C2 server, packaging an AES-GCM-style payload blob
(with `cryptography` if available, else a base64 stand-in) into the TLV frame.
"""

from __future__ import annotations

import base64
import os
import socket
import struct
import threading
import time

from c2_sim.bus import EventBus
from c2_sim.server import LEN_FMT, MAGIC, MAX_PAYLOAD

try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    _HAS_AESGCM = True
except Exception:  # pragma: no cover - optional dependency
    _HAS_AESGCM = False

CHANNELS: dict[str, int] = {"http": 0, "https": 1, "dns": 2}


class C2Agent:
    def __init__(self, agent_id: int, host: str, port: int,
                 interval_s: float, jitter_pct: float, channel: str,
                 user_agent: str, bus: EventBus, sleep_first: float = 0.0):
        self.id = agent_id
        self.host = host
        self.port = port
        self.interval = interval_s
        self.jitter = jitter_pct
        self.channel = channel
        self.user_agent = user_agent
        self.bus = bus
        self.sleep_first = sleep_first
        self.stop_flag = threading.Event()
        self.sent = 0

    # -- payload -------------------------------------------------------- #
    @staticmethod
    def _encrypt_payload(task_id: str) -> bytes:
        if _HAS_AESGCM:
            key = os.urandom(32)
            nonce = os.urandom(12)
            blob = AESGCM(key).encrypt(nonce, b"task:" + task_id.encode(), None)
            return nonce + blob
        return base64.b64encode(b"task:" + task_id.encode())

    def _packet(self, task_id: str) -> bytes:
        blob = self._encrypt_payload(task_id)
        payload = base64.b64encode(blob)
        head = MAGIC + bytes([CHANNELS.get(self.channel, 0), self.id & 0xFF])
        head += LEN_FMT.pack(min(len(payload), MAX_PAYLOAD))
        return head + payload[:MAX_PAYLOAD]

    # -- beacon loop ---------------------------------------------------- #
    def run(self, duration: float) -> None:
        if self.sleep_first > 0:
            time.sleep(min(self.sleep_first, duration))
        deadline = time.time() + duration
        while not self.stop_flag.is_set() and time.time() < deadline:
            interval = self.interval * (1 + (self.jitter / 100.0) *
                                        ((time.time() % 5000) / 2500 - 1))  # -j..+j
            interval = max(0.05, interval)
            try:
                self.beacon_once()
                self.sent += 1
            except OSError:
                time.sleep(1.0)  # server not up yet
            time.sleep(min(interval, max(0.0, deadline - time.time()) or interval))

    def beacon_once(self) -> None:
        task_id = os.urandom(8).hex() * 2  # 16 hex chars matches Suricata pcre
        with socket.create_connection((self.host, self.port), timeout=3) as sock:
            sock.sendall(self._packet(task_id))
            try:
                sock.settimeout(2)
                sock.recv(16)  # "ok" ack
            except OSError:
                pass
        # Push the agent-side packet (outbound half of the "conversation").
        self.bus.push({
            "src_ip": "10.0.0.%d" % (100 + self.id),
            "src_port": 40000 + self.id,
            "dst_ip": self.host, "dst_port": self.port,
            "proto": "tcp", "traffic_type": "c2_beacon",
            "payload_hex": "007f",
            "task_id": task_id,
            "channel": self.channel,
            "agent_id": self.id,
            "user_agent": self.user_agent,
            "role": "agent_side",
        })

    def stop(self) -> None:
        self.stop_flag.set()


class AgentFleet:
    def __init__(self, cfg, bus: EventBus):
        self.cfg = cfg
        self.bus = bus
        self.agents: list[C2Agent] = []
        self._threads: list[threading.Thread] = []

    def spawn(self) -> None:
        for i in range(self.cfg.agent_count):
            agent = C2Agent(agent_id=i, host=self.cfg.server_host,
                            port=self.cfg.server_port,
                            interval_s=self.cfg.beacon_interval,
                            jitter_pct=self.cfg.jitter_pct,
                            channel=self.cfg.channel,
                            user_agent=self.cfg.user_agent,
                            bus=self.bus, sleep_first=self.cfg.sleep_window)
            self.agents.append(agent)
            t = threading.Thread(target=agent.run, args=(self.cfg.run_duration,),
                                 daemon=True, name=f"agent-{i}")
            self._threads.append(t)
            t.start()

    def stop(self) -> None:
        for a in self.agents:
            a.stop()
        for t in self._threads:
            t.join(timeout=5)
        self._threads.clear()

    @property
    def sent(self) -> int:
        return sum(a.sent for a in self.agents)