"""Benign traffic generator (architecture L2 - precision tuning).

Synthesizes realistic "noise" traffic that must NOT match the C2 signatures.
Without this, precision/recall numbers are meaningless. Events are marked
`traffic_type=benign` and form the false-positive baseline for the detector.
"""

from __future__ import annotations

import os
import random
import string
import threading
import time

from c2_sim.bus import EventBus

BENIGN_UAS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0 Safari/537.36",
    "curl/8.6.0",
    "python-requests/2.32.3",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) Mobile Safari/605.1.15",
    "Wget/1.21.4",
]


def _rand_host() -> str:
    return f"10.0.{random.randint(2, 90)}.{random.randint(2, 250)}"


def _rand_qname() -> str:
    words = ["login", "api", "cdn", "img", "static", "www", "mail", "blog"]
    tlds = ["com", "net", "org", "io"]
    s = "".join(random.choices(string.ascii_lowercase, k=random.randint(6, 10)))
    return f"{random.choice(words)}-{s}.{random.choice(tlds)}"


def _benign_event(ts: float) -> dict:
    kind = random.random()
    if kind < 0.55:  # plain HTTPS-ish web request
        return {
            "src_ip": _rand_host(), "src_port": random.randint(1024, 65535),
            "dst_ip": "93.184.216.34", "dst_port": 443, "proto": "tcp",
            "traffic_type": "benign", "payload_hex": "47455420",  # "GET "
            "task_id": "", "channel": "https",
            "user_agent": random.choice(BENIGN_UAS), "role": "benign",
            "ts": ts,
        }
    if kind < 0.80:  # DNS
        return {
            "src_ip": _rand_host(), "src_port": random.randint(1024, 65535),
            "dst_ip": "8.8.8.8", "dst_port": 53, "proto": "udp",
            "traffic_type": "benign", "payload_hex": "0100", "task_id": "",
            "dns_qname": _rand_qname(), "channel": "dns",
            "user_agent": "", "role": "benign", "ts": ts,
        }
    # random TCP chatter
    return {
        "src_ip": _rand_host(), "src_port": random.randint(1024, 65535),
        "dst_ip": _rand_host(), "dst_port": random.choice([22, 80, 443, 3306, 5432]),
        "proto": "tcp", "traffic_type": "benign", "payload_hex": os.urandom(24).hex(),
        "task_id": "", "channel": "tcp", "user_agent": "", "role": "benign",
        "ts": ts,
    }


class BenignTraffic:
    def __init__(self, rate: float, bus: EventBus):
        self.bus = bus
        self.interval = 1.0 / max(rate, 0.01)
        self.stop_flag = threading.Event()
        self.generated = 0
        self._thread: threading.Thread | None = None

    def run(self, duration: float) -> None:
        deadline = time.time() + duration
        accumulator_backlog = 0.0
        while not self.stop_flag.is_set() and time.time() < deadline:
            start = time.time()
            accumulator_backlog += self.interval
            while accumulator_backlog > 0:
                self.bus.push(_benign_event(start))
                self.generated += 1
                accumulator_backlog -= self.interval
            time.sleep(min(max(0.0, deadline - start + 0.005), 0.05))

    def start(self, duration: float):
        self._thread = threading.Thread(target=self.run, args=(duration,), daemon=True)
        self._thread.start()

    def stop(self):
        self.stop_flag.set()