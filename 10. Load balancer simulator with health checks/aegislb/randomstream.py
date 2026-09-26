from __future__ import annotations

import random
import hashlib


class RngStream:
    def __init__(self, seed: int):
        self._master = random.Random(seed)

    def child(self, label: str):
        d = hashlib.sha256(label.encode("utf-8")).digest()
        s = int.from_bytes(d[:4], "big")
        return random.Random((self._master.randrange(0, 2**32)) ^ s)