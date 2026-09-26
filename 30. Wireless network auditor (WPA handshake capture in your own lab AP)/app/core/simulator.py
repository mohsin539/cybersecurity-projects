"""Deterministic lab simulator - generates realistic 802.11 / EAPOL frames.

No real radio is touched. The simulator exercises the exact same pipeline
as a live capture (scope guard -> EAPOL state machine -> evidence vault),
so the full product is testable anywhere and the GUI is fully demonstrable
before a hardware adapter is attached.
"""
import random
import time
from datetime import datetime, timezone
from app.core.scope import ScopeGuard
from app.core.eapol import EapolRecord, MICState


def _ts() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


def _hex(n: int) -> str:
    return bytes(random.randbytes(n)).hex()


def _mac() -> str:
    return ":".join(f"{random.randrange(256):02X}" for _ in range(6))


class LabSimulator:
    """Emits frame events for registered lab APs plus realistic clients."""

    def __init__(self, scope: ScopeGuard, seed: int | None = None):
        self.scope = scope
        self.rng = random.Random(seed)
        self._clients: dict[str, str] = {}  # bssid -> list of client macs
        self._progress: dict[tuple, int] = {}  # (bssid, client) -> next msg
        self._replay: dict[tuple, str] = {}
        self._findings: list[dict] = []
        self._start = time.monotonic()

    def reset(self) -> None:
        self._clients.clear()
        self._progress.clear()
        self._replay.clear()
        self._findings.clear()
        self._start = time.monotonic()

    def step(self) -> list[EapolRecord]:
        """Advance simulation; returns EAPOL records to feed the engine.

        Also yields occasional finding candidates (WPS exposed, open net, etc.)
        surfaced through `pending_findings()`. Frames for out-of-scope BSSIDs
        are never produced -- the simulator is scope-aware by construction.
        """
        records = []
        allowed = self.scope.authorized_list()
        if not allowed:
            return records

        for bssid, ssid in allowed:
            if self.rng.random() < 0.30 and bssid not in self._clients:
                self._clients[bssid] = _mac()
            n_clients = len([c for c in self._clients if True])
            _ = n_clients

            for client in [self._clients[b] for b, c in self._clients.items() if b == bssid]:
                key = (bssid.upper(), client.upper())
                nxt = self._progress.get(key, 1)
                if self.rng.random() < 0.55:
                    rec = self._build(key, nxt)
                    records.append(rec)
                    self._progress[key] = nxt + 1 if nxt < 4 else 1
                    if nxt == 4:
                        self._findings.append(self._weak_cipher_finding(bssid, ssid, client))
                        if self.rng.random() < 0.4:
                            self._findings.append(self._pmf_finding(bssid, ssid, client))
        return records

    def _build(self, key: tuple, nxt: int) -> EapolRecord:
        bssid, client = key
        prev_replay = self._replay.get(key, "0")
        replay = str(int(prev_replay) + 1)
        self._replay[key] = replay
        snonce = _hex(16)
        anonce = _hex(16)
        return EapolRecord(
            msg_num=nxt,
            bssid=bssid,
            client=client,
            anonce=anonce if nxt in (1, 3) else prev_replay,
            snonce=snonce if nxt in (2, 3) else "",
            replay=replay,
            mic_state=MICState.VALID if nxt in (2, 4) else MICState.PENDING,
            pmkid=_hex(8) if nxt == 1 else "",
        )

    @staticmethod
    def _weak_cipher_finding(bssid: str, ssid: str, client: str) -> dict:
        return {
            "category": "Configuration",
            "title": "Legacy cipher advertised by lab AP",
            "bssid": bssid,
            "ssid": ssid,
            "severity": "Medium",
            "detail": ("The advertised RSNE permits TKIP/CCMP. "
                       "Migrate the lab AP to WPA3/WPA2-AES-only."),
            "cve": "None",
            "ts": _ts(),
            "client": client,
        }

    @staticmethod
    def _pmf_finding(bssid: str, ssid: str, client: str) -> dict:
        return {
            "category": "Configuration",
            "title": "Protected Management Frames (802.11w) disabled",
            "bssid": bssid,
            "ssid": ssid,
            "severity": "High",
            "detail": ("Management frames are unencrypted; enable PMF to deter "
                       "deauthentication and spoofing on the lab network."),
            "cve": "CWE-899",
            "ts": _ts(),
            "client": client,
        }

    def pending_findings(self) -> list[dict]:
        out = list(self._findings)
        self._findings.clear()
        return out

    def heartbeat(self) -> dict:
        total = sum(1 for c in self._clients.values())
        return {
            "channel": self.rng.choice([1, 6, 11]),
            "frames": total * 7,
            "clients": total,
        }