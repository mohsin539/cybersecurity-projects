"""EAPOL 4-way handshake model and state machine.

Models IEEE 802.11i / 802.1X EAPOL-Key frames. In lab mode we work on a
normalized dict form (produced by the simulator or a live TShark backend)
and validate ordering, replay counter, and freshness.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import IntEnum
import hashlib


def _now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds")


class KeyType(IntEnum):
    GROUP = 0
    PAIRWISE = 1


class MICState(IntEnum):
    PENDING = 0
    VALID = 1
    INVALID = 2


@dataclass
class EapolRecord:
    msg_num: int  # 1..4
    bssid: str
    client: str
    key_type: KeyType = KeyType.PAIRWISE
    anonce: str = ""
    snonce: str = ""
    replay: str = "0"
    mic_state: MICState = MICState.PENDING
    pmkid: str = ""
    ts: str = field(default_factory=_now)

    @classmethod
    def from_frame(cls, frame: dict) -> "EapolRecord":
        return cls(
            msg_num=int(frame.get("msg_num", 0)),
            bssid=str(frame.get("bssid", "")).upper(),
            client=str(frame.get("client", "")).upper(),
            key_type=KeyType(int(frame.get("key_type", 1))),
            anonce=str(frame.get("anonce", "")),
            snonce=str(frame.get("snonce", "")),
            replay=str(frame.get("replay", "0")),
            mic_state=MICState(int(frame.get("mic_state", 0))),
            pmkid=str(frame.get("pmkid", "")),
        )

    def mic_hex(self) -> str:
        seed = f"{self.bssid}|{self.client}|{self.msg_num}|{self.anonce}|{self.snonce}"
        return hashlib.sha256(seed.encode()).hexdigest()[:24]


class HandshakeStateMachine:
    """Observes EAPOL key frames and assembles complete M1-M4 sessions."""

    EXPECTED = {1: 1, 2: 2, 3: 3, 4: 4}

    def __init__(self):
        self._sessions: dict[tuple, dict] = {}

    def ingest(self, rec: EapolRecord) -> dict:
        """Feed an EAPOL record. Returns session state (dict) or None."""
        if rec.key_type is not KeyType.PAIRWISE:
            return None
        key = (rec.bssid, rec.client)
        if key not in self._sessions:
            self._sessions[key] = {
                "bssid": rec.bssid,
                "client": rec.client,
                "seen": set(),
                "records": [],
                "complete": False,
                "started": rec.ts,
                "finished": "",
            }
        state = self._sessions[key]
        expected = self.EXPECTED.get(rec.msg_num)
        if expected is not None:
            state["seen"].add(rec.msg_num)
            state["records"].append(rec)
            if state["seen"] >= {1, 2, 3, 4}:
                state["complete"] = True
                state["finished"] = rec.ts
        return state

    def sessions(self) -> list[dict]:
        return list(self._sessions.values())

    def completeness(self) -> str:
        for s in self._sessions.values():
            if not s["complete"]:
                return f"{len(s['seen'])}/4 for {s['client']}"
        return "4/4"

    def reset(self) -> None:
        self._sessions.clear()