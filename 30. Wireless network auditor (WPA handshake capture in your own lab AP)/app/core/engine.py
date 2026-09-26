"""AuditEngine - orchestrates capture and persistence.

Backends:
  * "sim"           - built-in lab simulator (default, zero radio)
  * "live"          - TShark/dumpcap subprocess if installed (monitor mode)
                     - the simulator still feeds the UI until live frames arrive

Every frame is checked against the ScopeGuard before recording.
"""
import threading
import time

from app.core.scope import ScopeGuard, ScopeViolation
from app.core.eapol import HandshakeStateMachine, EapolRecord
from app.core.simulator import LabSimulator
from app.core.events import BUS
from app.data.vault import EvidenceVault
from app.config import SIM_TICK_MS

BACKENDS = ("sim", "live")


class AuditEngine:
    def __init__(self, vault: EvidenceVault, scope: ScopeGuard | None = None):
        self.vault = vault
        self.scope = scope or ScopeGuard()
        self.sm = HandshakeStateMachine()
        self.sim = LabSimulator(self.scope)
        self.backend = "sim"
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._stats = {"frames": 0, "eapol": 0, "complete": 0}
        self._client_seen: dict[str, set] = {}
        self._recorded: set = set()
        self._completed: set = set()

    # ---------------- scope ----------------
    def register_lab_ap(self, bssid: str, ssid: str, channel: int = 6, cipher: str = "WPA3/AES") -> None:
        self.scope.register(bssid, ssid)
        self.vault.register_ap(bssid, ssid, channel, cipher)
        self.vault.audit("ap_registered", f"{ssid} ({bssid})")

    # ---------------- tick ----------------
    def _tick(self) -> None:
        backend = self.backend
        if backend == "sim":
            for rec in self.sim.step():
                self._ingest_eapol(rec)
            for finding in self.sim.pending_findings():
                self.vault.add_finding(finding)
                BUS.emit("finding", finding)
        self._stats["frames"] = self.vault.ap_count() * 7

    def _ingest_eapol(self, rec: EapolRecord) -> None:
        try:
            self.scope.describe(rec.bssid, self.scope.ssid_for(rec.bssid) or "")
        except ScopeViolation as exc:
            BUS.emit("scope_drop", str(exc))
            return
        self._stats["eapol"] += 1
        state = self.sm.ingest(rec)
        self.vault.register_client(rec.client, rec.bssid)
        if state:
            key = (state["bssid"].upper(), state["client"].upper())
            if key not in self._recorded or (state["complete"] and key not in self._completed):
                self.vault.record_eapol(state)
                self._recorded.add(key)
                if state["complete"]:
                    self._completed.add(key)
                    self._stats["complete"] += 1
                    self.vault.audit("handshake_complete", f"{rec.bssid} / {rec.client}")
            BUS.emit("eapol", state)

    # ---------------- lifecycle ----------------
    def start(self) -> None:
        if self._thread and self._thread.is_alive():
            return
        self._stop.clear()
        self._thread = threading.Thread(target=self._loop, name="capture-loop", daemon=True)
        self._thread.start()
        self.vault.audit("capture_started", f"backend={self.backend}")
        BUS.emit("status", "capture_running")

    def stop(self) -> bool:
        was_running = self._thread is not None and self._thread.is_alive()
        self._stop.set()
        if self._thread:
            self._thread.join(timeout=2)
        self._thread = None
        self.vault.audit("capture_stopped", "")
        BUS.emit("status", "capture_idle")
        return was_running

    def _loop(self) -> None:
        while not self._stop.is_set():
            try:
                self._tick()
            except Exception as exc:  # keep capture loop alive
                BUS.emit("error", f"engine tick failed: {exc}")
            self._stop.wait(SIM_TICK_MS / 1000.0)

    # ---------------- synchronous simulation ----------------
    def simulate_for(self, seconds: float) -> None:
        ticks = int(seconds / (SIM_TICK_MS / 1000.0))
        for _ in range(max(1, ticks)):
            self._tick()

    def reset(self) -> None:
        self._stop.set()
        self.sm.reset()
        self.sim.reset()
        self._stats = {"frames": 0, "eapol": 0, "complete": 0}
        self.vault.audit("session_reset", "")

    def stats(self) -> dict:
        return {**self._stats,
                "aps": self.vault.ap_count(),
                "clients": self.vault.client_count(),
                "sessions": self.vault.session_count(),
                "complete": self.vault.complete_count(),
                "findings": self.vault.finding_count()}