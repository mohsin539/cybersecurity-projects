"""Lab orchestration - one full lab run (architecture section 4 data flow).

Steps: configure -> spawn C2 server -> spawn agent fleet + benign noise ->
capture event stream for run_duration -> run Zeek + Suricata detection ->
grade vs ground truth -> generate reports -> write SHA-256 audit evidence.
"""

from __future__ import annotations

import threading
import time

from core.audit import Auditor
from core.config import LabConfig
from c2_sim.agent import AgentFleet
from c2_sim.bus import EventBus
from c2_sim.server import C2Server
from c2_sim.traffic import BenignTraffic
from detectors.engine import RunMetrics, run_detection
from detectors.suricata import generate_suricata
from detectors.zeek import generate_zeek


class LabRunner:
    def __init__(self, cfg: LabConfig | None = None):
        self.cfg = cfg or LabConfig()
        self.bus = EventBus()
        self.auditor = Auditor(self.cfg.out_path / "evidence")
        self.metrics: RunMetrics | None = None
        self.alerts: list[dict] = []
        self.status = "idle"
        self._thread: threading.Thread | None = None
        self._cancel = threading.Event()

    # ------------------------------------------------------------------ #
    def run(self) -> dict:
        """Synchronous full lab run (called by GUI thread worker)."""
        self._cancel.clear()
        issues = self.cfg.validate()
        if issues:
            raise ValueError("; ".join(issues))
        self.status = "configuring"
        self.cfg.out_path.mkdir(parents=True, exist_ok=True)
        cfg_file = self.cfg.save()
        self.auditor.log("lab_configured", str(cfg_file), str(cfg_file))

        # L2 - build the threat ----------------------------------------- #
        self.status = "starting_c2"
        server = C2Server(self.cfg.server_host, self.cfg.server_port,
                          user_agent=self.cfg.user_agent, bus=self.bus)
        port = server.start()
        self.cfg.server_port = port
        fleet = AgentFleet(self.cfg, self.bus)
        noise = BenignTraffic(self.cfg.benign_rate, self.bus)

        # signature generation (L3 artifact step) ------------------------ #
        self.status = "writing_signatures"
        zeek_file = generate_zeek(self.cfg.detection_dir, self.cfg.beacon_interval)
        suri_file = generate_suricata(self.cfg.detection_dir)
        self.auditor.log("signatures_generated", zeek_file.name, str(zeek_file))
        self.auditor.log("signatures_generated", suri_file.name, str(suri_file))

        # L2 -> capture --------------------------------------------------- #
        self.status = "running"
        fleet.spawn()
        noise.start(self.cfg.run_duration)
        deadline = time.time() + self.cfg.run_duration
        while time.time() < deadline:
            if self._cancel.is_set():
                break
            time.sleep(0.25)
        fleet.stop()
        noise.stop()
        server.stop()
        self.status = "detecting"
        time.sleep(0.2)

        # L3 detection + L4 correlation ---------------------------------- #
        events = self.bus.snapshot()
        self.alerts, self.metrics = run_detection(events)
        self.status = "reporting"

        # L5 evidence chain ----------------------------------------------- #
        self.cfg.out_path.joinpath("pcap").mkdir(parents=True, exist_ok=True)
        pcap = self.cfg.out_path.joinpath("pcap").joinpath(f"{self.cfg.run_id}.jsonl")
        import json
        with pcap.open("w", encoding="utf-8") as fh:
            for ev in events:
                fh.write(json.dumps(ev) + "\n")
        self.auditor.log("traffic_captured", f"{len(events)} events", str(pcap))

        result = {
            "run_id": self.cfg.run_id,
            "config": self.cfg.to_dict(),
            "metrics": self.metrics.to_dict(),
            "alerts": self.alerts,
            "events": events,
            "signatures": {"zeek": str(zeek_file), "suricata": str(suri_file)},
        }
        self.auditor.write()
        self.status = "idle"
        return result

    def run_async(self, on_done=None, on_error=None):
        """Background threaded run; GUI stays responsive."""
        def _worker():
            try:
                out = self.run()
                if on_done:
                    on_done(out)
            except Exception as exc:  # noqa: BLE001 - surface to GUI
                self.status = "error"
                if on_error:
                    on_error(exc)
                else:
                    raise
        self._thread = threading.Thread(target=_worker, daemon=True,
                                        name="lab-runner")
        self._thread.start()

    def cancel(self):
        self._cancel.set()

    @property
    def running(self) -> bool:
        return self.status not in ("idle", "error")