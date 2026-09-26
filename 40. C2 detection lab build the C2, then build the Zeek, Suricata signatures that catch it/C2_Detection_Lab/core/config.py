"""Lab configuration model (architecture.md section 1 - L1/L2 builder profile)."""

from __future__ import annotations

import json
import random
import string
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path

DEFAULT_OUTDIR = Path("labs") / f"run_{time.strftime('%Y%m%d_%H%M%S')}"


@dataclass
class LabConfig:
    """Everything needed to build the C2 and run one detection pass.

    Mirrors `config/lab.json` in the architecture blueprint.
    """

    run_id: str = field(default_factory=lambda: time.strftime("run_%Y%m%d_%H%M%S"))
    beacon_interval: float = 5.0          # seconds between beacons (30-300 is real-world)
    jitter_pct: float = 20.0              # % randomness applied to interval
    sleep_window: float = 0.0             # optional deep-sleep phase before beaconing
    channel: str = "http"                 # http | https | dns
    server_host: str = "127.0.0.1"
    server_port: int = 0                  # 0 => ephemeral port chosen by OS
    agent_count: int = 3
    run_duration: float = 30.0            # lab duration in seconds
    benign_rate: float = 2.0              # benign noise events per second (precision tuning)
    user_agent: str = "Mozilla/5.0 (Windows NT 10.0) AppleWebKit/537.36 C2DetectLab/1.0"
    magic: str = "00 7f"                  # TLV magic byte-pattern -> Suricata content match
    outdir: str = str(DEFAULT_OUTDIR)
    detections_dir: str = "detections"    # where zeek/suricata artifacts are written
    pcap_dir: str = "pcap"

    # ------------------------------------------------------------------ #
    def to_dict(self) -> dict:
        return asdict(self)

    def save(self, path: Path | None = None) -> Path:
        target = (path or (self.out_path / "config")).with_suffix(".json")
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(
            json.dumps(self.to_dict(), indent=2), encoding="utf-8"
        )
        return target

    @property
    def out_path(self) -> Path:
        return Path(self.outdir)

    @property
    def detection_dir(self) -> Path:
        return self.out_path / self.detections_dir

    @property
    def pcap_path(self) -> Path:
        return self.out_path / self.pcap_dir

    @classmethod
    def load(cls, path: str | Path) -> "LabConfig":
        data = json.loads(Path(path).read_text(encoding="utf-8"))
        known = {f for f in cls.__dataclass_fields__} | {"run_id"}
        cfg = cls(**{k: v for k, v in data.items() if k in known})
        cfg.run_id = data.get("run_id", cfg.run_id)
        return cfg

    def jittered_interval(self) -> float:
        """Apply +/- jitter to the beacon interval (architecture L2)."""
        spread = self.beacon_interval * (self.jitter_pct / 100.0)
        return max(0.05, self.beacon_interval + random.uniform(-spread, spread))

    def random_taskid(self, length: int = 16) -> str:
        return "".join(random.choices(string.hexdigits.lower(), k=length))

    def validate(self) -> list[str]:
        """OWASP A03/A05 - sane default input validation."""
        issues: list[str] = []
        if not 0.5 <= self.beacon_interval <= 600:
            issues.append("beacon_interval must be 0.5-600 s")
        if not 0 <= self.jitter_pct <= 100:
            issues.append("jitter_pct must be 0-100")
        if self.agent_count < 1 or self.agent_count > 50:
            issues.append("agent_count must be 1-50")
        if self.benign_rate < 0 or self.benign_rate > 100:
            issues.append("benign_rate must be 0-100 events/s")
        if self.channel not in ("http", "https", "dns"):
            issues.append("channel must be http|https|dns")
        return issues