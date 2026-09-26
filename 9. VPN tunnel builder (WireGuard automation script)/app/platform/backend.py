"""WireGuard backend abstraction (ports & adapters / hexagonal).

* LocalBackend     — real `wg` / `wg-quick` via subprocess (Linux/macOS).
* SimulatorBackend — deterministic in-process simulation for Windows, demos,
                     CI, and development. Clearly flagged as simulated.
* detect_backend() — picks local when `wg` is found, else simulator; honours
                     the `backend` setting (auto|local|simulator|dry-run).

Security rules (NAM A03 / ISO A.8.28): subprocesses are invoked with argument
**arrays** (no shell), and every user-derived string (interface, key) has been
validated by the core.validate module before it can reach this layer.
"""

from __future__ import annotations

import json
import shutil
import socket
import subprocess
import time
from dataclasses import dataclass, field
from pathlib import Path

from ..core.crypto import utc_now_iso
from ..persistence.store import StateStore

DEFAULT_WG_PORT = 51820


def _run(args: list[str], timeout: float = 10) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
        return proc.returncode, proc.stdout.strip(), proc.stderr.strip()
    except FileNotFoundError:
        return 127, "", "command not found"
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"


@dataclass
class BackendResult:
    ok: bool
    message: str
    extra: dict = field(default_factory=dict)


class BaseBackend:
    name = "abstract"
    is_simulated = False

    def available(self) -> bool:
        return True

    def get_status(self, interface: str) -> dict:
        raise NotImplementedError

    def up(self, conf_path: Path, interface: str) -> BackendResult:
        raise NotImplementedError

    def down(self, interface: str, conf_path: Path | None = None) -> BackendResult:
        raise NotImplementedError

    def reload(self, conf_path: Path, interface: str) -> BackendResult:
        raise NotImplementedError

    def preflight(self, interface: str, listen_port: int) -> list[str]:
        issues: list[str] = []
        if len(interface) > 15:
            issues.append("interface name longer than 15 characters")

        def _port_free(port: int) -> bool:
            probes = [socket.AF_INET, socket.AF_INET6]
            for family in probes:
                try:
                    with socket.socket(family, socket.SOCK_DGRAM) as s:
                        s.bind(("", port))
                    return True
                except OSError:
                    return False
            return False

        if not _port_free(listen_port):
            issues.append(f"UDP port {listen_port} already in use on this host")
        return issues


class LocalBackend(BaseBackend):
    name = "local"
    is_simulated = False

    def __init__(self):
        self._wg = shutil.which("wg")
        self._wg_quick = shutil.which("wg-quick")

    def available(self) -> bool:
        return self._wg is not None and self._wg_quick is not None

    def _parse_dump(self, dump: str) -> dict:
        lines = [l for l in dump.splitlines() if l.strip()]
        status: dict = {"running": True, "interface": {}}
        peers: list[dict] = []
        first = True
        for line in lines:
            parts = line.split("\t")
            if first and len(parts) >= 3:
                status["interface"] = {
                    "private_key": "REDACTED",
                    "public_key": parts[1],
                    "listen_port": parts[2],
                    "fwmark": parts[3] if len(parts) > 3 else "",
                }
                first = False
                continue
            if len(parts) >= 7:
                peers.append({
                    "public_key": parts[0],
                    "preshared": (parts[1] and parts[1] != "(none)"),
                    "endpoint": parts[2],
                    "allowed_ips": parts[3].split(",") if parts[3] else [],
                    "latest_handshake": self._human_age(int(parts[4])) if parts[4].isdigit() else "-",
                    "transfer_rx": self._human_bytes(int(parts[5])) if parts[5].isdigit() else "0",
                    "transfer_tx": self._human_bytes(int(parts[6])) if parts[6].isdigit() else "0",
                    "keepalive": parts[7] if len(parts) > 7 else "",
                })
        status["peers"] = peers
        return status

    @staticmethod
    def _human_age(seconds: int) -> str:
        if seconds <= 0:
            return "never"
        m, s = divmod(seconds, 60)
        h, m = divmod(m, 60)
        return f"{h}h{m}m{s}s"

    @staticmethod
    def _human_bytes(value: int) -> str:
        for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
            if abs(value) < 1024 or unit == "TiB":
                return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
            value /= 1024
        return f"{value:.1f} TiB"

    def get_status(self, interface: str) -> dict:
        rc, out, err = _run([self._wg, "show", interface, "dump"])
        if rc != 0:
            return {"running": False, "error": err or f"interface {interface} not found",
                    "peers": []}
        status = self._parse_dump(out)
        status["is_simulated"] = False
        return status

    def up(self, conf_path: Path, interface: str) -> BackendResult:
        rc, out, err = _run([self._wg_quick, "up", str(conf_path)])
        if rc != 0:
            return BackendResult(False, err or "wg-quick failed", {"output": out})
        return BackendResult(True, f"interface {interface} is up")

    def down(self, interface: str, conf_path: Path | None = None) -> BackendResult:
        rc, out, err = _run([self._wg_quick, "down", interface])
        if rc != 0:
            return BackendResult(False, err or "wg-quick down failed", {"output": out})
        return BackendResult(True, f"interface {interface} is down")

    def reload(self, conf_path: Path, interface: str) -> BackendResult:
        # wg syncconf <iface> <conf> — applies config to a live interface
        rc, out, err = _run([self._wg, "syncconf", interface, str(conf_path)], timeout=15)
        if rc != 0:
            return BackendResult(False, err or "wg syncconf failed", {"output": out})
        return BackendResult(True, f"interface {interface} config synchronised")


class SimulatorBackend(BaseBackend):
    name = "simulator"
    is_simulated = True

    def __init__(self, store: StateStore):
        self._store = store
        self._path = store.backend_status_file()

    def _load(self) -> dict:
        if self._path.exists():
            try:
                return json.loads(self._path.read_text(encoding="utf-8"))
            except (ValueError, OSError):
                pass
        return {}

    def _save(self, status: dict) -> None:
        self._path.write_text(json.dumps(status, indent=2, sort_keys=True), encoding="utf-8")

    def _peers_status(self, interface: str) -> list[dict]:
        all_peers = [p for p in self._store.load_state().get("peers", [])
                     if p.get("tunnel") == interface and p.get("enabled")]
        now = int(time.time())
        out: list[dict] = []
        for idx, peer in enumerate(all_peers):
            last_handshake = now - (idx + 1) * 23          # simulated drift
            rx = 1024 * 1024 * (idx + 3)
            tx = 512 * 1024 * (idx + 1)
            out.append({
                "public_key": peer.get("public_key", ""),
                "preshared": bool(peer.get("preshared")),
                "endpoint": peer.get("endpoint", ""),
                "allowed_ips": peer.get("allowed_ips", []),
                "latest_handshake": f"{self._human_age(now - last_handshake)} ago",
                "transfer_rx": self._human_bytes(rx),
                "transfer_tx": self._human_bytes(tx),
                "keepalive": peer.get("persistent_keepalive", 0),
                "simulated": True,
            })
        return out

    @staticmethod
    def _human_age(seconds: int) -> str:
        m, s = divmod(seconds, 60)
        h, m = divmod(m, 60)
        return f"{h}h{m}m{s}s"

    @staticmethod
    def _human_bytes(value: int) -> str:
        for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
            if abs(value) < 1024 or unit == "TiB":
                return f"{value:.1f} {unit}" if unit != "B" else f"{int(value)} B"
            value /= 1024
        return f"{value:.1f} TiB"

    def get_status(self, interface: str) -> dict:
        status = self._load().get(interface)
        if not status or status.get("running") is False:
            return {"running": False, "error": "interface is not running (simulated)",
                    "peers": [], "is_simulated": True}
        return {
            "running": True,
            "interface": {"public_key": "SIMULATED", "listen_port": status.get("port", 51820),
                          "private_key": "REDACTED"},
            "peers": self._peers_status(interface),
            "is_simulated": True,
            "started_at": status.get("started_at"),
        }

    def up(self, conf_path: Path, interface: str) -> BackendResult:
        status = self._load()
        status[interface] = {"running": True, "port": 51820,
                             "started_at": utc_now_iso(), "conf": conf_path.name}
        self._save(status)
        return BackendResult(True, f"interface {interface} is up (simulated)")

    def down(self, interface: str, conf_path: Path | None = None) -> BackendResult:
        status = self._load()
        if interface in status:
            status[interface]["running"] = False
        self._save(status)
        return BackendResult(True, f"interface {interface} is down (simulated)")

    def reload(self, conf_path: Path, interface: str) -> BackendResult:
        status = self._load()
        if interface in status:
            status[interface].update({"conf": conf_path.name})
        self._save(status)
        return BackendResult(True, f"config synchronised (simulated): {conf_path.name}")


def detect_backend(store: StateStore, setting: str = "auto") -> BaseBackend:
    if setting == "local":
        return LocalBackend()
    if setting in ("simulator", "dry-run"):
        return SimulatorBackend(store)
    local = LocalBackend()
    if local.available():
        return local
    return SimulatorBackend(store)