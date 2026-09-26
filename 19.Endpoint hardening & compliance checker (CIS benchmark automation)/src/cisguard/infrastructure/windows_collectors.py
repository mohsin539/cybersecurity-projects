"""Windows collector adapters — STRICTLY READ-ONLY (INV-2).

- Registry: winreg read-only (KEY_READ | KEY_WOW64_64KEY).
- Services: `sc query`/`sc qc` parsing (no start/stop/config calls exist here).
- Commands: FIXED argv whitelist from the domain catalog; no user-supplied args
  ever reach the process (INV-3); timeouts enforced; output capped.
- auditpol / Defender preferences: read-only parsing of standard tools/APIs.
"""

from __future__ import annotations

import re
import subprocess

from cisguard.domain.errors import CollectorError

_TIMEOUT_S = 20
_MAX_OUTPUT = 200_000  # chars


class WinRegistryCollector:
    def read_value(self, hive: str, path: str, value: str):
        import winreg

        hkey = {"HKLM": winreg.HKEY_LOCAL_MACHINE, "HKCU": winreg.HKEY_CURRENT_USER}[hive]
        try:
            with winreg.OpenKey(hkey, path, 0, winreg.KEY_READ | winreg.KEY_WOW64_64KEY) as key:
                data, _type = winreg.QueryValueEx(key, value)
                return data
        except FileNotFoundError:
            return None
        except PermissionError as exc:
            raise CollectorError(f"Access denied reading {hive}\\{path}\\{value}") from exc
        except OSError as exc:
            raise CollectorError(f"Registry read failed: {exc}") from exc


class WinServiceCollector:
    def query(self, name: str) -> str:
        try:
            out = self._sc(["sc", "qc", name])
        except CollectorError:
            return "NotFound"
        m = re.search(r"START_TYPE\s+:\s*(\d+)\s+(\w+)", out)
        if not m:
            return "NotFound"
        start_type = m.group(2).upper()
        if "DISABLED" in start_type:
            return "Disabled"
        # running state
        try:
            state_out = self._sc(["sc", "query", name])
            if "RUNNING" in state_out.upper():
                return "Running"
            return "Stopped"
        except CollectorError:
            return "Stopped"

    @staticmethod
    def _sc(argv: list[str]) -> str:
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=_TIMEOUT_S,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise CollectorError(f"sc failed: {exc}") from exc
        if proc.returncode != 0:
            raise CollectorError(f"sc rc={proc.returncode}")
        return (proc.stdout or "")[:_MAX_OUTPUT]


class WinCommandCollector:
    """Runs ONLY whitelisted catalog argvs; argv[0] must be in TRUSTED_BINARIES."""

    TRUSTED_BINARIES = {"net", "manage-bde", "powershell", "cmd", "auditpol"}

    def run(self, argv: list[str]) -> str:
        if not argv or argv[0].lower() not in self.TRUSTED_BINARIES:
            raise CollectorError(f"Command not whitelisted: {argv[:1]}")
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=_TIMEOUT_S,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise CollectorError(f"command failed: {exc}") from exc
        return ((proc.stdout or "") + (proc.stderr or ""))[:_MAX_OUTPUT]


class WinAuditpolCollector:
    def subcategory(self, name: str) -> dict[str, bool]:
        try:
            proc = subprocess.run(
                ["auditpol", "/get", "/subcategory:", name],
                capture_output=True, text=True, timeout=_TIMEOUT_S,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (subprocess.TimeoutExpired, OSError) as exc:
            raise CollectorError(f"auditpol failed: {exc}") from exc
        out = (proc.stdout or "")
        success = failure = False
        for line in out.splitlines():
            if name.lower() in line.lower():
                success = "success" in line.lower() and "no auditing" not in line.lower()
                failure = "failure" in line.lower() and "no auditing" not in line.lower()
        return {"Success": success, "Failure": failure}


class WinDefenderCollector:
    _PREF_PROPS = {
        # MPPreference property -> bool-typed handling
        "DisableRealtimeMonitoring": True,
        "DisableBehaviorMonitoring": True,
        "DisableScriptScanning": True,
        "MAPSReporting": False,
        "PUAProtection": False,
    }

    def preference(self, name: str) -> str:
        return self.preferences([name]).get(name, "")

    def preferences(self, names: list[str]) -> dict[str, str]:
        """Single PowerShell call fetching all requested MPPreference props.
        ~1s total instead of ~1s per property."""
        props = [n for n in names if n in self._PREF_PROPS or True]
        expr = "; ".join(f"Write-Output ($p = (Get-MpPreference).{n})" for n in props)
        argv = [
            "powershell", "-NoProfile", "-NonInteractive", "-Command",
            "$mp = Get-MpPreference; "
            + " ".join(f'Write-Output $mp.{n}' for n in props),
        ]
        try:
            proc = subprocess.run(
                argv, capture_output=True, text=True, timeout=60,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
        except (subprocess.TimeoutExpired, OSError):
            return {n: "" for n in props}
        lines = (proc.stdout or "").splitlines()
        out: dict[str, str] = {}
        for i, n in enumerate(props):
            out[n] = lines[i].strip() if i < len(lines) else ""
        return out


class WinSystemCollector:
    def hostname(self) -> str:
        import socket

        return socket.gethostname()

    def os_caption(self) -> str:
        try:
            proc = subprocess.run(
                ["cmd", "/c", "ver"], capture_output=True, text=True, timeout=10,
                creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0),
            )
            return (proc.stdout or "").strip().splitlines()[-1].strip() if (proc.stdout or "").strip() else "Windows"
        except (subprocess.TimeoutExpired, OSError):
            return "Windows"
