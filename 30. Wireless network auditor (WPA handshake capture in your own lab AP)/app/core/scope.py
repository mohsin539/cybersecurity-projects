"""Lab scope enforcement - A05/A04 mitigation.

The auditor only ever records frames whose BSSID matches a registered
lab access point. Everything else is discarded at the source, never
touching storage or reports.
"""
import re

MAC_RE = re.compile(r"^([0-9A-F]{2}:){5}[0-9A-F]{2}$", re.I)


class ScopeViolation(Exception):
    pass


class ScopeGuard:
    """Central allow-list enforced by the engine before any record exists."""

    def __init__(self):
        self._allowed: dict[str, str] = {}  # bssid(up) -> ssid

    def register(self, bssid: str, ssid: str) -> None:
        b = self._norm_mac(bssid)
        self._allowed[b] = ssid

    def remove(self, bssid: str) -> None:
        self._allowed.pop(self._norm_mac(bssid), None)

    def is_authorized(self, bssid: str) -> bool:
        return self._norm_mac(bssid) in self._allowed

    def ssid_for(self, bssid: str) -> str | None:
        return self._allowed.get(self._norm_mac(bssid))

    def describe(self, bssid: str, ssid: str) -> None:
        """Raise if not in scope; canonicalize ssid."""
        if not self.is_authorized(bssid):
            raise ScopeViolation(
                f"BSSID {bssid} is outside the registered lab scope and was dropped.")

    def authorized_list(self) -> list[tuple[str, str]]:
        return sorted((b, s) for b, s in self._allowed.items())

    @staticmethod
    def _norm_mac(mac: str) -> str:
        if not MAC_RE.match(mac):
            raise ValueError(f"Invalid BSSID format: {mac!r}")
        return mac.upper()