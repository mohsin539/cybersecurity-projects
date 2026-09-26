"""Shared report data bundle snapshot.
"""
from dataclasses import dataclass, field
from datetime import datetime, timezone

from app.data.vault import EvidenceVault


@dataclass
class ReportData:
    generated_at: str
    app_version: str
    backend: str
    aps: list
    clients: list
    sessions: list
    findings: list
    audit: list
    chain: dict
    stats: dict

    @classmethod
    def from_vault(cls, vault: EvidenceVault, backend: str = "sim") -> "ReportData":
        return cls(
            generated_at=datetime.now(timezone.utc).isoformat(timespec="seconds"),
            app_version="1.0.0",
            backend=backend,
            aps=vault.aps(),
            clients=vault.clients(),
            sessions=vault.sessions(),
            findings=vault.findings(),
            audit=vault.audit_log(40),
            chain=vault.chain_state(),
            stats={
                "aps": vault.ap_count(),
                "clients": vault.client_count(),
                "sessions": vault.session_count(),
                "complete": vault.complete_count(),
                "findings": vault.finding_count(),
            },
        )

    def severity_totals(self) -> dict[str, int]:
        out = {"Critical": 0, "High": 0, "Medium": 0, "Low": 0, "Info": 0}
        for f in self.findings:
            s = f.get("severity", "Info")
            out[s] = out.get(s, 0) + 1
        return out