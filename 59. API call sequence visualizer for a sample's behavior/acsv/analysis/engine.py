"""Analysis engine (architecture §5.2/§5.4).

Produces statistics, sequence summaries, call-graph edges and a small set of
anomaly findings (severity-tagged) from the event store. Every finding is
carries OWASP/A.control tags consumed by the Compliance Console.
"""

from __future__ import annotations

import collections
import statistics
from dataclasses import dataclass, field

SUSPICIOUS_CHAINS = [
    ("CreateProcessW", "VirtualProtectEx", "WriteProcessMemory", "CreateRemoteThread"),
    ("OpenProcess", "VirtualAllocEx", "WriteProcessMemory", "CreateRemoteThread"),
    ("GetProcAddress", "LoadLibraryExW", "CreateRemoteThread"),
]
SUSPICIOUS_APIS = {"CreateRemoteThread", "WriteProcessMemory", "VirtualProtectEx",
                   "RegSetValueExW", "NtCreateFile"}


@dataclass
class Finding:
    title: str
    severity: str  # info | low | medium | high | critical
    description: str
    seq_range: tuple[int, int] | None = None
    tags: list[str] = field(default_factory=list)


class AnalysisEngine:
    def __init__(self, store) -> None:
        self.store = store

    def analyze(self, session_id: str) -> dict:
        events = self.store.iter_events(session_id)
        return self._compute(events, session_id)

    def _compute(self, events: list[dict], session_id: str) -> dict:
        counts = collections.Counter(e["api"] for e in events)
        cats = collections.Counter(e["category"] for e in events)
        statuses = collections.Counter(e.get("status", "UNKNOWN") for e in events)
        by_thread: dict[int, int] = {}
        for e in events:
            by_thread[e["tid"]] = by_thread.get(e["tid"], 0) + 1
        seqs = [e["seq"] for e in events]
        edges: list[tuple[str, str, int]] = self._compute_edges(events)
        findings = self._detect(events, edges)
        rate = 0.0
        if len(events) >= 2:
            span = (events[-1]["ts_ns"] - events[0]["ts_ns"]) / 1e9
            if span > 0:
                rate = len(events) / span
        return {
            "session_id": session_id,
            "event_count": len(events),
            "unique_apis": len(counts),
            "top_apis": counts.most_common(25),
            "categories": dict(cats),
            "statuses": dict(statuses),
            "threads": dict(by_thread),
            "seq_min": min(seqs) if seqs else 0,
            "seq_max": max(seqs) if seqs else 0,
            "calls_per_second": round(rate, 1),
            "edges": edges,
            "findings": [f.__dict__ for f in findings],
            "high_value_ops": self._high_value(counts),
        }

    def _compute_edges(self, events: list[dict]) -> list[tuple[str, str, int]]:
        cnt: dict[tuple[str, str], int] = collections.Counter()
        by_thread: dict[int, str] = {}
        for e in events:
            prev = by_thread.get(e["tid"])
            if prev and prev != e["api"]:
                cnt[(prev, e["api"])] += 1
            by_thread[e["tid"]] = e["api"]
        return [(a, b, c) for (a, b), c in cnt.most_common(200)]

    def _detect(self, events: list[dict], edges) -> list[Finding]:
        findings: list[Finding] = []
        apis = [e["api"] for e in events]
        # Process injection sequence detection
        for chain in SUSPICIOUS_CHAINS:
            idx = self._index_of_subseq(apis, chain)
            if idx is None:
                continue
            first = events[idx]["seq"]
            last = events[idx + len(chain) - 1]["seq"]
            findings.append(Finding(
                title="Injection chain detected",
                severity="high",
                description="Sequence matched: " + " > ".join(chain),
                seq_range=(first, last),
                tags=["OWASP-A04", "A.5.28", "CWE-787"],
            ))
        # Thread spawn without matching process lifecycle
        remote_threads = [e for e in events if e["api"] == "CreateRemoteThread"]
        if remote_threads:
            findings.append(Finding(
                title="CreateRemoteThread used",
                severity="medium",
                description=f"{len(remote_threads)} remote thread creation(s)",
                seq_range=(remote_threads[0]["seq"], remote_threads[-1]["seq"]),
                tags=["OWASP-A04", "CWE-787"],
            ))
        # Writes to Run key
        if any(e["api"] == "RegSetValueExW" and "Run" in str(e.get("args", {}).get("SubKey", ""))
               for e in events):
            findings.append(Finding(
                title="Persistence (Run key) write",
                severity="medium",
                description="Registry Run key modified",
                tags=["A.5.24", "A.5.26", "CWE-154"],
            ))
        # Internal target network connections
        if any(e["api"] == "WSAConnect" and str(e.get("args", {}).get("Addr", "")).startswith(("10.", "192.168.", "172."))
               for e in events):
            findings.append(Finding(
                title="Connection to private-range host",
                severity="low",
                description="Sample attempted private-network connections",
                tags=["OWASP-A10"],
            ))
        if not findings:
            findings.append(Finding(
                title="No high-severity deviation",
                severity="info",
                description="Behavior corpus within expected envelope",
                tags=["A.5.24"],
            ))
        # Modules touched
        mods = {e.get("module") for e in events if e.get("module")}
        if mods:
            findings.append(Finding(
                title="Module usage summary",
                severity="info",
                description="Modules: " + ", ".join(sorted(mods)),
                tags=["A.5.9"],
            ))
        return findings

    def _index_of_subseq(self, seq: list[str], sub: tuple[str, ...]) -> int | None:
        n, m = len(seq), len(sub)
        for i in range(n - m + 1):
            if tuple(seq[i : i + m]) == sub:
                return i
        return None

    @staticmethod
    def _high_value(counts: collections.Counter) -> dict[str, int]:
        return {k: v for k, v in counts.items() if k in SUSPICIOUS_APIS}