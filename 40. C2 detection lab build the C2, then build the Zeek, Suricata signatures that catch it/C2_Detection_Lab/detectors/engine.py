"""Detection orchestration, correlation and scoring (architecture L3->L4).

Consumes the event-bus stream, runs both engines, merges detections into a
single normalized record set, and grades them against ground truth labels to
produce precision / recall / F1 / alert latency (architecture section 4.5).
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from detectors.zeek import match_zeek
from detectors.suricata import match_suricata


@dataclass
class RunMetrics:
    total_events: int = 0
    c2_events: int = 0
    benign_events: int = 0
    tp: int = 0
    fp: int = 0
    fn: int = 0
    alerts: int = 0
    zeek_count: int = 0
    suricata_count: int = 0
    latency_sum: float = 0.0
    detected_per_agent: dict[str, int] = field(default_factory=dict)

    @property
    def precision(self) -> float:
        denom = self.tp + self.fp
        return round(self.tp / denom, 3) if denom else 0.0

    @property
    def recall(self) -> float:
        denom = self.tp + self.fn
        return round(self.tp / denom, 3) if denom else 0.0

    @property
    def f1(self) -> float:
        p, r = self.precision, self.recall
        if p + r == 0:
            return 0.0
        return round(2 * p * r / (p + r), 3)

    @property
    def accuracy(self) -> float:
        return round((self.tp + (self.benign_events - self.fp)) /
                     max(1, self.total_events), 3)

    def to_dict(self) -> dict:
        return {
            "total_events": self.total_events,
            "c2_events": self.c2_events,
            "benign_events": self.benign_events,
            "true_positives": self.tp,
            "false_positives": self.fp,
            "false_negatives": self.fn,
            "alerts": self.alerts,
            "zeek_detections": self.zeek_count,
            "suricata_detections": self.suricata_count,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "accuracy": self.accuracy,
            "avg_alert_latency_s": round(self.latency_sum / max(1, self.alerts), 3),
            "detected_per_agent": self.detected_per_agent,
        }


def run_detection(events: list[dict]) -> tuple[list[dict], RunMetrics]:
    zeek_hits = match_zeek(events)
    suri_hits = match_suricata(events)

    c2_events = [e for e in events if e.get("traffic_type") == "c2_beacon"]
    benign_set = [e for e in events if e.get("traffic_type") == "benign"]
    bench_start = min((e.get("ts", 0.0) for e in c2_events), default=0.0)

    # Deduplicate: one detection record per event (engine with best score wins).
    merged: dict[int, dict] = {}
    for hit in zeek_hits + suri_hits:
        key = id(hit["ts"]), hit.get("agent_id"), hit.get("dst_port")
        # Events share equal ts; use proximity to a real event as key instead.
        real = _nearest_event(events, hit)
        mkey = id(real) if real is not None else key
        if mkey not in merged or hit["true_positive"] or hit["score"] >= merged[mkey]["score"]:
            merged[mkey] = hit
            merged[mkey]["_event"] = real

    alerts = sorted(list(merged.values()), key=lambda d: d["ts"])
    metrics = RunMetrics(
        total_events=len(events),
        c2_events=len(c2_events),
        benign_events=len(benign_set),
    )
    per_agent_tp: dict[str, int] = defaultdict(int)
    latency_sum = 0.0

    for a in alerts:
        ev = a.get("_event")
        tp = bool(ev and ev.get("traffic_type") == "c2_beacon")
        a["true_positive"] = tp
        if tp:
            metrics.tp += 1
            latency = max(0.0, a["ts"] - float(ev["ts"]))
            latency_sum += latency
            key = f"agent-{ev.get('agent_id')}" if ev.get("agent_id") is not None else "?"
            per_agent_tp[key] += 1
        else:
            metrics.fp += 1
        metrics.alerts += 1

    metrics.fn = metrics.c2_events - metrics.tp
    metrics.zeek_count = len(zeek_hits)
    metrics.suricata_count = len(suri_hits)
    metrics.latency_sum = latency_sum
    metrics.detected_per_agent = dict(per_agent_tp)

    for a in alerts:
        a.pop("_event", None)
    return alerts, metrics


def _nearest_event(events: list[dict], hit: dict) -> dict | None:
    """Match a detection to the closest real event by time + port."""
    best, best_d = None, 1e9
    for e in events:
        d = abs(float(e.get("ts", 0.0)) - hit["ts"])
        if e.get("dst_port") == hit.get("dst_port") and d < best_d:
            best, best_d = e, d
    return best if best_d < 2.0 else None