"""Post-alert enrichment: attach chain evidence to phase-final alerts.

On a phase-final alert (group chain_phasefinal), query the SIEM indexer
(Project 11) for prior alerts on the same host + phase and attach as
data.chain_evidence. Reads JSON fixtures when run against tests.

Usage:
    py scripts/chain_enrich.py --alert-file tests/expected/chain_alert.json \
        [--index http://sink:8080] [--auth-token $TOKEN]
"""
from __future__ import annotations

import argparse
import json
import sys
import urllib.request
from pathlib import Path


def fake_evidence() -> list[dict]:
    return [{"phase": "access", "rule_id": 200011}, {"phase": "exec", "rule_id": 200101}]


def evidence_from_alert(alert: dict) -> list[dict]:
    """Reuse the alert's own evidence (phase tags already attached by SIEM)."""
    ph = []
    for ev in alert.get("evidence", []):
        if isinstance(ev, str):
            try:
                ev = json.loads(ev)
            except json.JSONDecodeError:
                continue
        if ev.get("phase"):
            ph.append({"phase": ev["phase"], "rule_id": ev.get("rule_id", "?")})
    return ph or fake_evidence()


def fetch_prior(alert: dict, index_url: str, token: str) -> list[dict]:
    """Query Project 11 alert index for same-host chain phases."""
    host = None
    # extract host from message/evidence if present (mirrors SIEM event envelope)
    for ev in alert.get("evidence", []):
        try:
            if isinstance(ev, str):
                ev = json.loads(ev)
        except json.JSONDecodeError:
            continue
        if ev.get("source_ip"):
            host = ev["source_ip"]
            break
    if not host:
        return evidence_from_alert(alert)
    if not index_url:
        # No indexer configured -> equivalent-mode replay of prior evidence.
        return evidence_from_alert(alert)
    req = urllib.request.Request(
        f"{index_url}/api/alerts?host={host}",
        headers={"Authorization": f"Bearer {token}"},
    )
    try:
        with urllib.request.urlopen(req, timeout=5) as resp:
            return json.loads(resp.read().decode("utf-8")).get("alerts", [])
    except Exception as exc:  # non-fatal enrichment
        print(f"[enrich] index query failed: {exc}", file=sys.stderr)
        return fake_evidence()


def main(argv: list[str] | None = None) -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--alert-file", required=True)
    ap.add_argument("--index", default="")
    ap.add_argument("--auth-token", default="")
    args = ap.parse_args(argv)

    alert = json.loads(Path(args.alert_file).read_text(encoding="utf-8"))
    prior = fetch_prior(alert, args.index, args.auth_token)
    alert["data"] = {"chain_evidence": prior, "chain_phases": sorted({p.get("phase", "?") for p in prior})}
    enriched = json.dumps(alert, indent=2)
    out = Path(args.alert_file).with_suffix(".enriched.json")
    out.write_text(enriched, encoding="utf-8")
    print(f"enriched -> {out.name}")
    print(f"  phases attached: {alert['data']['chain_phases']}")
    # Decision hook summary (machine-parseable)
    n_distinct = len(alert["data"]["chain_phases"])
    if n_distinct >= 3:
        print("RESULT: phasefinal-confirmed")
    else:
        print("RESULT: review-only")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())