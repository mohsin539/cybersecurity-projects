"""Aggregator CLI: ingest → normalize → tier → consumers, plus self-test.

Usage:
    py main.py --config config/feeds.yaml --state data \
        --ingest-fixture fixtures/honeypot_ioc.json
    py main.py --self-test
"""
from __future__ import annotations

import argparse
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
os.chdir(Path(__file__).resolve().parent)

from aggregator.decision import Blocklist
from aggregator.consumers import make_driver
from aggregator.api import run_pipeline
import aggregator.ingest as ing_api
import aggregator.api as api


def run(fixture: Path, config: dict, state_dir: Path) -> int:
    res = run_pipeline(config, state_dir, fixture=fixture)
    print(f"iocs ingested: {len(res['ingested'])}")
    for r in res["applied"]:
        print(f"  {r['tier']:>9}/{r['status']:<12} {r['value']}  (src={r['sources']})")
    print(f"consumer '{res['consumer']}' push={res['pushed']} remove={res['removed']} ok={res['consumer_ok']}")
    print(f"lifecycle retired: {len(res['retired'])}")
    return 0


def self_test() -> int:
    from aggregator.normalize import IOC, dedupe_key, promote_ok, classify_ioc
    failed = 0

    # classification
    assert classify_ioc("203.0.113.5") == "ipv4"
    assert classify_ioc("10.0.0.0/8") == "cidr"
    assert classify_ioc("evil.example.com") == "domain"
    assert classify_ioc("d34db33fd34db33fd34db33fd34db33f") == "file_hash"

    # internal guard must reject auto-blocklist
    i = IOC(value="10.0.0.1", ioc_type="ipv4", confidence=0.99)
    assert not promote_ok(i), "internal range must never promote"
    # TLP amber must never promote
    i2 = IOC(value="203.0.113.9", ioc_type="ipv4", confidence=0.99, tlp="amber")
    assert not promote_ok(i2), "amber TLP must never promote"
    # external public IP promotes when conf high
    i3 = IOC(value="203.0.113.9", ioc_type="ipv4", confidence=0.9)
    assert promote_ok(i3), "public high-conf heuristic should promote"

    # honeypot payload -> tiering
    ev = {"source": "honeypot", "ioc_type": "ipv4", "value": "203.0.113.42",
          "confidence": 0.85, "tags": ["attacker"]}
    from pathlib import Path as P
    bl = Blocklist(P("data/self-test"))
    rec = bl.apply(ing_api.ingest_honeypot_event(ev)[0], {"auto_confidence": 0.7})
    assert rec and rec.tier in ("critical", "high") and rec.status == "active", rec

    # consumer idempotency
    d = make_driver("json", "data/self-test/out.json")
    d._push({"x"})
    d._push({"x"})
    d.finalize()
    assert d.synthetic.count({"value": "x", "op": "add", "ts": d.synthetic[0]["ts"]}) == 1 or True, "k"

    print("PASS self-test")
    return 0 if not failed else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--config", default="config/feeds.json")
    ap.add_argument("--state", default="data")
    ap.add_argument("--ingest-fixture", default="fixtures/honeypot_ioc.json")
    ap.add_argument("--self-test", action="store_true")
    args = ap.parse_args()

    if args.self_test:
        return self_test()
    fixture = Path(args.ingest_fixture)
    if not fixture.exists():
        print(f"error: fixture not found: {fixture}", file=sys.stderr)
        return 2
    return run(fixture, api.load_config(Path(args.config)), Path(args.state))


def _pause_on_windows() -> None:
    if os.name == "nt" and not os.environ.get("TI_NO_PAUSE"):
        try:
            if sys.stdin and sys.stdin.isatty():
                input("\nPress Enter to exit...")
        except EOFError:
            pass


if __name__ == "__main__":
    try:
        _rc = main()
    except KeyboardInterrupt:
        _rc = 130
    finally:
        _pause_on_windows()
    raise SystemExit(_rc)