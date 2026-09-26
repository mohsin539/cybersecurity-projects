"""Headless smoke test for the compliance engine + store (no GUI needed)."""
import json
import os
import shutil
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from mdmcheck.demo import demo_batch, demo_telemetry
from mdmcheck.engine import evaluate, version_gte
from mdmcheck.policy import default_policy, validate_device_policy
from mdmcheck.store import StateStore


def main():
    tmp = Path(tempfile.mkdtemp(prefix="mdmlite-test-"))
    store = StateStore(tmp / "state.json")

    # version comparison sanity
    assert version_gte("13.0", "12.0") is True
    assert version_gte("11.0", "12.0") is False
    assert version_gte("15.7", "15.0") is True

    # demo telemetry grammars
    for pf in ("android", "ios"):
        t = demo_telemetry("test-dev", pf)
        assert "os" in t and "security" in t and "apps" in t

    # seed + scan demo fleet
    for d in demo_batch()["devices"]:
        store.add_device(d)
    results = []
    for d in store.devices():
        dev = store.device(d["id"])
        tel = demo_telemetry(dev.id, dev.platform)
        result = evaluate(store.policy(), dev.id, dev.platform, tel)
        store.apply_scan(dev.id, tel, result, "demo")
        results.append((dev.name, result.status, result.score, result.fail_count))

    for name, status, score, fails in results:
        print(f"  {name:20s} {status:14s} score={score:6.1f} fails={fails}")

    pol = store.policy()
    n_rules = len(pol["rules"])
    assert n_rules >= 10
    assert all(dv in ("COMPLIANT", "NON_COMPLIANT") for _, dv, _, _ in results)

    # invalid policy must be rejected
    try:
        validate_device_policy({"rules": [{"id": "x", "kind": "bogus_kind"}]})
        raise AssertionError("invalid policy accepted!")
    except ValueError:
        pass

    # persistence round-trip
    store.save()
    reloaded = StateStore(tmp / "state.json")
    assert len(reloaded.devices()) == len(store.devices())

    # report generation
    from mdmcheck.report import generate_html_report, generate_json_report

    st = store.export_report()
    html = generate_html_report(st)
    js = generate_json_report(st)
    assert "<html" in html and js["summary"]["total"] == len(store.devices())

    # security log present
    assert store.logs(limit=5)

    shutil.rmtree(tmp, ignore_errors=True)
    print("\nALL CHECKS PASSED")


if __name__ == "__main__":
    sys.exit(main())