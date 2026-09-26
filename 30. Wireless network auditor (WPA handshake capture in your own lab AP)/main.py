"""Wireless Network Auditor - entry point.

Usage:
  python main.py                # launch GUI
  python main.py --selftest     # headless engine + report verification
"""
import os
import sys
import zipfile


def run_selftest() -> int:
    import tempfile
    _tmp = tempfile.mkdtemp(prefix="wna_selftest_")
    os.environ["WNA_DATA_DIR"] = _tmp

    from app.core.scope import ScopeGuard
    from app.core.engine import AuditEngine
    from app.data.vault import EvidenceVault
    from app.report import base, html_exporter, csv_exporter, xlsx_exporter, json_exporter
    from app import config

    print(f"== {config.APP_NAME} selftest v{config.APP_VERSION} ::\n")

    vault = EvidenceVault()
    engine = AuditEngine(vault)
    for bssid, ssid, ch in (
        ("00:1A:2B:3C:4D:5E", "MY-LAB-AP", 6),
        ("00:1A:2B:3C:4D:5F", "LAB-AP-2", 11),
    ):
        engine.register_lab_ap(bssid, ssid, ch)

    try:
        engine.scope.describe("DE:AD:BE:EF:00:11", "EVIL-SSID")
        print("[FAIL] out-of-scope frame was not rejected")
        return 2
    except Exception as exc:
        print(f"[ OK ] scope guard rejects out-of-scope frames ({type(exc).__name__})")

    engine.simulate_for(4.0)
    s = engine.stats()
    print(f"[ OK ] simulated capture -> aps={s['aps']} clients={s['clients']} "
          f"sessions={s['sessions']} complete={s['complete']} findings={s['findings']}")

    data = base.ReportData.from_vault(vault, engine.backend)
    os.makedirs(config.REPORT_DIR, exist_ok=True)
    root = os.path.join(config.REPORT_DIR, "audit")

    hp = html_exporter.export(data, root + ".html")
    print(f"[ OK ] HTML  {os.path.getsize(hp)} bytes")
    with open(hp, encoding="utf-8") as fh:
        assert "Wireless Network Auditor" in fh.read()
    print("[ OK ] HTML content verified")

    cf = csv_exporter.export(data, config.REPORT_DIR)
    for k, p in cf.items():
        print(f"[ OK ] CSV   {os.path.basename(p)} ({os.path.getsize(p)} B)")
    with open(cf["findings"], encoding="utf-8-sig") as fh:
        head = fh.readline().strip()
    print(f"[ OK ] CSV header: {head}")

    xp = xlsx_exporter.export(data, root + ".xlsx")
    if zipfile.is_zipfile(xp):
        with zipfile.ZipFile(xp) as z:
            names = z.namelist()
            assert "xl/workbook.xml" in names and len([n for n in names if n.startswith("xl/worksheets/")]) == 6
        print(f"[ OK ] XLSX  valid workbook, 6 sheets ({os.path.getsize(xp)} bytes)")
        zt = zipfile.ZipFile(xp).read("xl/workbook.xml").decode()
        assert "Dashboard" in zt and "Findings" in zt
        print("[ OK ] XLSX sheet names verified")
    else:
        print("[FAIL] XLSX is not a valid zip")
        return 2

    jp = json_exporter.export(data, root + ".json")
    print(f"[ OK ] JSON  {os.path.getsize(jp)} bytes")
    import json as _json
    with open(jp, encoding="utf-8") as fh:
        doc = _json.load(fh)
    assert doc["schema"] == "wna.report.v1"
    print("[ OK ] JSON schema verified")

    print(f"\n== integrity ==")
    print(f"      hash chain: {vault.chain_state()}")
    print(f"      AES-GCM mode: {'DPAPI-wrapped key' if vault._crypto.advanced else 'PBKDF2-derived key'}")

    vault.close()
    print("\nSELFTEST PASSED")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        try:
            return run_selftest()
        except Exception as exc:
            import traceback
            traceback.print_exc()
            print(f"\nSELFTEST FAILED: {exc}")
            return 1
    if os.name == "nt" and "--headless" not in sys.argv:
        from app.gui.app import run
        run()
        return 0
    return run_selftest()


if __name__ == "__main__":
    sys.exit(main())