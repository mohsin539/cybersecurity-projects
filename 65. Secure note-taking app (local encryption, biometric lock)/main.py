"""SecureNote Pro — entry point.

Usage:
  SecureNotePro.exe                -> GUI
  SecureNotePro.exe --cli          -> headless CLI
"""

import os
import sys

if getattr(sys, "frozen", False):
    _BASE = os.path.dirname(sys.executable)
else:
    _BASE = os.path.dirname(os.path.abspath(__file__))
    _SRC = os.path.join(_BASE, "src")
    if _SRC not in sys.path:
        sys.path.insert(0, _SRC)


def main_cli() -> int:
    from secure_note.app import SecureNoteApp
    app = SecureNoteApp()
    print(f"SecureNote Pro | data dir: {app.data_dir}")
    print(f"Vault exists: {app.vault.exists} | Biometric: {app.bio_state}")
    if app.vault.exists and not app.unlocked and not sys.stdin.isatty():
        print("CLI interactive mode requires a TTY for passphrase entry.")
        return 0
    print("Unlock with two factors (biometric + passphrase) — see architecture.md.")
    return 0


def _selftest() -> int:
    """Headless end-to-end verification used to certify the built artifact."""
    import os
    import tempfile
    from secure_note.app import SecureNoteApp

    os.environ["SECURENOTE_HOME"] = tempfile.mkdtemp(prefix="sn_selftest_")
    app = SecureNoteApp()
    assert not app.vault.exists
    assert app.setup("selftest master passphrase 2026", enable_biometric=False)["ok"]
    assert app.vault.exists and app.unlocked
    assert app.add_note("hello", "world", "selftest")["ok"]
    assert len(app.note_list()) == 1
    app.lock()
    assert not app.unlocked
    assert app.unlock(passphrase="selftest master passphrase 2026")["ok"]
    assert app.audit_verify()["ok"]
    res = app.generate_reports(dest_dir=os.path.join(app.data_dir, "reports"))
    assert res["ok"]
    if res.get("artifacts", {}).get("pdf_error"):
        raise SystemExit("PDF FAILED: " + res["artifacts"]["pdf_error"])
    for k in ("json", "csv", "pdf", "zip"):
        assert os.path.exists(res["artifacts"][k]), f"missing {k}"
    assert app.change_passphrase(
        "selftest master passphrase 2026", "rotated passphrase now 2026!")["ok"]
    assert app.wipe()["ok"] and not app.vault.exists
    print("SELFTEST PASSED — crypto, vault, audit, reports, rotation, wipe all verified")
    return 0


def main() -> int:
    if "--selftest" in sys.argv:
        return _selftest()
    if "--cli" in sys.argv:
        return main_cli()
    try:
        from secure_note.ui import run_ui
        return run_ui()
    except Exception as e:  # noqa: BLE001 - surface startup failures to the user
        import traceback
        traceback.print_exc()
        print(f"\nStartup failed: {e}")
        print("Tip: run 'SecureNotePro.exe --cli' to check the environment.")
        return 1


if __name__ == "__main__":
    sys.exit(main())