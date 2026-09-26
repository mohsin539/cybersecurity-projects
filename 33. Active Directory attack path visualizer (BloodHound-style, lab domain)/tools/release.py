#!/usr/bin/env python3
"""One-command release pipeline for the portable SentinelGraph.exe.

Steps:
  1. build the SPA (npm run build) -> backend/static
  2. run backend tests (fail fast)
  3. PyInstaller build (SentinelGraph.spec)
  4. code-sign + verify (tools/sign_exe.py) — required unless --skip-sign
  5. smoke-launch the exe and hit /api/v1/meta

Usage:
  python tools/release.py                    # full pipeline incl. signing
  python tools/release.py --skip-sign        # dev build (unsigned, loudly)
  SG_CODESIGN_PFX=... SG_CODESIGN_PFX_PASSWORD=... python tools/release.py
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BACKEND = ROOT / "backend"
EXE = BACKEND / "dist" / "SentinelGraph.exe"


def run(cmd: list[str] | str, cwd: Path | None = None,
        shell: bool = False) -> int:
    print(f"\n=== {' '.join(cmd) if isinstance(cmd, list) else cmd}")
    rc = subprocess.run(cmd, cwd=cwd, shell=shell).returncode
    if rc != 0:
        print(f"[release] step failed with exit {rc}: {cmd}", file=sys.stderr)
        sys.exit(rc)
    return rc


def smoke_test(port: int = 8021, timeout_s: int = 30) -> None:
    import urllib.error
    env = dict(os.environ, SG_PORT=str(port))
    proc = subprocess.Popen([str(EXE)], cwd=str(ROOT / "tmp-smoke") if
                            (ROOT / "tmp-smoke").mkdir(exist_ok=True) is None
                            else None, env=env,
                            stdout=subprocess.DEVNULL,
                            stderr=subprocess.DEVNULL)
    try:
        url = f"http://127.0.0.1:{port}/api/v1/meta"
        deadline = time.time() + timeout_s
        last_err = None
        while time.time() < deadline:
            try:
                with urllib.request.urlopen(url, timeout=3) as r:
                    if r.status == 200:
                        print(f"[release] smoke OK: {url} -> 200")
                        return
            except (urllib.error.URLError, OSError) as e:
                last_err = e
                time.sleep(1)
        raise SystemExit(f"[release] smoke test failed: {last_err}")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--skip-sign", action="store_true",
                    help="produce an UNSIGNED build (dev only)")
    ap.add_argument("--skip-ui", action="store_true",
                    help="skip npm build (static already current)")
    ap.add_argument("--skip-smoke", action="store_true")
    ap.add_argument("--port", type=int, default=8021)
    args = ap.parse_args()

    # 1. Frontend bundle
    if not args.skip_ui:
        npm = "npm.cmd" if os.name == "nt" else "npm"
        run([npm, "run", "build"], cwd=ROOT / "frontend")

    # 2. Backend tests
    run([sys.executable, "-m", "pytest", "tests/", "-q"], cwd=BACKEND)

    # 3. PyInstaller
    run([sys.executable, "-m", "PyInstaller", "SentinelGraph.spec",
         "--noconfirm"], cwd=BACKEND)
    if not EXE.is_file():
        raise SystemExit(f"[release] exe missing after build: {EXE}")

    # 4. Code signing (CI gate: unsigned releases fail unless explicit)
    sign = ROOT / "tools" / "sign_exe.py"
    if args.skip_sign:
        print("\n[release] WARNING: --skip-sign set — build is UNSIGNED "
              "(not for distribution).")
    else:
        run([sys.executable, str(sign), "--exe", str(EXE)])

    # 5. Smoke launch
    if not args.skip_smoke:
        smoke_test(args.port)

    print(f"\n[release] DONE — {EXE}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
