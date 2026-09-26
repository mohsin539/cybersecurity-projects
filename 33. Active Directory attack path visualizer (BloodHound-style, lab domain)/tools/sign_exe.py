#!/usr/bin/env python3
"""Code-signing step for the SentinelGraph portable exe.

Wraps signtool (Windows SDK) or osslsigncode with bank-friendly defaults:
authenticode signature + RFC3161 timestamp + (optional) SHA-256 digest page
hash. Designed for CI: exits non-zero when signing is required but not
possible, so an unsigned exe can never ship silently.

Usage:
  python tools/sign_exe.py --verify                  # verify only
  python tools/sign_exe.py                           # sign dist exe
  python tools/sign_exe.py --pfx my.pfx --dry-run    # show command

Configuration (env or flags):
  SG_CODESIGN_PFX / --pfx          PFX/PKCS#12 certificate path
  SG_CODESIGN_PFX_PASSWORD / --pfx-password   cert password (prefer env/PFM)
  SG_TS_URL / --ts-url             RFC3161 timestamp server
"""
from __future__ import annotations

import argparse
import hashlib
import os
import shutil
import subprocess
import sys
from pathlib import Path

DEFAULT_TS_URL = "http://timestamp.digicert.com"

_SIGNTOOL_HINTS = [
    r"C:\Program Files (x86)\Windows Kits\10\bin",
    r"C:\Program Files\Windows Kits\10\bin",
]


def _find_signtool() -> str | None:
    if p := shutil.which("signtool"):
        return p
    base_env = os.environ.get("WINDOWS_KITS_ROOT")
    roots = ([Path(base_env)] if base_env else []) + \
        [Path(h) for h in _SIGNTOOL_HINTS if Path(h).is_dir()]
    for root in roots:
        if not root.is_dir():
            continue
        for ver in sorted((d.name for d in root.iterdir() if d.is_dir()),
                          reverse=True):
            cand = root / ver / "x64" / "signtool.exe"
            if cand.is_file():
                return str(cand)
    return None


def _find_osslsigncode() -> str | None:
    return shutil.which("osslsigncode")


def _sha256(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as fh:
        for chunk in iter(lambda: fh.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


def _sign_cmd(tool: str, exe: Path, pfx: str, pfx_password: str,
              ts_url: str) -> list[str]:
    if tool == "signtool":
        # /fd sha256 + /tr RFC3161 (never deprecated /t); /ph for page hashes.
        return [
            tool, "sign", "/f", pfx, "/p", pfx_password,
            "/fd", "SHA256", "/tr", ts_url, "/td", "SHA256", "/ph",
            str(exe),
        ]
    # osslsigncode (cross-platform CI)
    out = exe.with_suffix(".exe.signed")
    return [
        tool, "sign", "-pkcs12", pfx, "-pass", pfx_password,
        "-t", ts_url, "-in", str(exe), "-out", str(out),
        "-h", "sha256", "-n", "SentinelGraph AD Attack Path Visualizer",
    ]


def _verify_cmd(tool: str, exe: Path) -> list[str]:
    if tool == "signtool":
        return [tool, "verify", "/pa", "/all", str(exe)]
    return [tool, "verify", "--in", str(exe)]


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--exe", default=str(Path(__file__).resolve().parents[1]
                                         / "backend" / "dist"
                                         / "SentinelGraph.exe"))
    ap.add_argument("--pfx", default=os.environ.get("SG_CODESIGN_PFX", ""))
    ap.add_argument("--pfx-password",
                    default=os.environ.get("SG_CODESIGN_PFX_PASSWORD", ""))
    ap.add_argument("--ts-url",
                    default=os.environ.get("SG_TS_URL", DEFAULT_TS_URL))
    ap.add_argument("--tool", choices=["auto", "signtool", "osslsigncode"],
                    default="auto")
    ap.add_argument("--verify", action="store_true",
                    help="verify existing signature only")
    ap.add_argument("--dry-run", action="store_true")
    args = ap.parse_args()

    exe = Path(args.exe)
    if not exe.is_file():
        print(f"[sign] ERROR: exe not found: {exe}", file=sys.stderr)
        return 2
    print(f"[sign] target : {exe}")
    print(f"[sign] sha256 : {_sha256(exe)}")

    tool = args.tool
    if tool == "auto":
        found = _find_signtool() or _find_osslsigncode()
        tool = "signtool" if (found and found.lower().endswith("signtool.exe")
                              ) else "osslsigncode"
        if not found:
            print("[sign] ERROR: no signing tool found. Install the Windows "
                  "SDK (signtool) or osslsigncode.", file=sys.stderr)
            return 2
        cmd_base = found
    else:
        cmd_base = (_find_signtool() if tool == "signtool"
                    else _find_osslsigncode())
        if not cmd_base:
            print(f"[sign] ERROR: {tool} not available.", file=sys.stderr)
            return 2

    if args.verify:
        cmd = _verify_cmd(tool, exe)
        print("[sign] verifying:", " ".join(cmd))
        rc = subprocess.run(cmd).returncode
        print("[sign] verification", "OK" if rc == 0 else "FAILED")
        return rc

    # Signing requested: fail loudly if no certificate is configured (CI gate).
    if not args.pfx:
        print("[sign] ERROR: no certificate configured. Set SG_CODESIGN_PFX "
              "(and SG_CODESIGN_PFX_PASSWORD) or pass --pfx. Refusing to "
              "produce an unsigned release.", file=sys.stderr)
        return 2
    if not Path(args.pfx).is_file():
        print(f"[sign] ERROR: certificate file not found: {args.pfx}",
              file=sys.stderr)
        return 2

    cmd = [cmd_base] + _sign_cmd(tool, exe, args.pfx, args.pfx_password,
                                 args.ts_url)[1:]
    if args.dry_run:
        masked = ["******" if c == args.pfx_password else c for c in cmd]
        print("[sign] dry-run:", " ".join(masked))
        return 0

    print("[sign] signing with", tool, "…")
    rc = subprocess.run(cmd).returncode
    if rc != 0:
        print("[sign] signing FAILED", file=sys.stderr)
        return rc
    print("[sign] signed OK — verifying …")
    vrc = subprocess.run(_verify_cmd(tool, exe)).returncode
    print(f"[sign] final sha256: {_sha256(exe)}")
    print("[sign] verification", "OK" if vrc == 0 else "FAILED")
    return vrc


if __name__ == "__main__":
    sys.exit(main())
