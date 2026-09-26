"""Build the portable rekt.exe (ARCHITECTURE.md §9).

Usage: python scripts/build_exe.py
Output: dist/rekt-portable/  (+ SHA256SUMS file)
"""
from __future__ import annotations

import hashlib
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def main() -> int:
    if not (ROOT / "rekt.spec").exists():
        print("rekt.spec missing", file=sys.stderr)
        return 1
    cmd = [sys.executable, "-m", "PyInstaller", "rekt.spec", "--noconfirm",
           "--distpath", str(ROOT / "dist"), "--workpath", str(ROOT / "build")]
    print("[build]", " ".join(cmd))
    rc = subprocess.run(cmd, cwd=str(ROOT)).returncode
    if rc != 0:
        return rc

    out = ROOT / "dist" / "rekt-portable"
    # Trust store: copy the release trust.pub into _internal (frozen lookup path)
    # so signed plugins verify out of the box. Never copy trust.key!
    internal = out / "_internal"
    internal.mkdir(exist_ok=True)
    src_trust = ROOT / "trust.pub"
    dst_trust = internal / "trust.pub"
    if src_trust.exists() and src_trust.stat().st_size > 0:
        dst_trust.write_bytes(src_trust.read_bytes())
    elif not dst_trust.exists():
        dst_trust.touch()

    # SHA256SUMS for the release page (NIST SSDF PS.2)
    sums = []
    for p in sorted(out.rglob("*")):
        if p.is_file():
            h = hashlib.sha256(p.read_bytes()).hexdigest()
            sums.append(f"{h}  {p.relative_to(out)}")
    (out / "SHA256SUMS").write_text("\n".join(sums) + "\n", encoding="ascii")
    print(f"[build] OK -> {out}")
    print(f"[build] {len(sums)} files hashed into SHA256SUMS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
