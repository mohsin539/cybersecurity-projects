"""Plugin signing toolkit (trust-model workflow, ARCHITECTURE.md §3.7).

Commands:
  keygen                  write trust.pub (public) + trust.key (private, KEEP SAFE)
  sign <plugin_dir>       sign plugin.toml + plugin.py -> plugin.sig

The private key never leaves the release machine; distribute only trust.pub.
"""
from __future__ import annotations

import base64
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))  # run-from-anywhere

from rekt.platform import trust  # noqa: E402


def keygen() -> int:
    pub, priv = trust.generate_keypair()
    Path("trust.pub").write_text(base64.b64encode(pub).decode("ascii"), encoding="ascii")
    Path("trust.key").write_text(base64.b64encode(priv).decode("ascii"), encoding="ascii")
    print("wrote trust.pub (distribute with releases)")
    print("wrote trust.key (KEEP PRIVATE — signing key)")
    return 0


def sign(plugin_dir: str) -> int:
    key_b64 = Path("trust.key").read_text(encoding="ascii").strip()
    from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
    from cryptography.hazmat.primitives import serialization

    sk = Ed25519PrivateKey.from_private_bytes(base64.b64decode(key_b64))
    pdir = Path(plugin_dir)
    message = (pdir / "plugin.toml").read_bytes() + (pdir / "plugin.py").read_bytes()
    sig = sk.sign(message)
    (pdir / "plugin.sig").write_text(
        json.dumps({"signature": base64.b64encode(sig).decode()}), encoding="ascii")
    print(f"signed {pdir} -> plugin.sig")
    return 0


def main() -> int:
    if len(sys.argv) < 2 or sys.argv[1] not in {"keygen", "sign"}:
        print(__doc__)
        return 1
    if sys.argv[1] == "keygen":
        return keygen()
    if len(sys.argv) < 3:
        print("usage: sign <plugin_dir>")
        return 1
    return sign(sys.argv[2])


if __name__ == "__main__":
    sys.exit(main())
