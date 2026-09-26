"""Generate NON-MALICIOUS demo fixtures exercising the pattern engine.

Produces, under ./fixtures:
  plain.txt            - readable plaintext (low entropy) - negative control
  rand_encrypted.bin   - random ciphertext-like blob (positive control)
  invoice.txt.lock     - 'encrypted' copy with appended extension + entropy payload
  decoy_original.docx  - known-plaintext original twin
  decoy_original.docx.enc - matching 'encrypted' suspect twin (evidence pair demo)
  ransom_note.txt      - simulated ransom note in plaintext

These are SYNTHETIC files only: they contain no malware and demonstrate the
entropy / structural heuristics. Analysis of them must NOT be interpreted as
actual ransomware.
"""

from __future__ import annotations

import os
import sys

OUT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "fixtures")


def write(name: str, data: bytes) -> str:
    p = os.path.join(OUT, name)
    with open(p, "wb") as f:
        f.write(data)
    return p


def main() -> int:
    os.makedirs(OUT, exist_ok=True)
    paths = []

    plain = (b"Quarterly financial report - summary page.\n" * 80)
    plain += b"The quick brown fox jumps over the lazy dog.\n" * 140
    paths.append(write("plain.txt", plain))

    import random
    rng = random.Random(20260923)
    blob = bytearray(rng.getrandbits(8) for _ in range(64 * 1024))
    # sprinkle an ASCII header to look like a document wrapper
    wrapper = b"%PDF-1.7\n%encrypted-payload-sim\n"
    paths.append(write("rand_encrypted.pdf", wrapper + bytes(blob)))

    invoice = b"Invoice 1042 - net 30 days - total due.\n" * 60
    encrypted_invoice = bytearray(
        rng.getrandbits(8) for _ in range(len(invoice) + 12))
    paths.append(write("invoice.txt.lock", bytes(encrypted_invoice)))

    original = (b"DRAFT project plan v3 - do not distribute.\n" * 90)
    paths.append(write("decoy_original.docx", original))
    enc_twin = wrapper + bytes(bytearray(
        rng.getrandbits(8) for _ in range(len(original) + 8)))
    paths.append(write("decoy_original.docx.enc", enc_twin))

    paths.append(write("ransom_note.txt",
                       b"Your files are ENCRYPTED. Pay 0.05 BTC to w1a1l11e11t to decrypt.\n"
                       b"Contact: recover@example.invalid\n" * 12))

    print("Fixtures written under", os.path.abspath(OUT))
    for p in paths:
        print("  -", os.path.basename(p))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())