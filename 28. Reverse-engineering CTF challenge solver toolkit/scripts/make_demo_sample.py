"""Generate a realistic 'rev100'-style CTF crackme sample (crafted PE64).

Layout: DOS header -> PE32+ header -> 2 section tables (.text, .rdata) ->
code blob with decoy strings -> rdata with the XOR'd+base64'd real flag.

Solve path (matches the GUI demo):
  1. Run analysis          -> Findings shows a base64ish blob
  2. Recipes -> one-click  -> 'Hex -> Base64 decode' is wrong on purpose;
     the intended chain is [b64_decode, xor key '7'] via the custom pipeline
  3. Disassembly tab       -> sandboxed Capstone rows of the .text section
  4. Decoy flag in Strings -> flag{n0t_th3_r34l_fl4g} (rule-hits, but fake)

Usage: python scripts/make_demo_sample.py [out_path]
"""
from __future__ import annotations

import base64
import struct
import sys
from pathlib import Path

FLAG = b"flag{S4ndb0x_F1rst_D1s4ss}"
XOR_KEY = ord("7")   # ASCII key '7' = 0x37 — matches the GUI recipe key string


def build() -> bytes:
    decoys = [
        b"Usage: crackme.exe <password>",
        b"Access denied. Nice try.",
        b"flag{n0t_th3_r34l_fl4g}",           # decoy: rule-hits but fake
        b"Welcome, agent.",
    ]
    enc_flag = base64.b64encode(bytes(b ^ XOR_KEY for b in FLAG))  # XOR then b64

    code = b"".join([
        b"\x55",                # push rbp
        b"\x48\x89\xe5",        # mov rbp, rsp
        b"\xb8\x2a\x00\x00\x00",  # mov eax, 0x2a
        b"\x48\x85\xc0",        # test rax, rax
        b"\x74\x05",            # je +5
        b"\x5d",                # pop rbp
        b"\xc3",                # ret
        b"\x5d\xc3",            # pop rbp; ret (branch target)
        b"\x90" * 16,           # nop sled
    ])
    rdata = b"\x00" + b"\x00".join(decoys) + b"\x00ENC:" + enc_flag + b"\x00"

    e_lfanew = 0x40
    dos = bytearray(b"MZ" + b"\x00" * (e_lfanew - 2))
    struct.pack_into("<I", dos, 0x3C, e_lfanew)

    pe = bytearray(b"PE\x00\x00")
    pe += struct.pack("<HHIIIHH", 0x8664, 2, 0, 0, 0, 240, 0x22)  # COFF: 2 sections
    opt = bytearray(struct.pack("<H", 0x20B))                     # PE32+ magic
    opt += struct.pack("<II", 9, 0)            # linker, size-of-code
    opt += b"\x00" * (16 - 4)
    opt += struct.pack("<I", 0x1000)           # AddressOfEntryPoint -> .text RVA
    opt += b"\x00" * (opt_pad_to(88) - len(opt))
    opt += struct.pack("<II", 0, 0)            # data dir 0 (export)
    opt += struct.pack("<II", 0, 0)            # data dir 1 (import) - empty is fine
    opt += b"\x00" * (240 - len(opt))

    def sec_hdr(name: bytes, vsize: int, vaddr: int, rawsize: int, rawptr: int,
                chars: int) -> bytes:
        return name.ljust(8, b"\x00") + struct.pack("<IIIIIIII", vsize, vaddr,
                                                    rawsize, rawptr, 0, 0, 0, chars)

    code_off = 0x400
    rdata_off = code_off + len(code)
    hdrs = sec_hdr(b".text", len(code), 0x1000, len(code), code_off, 0x60000020)
    hdrs += sec_hdr(b".rdata", len(rdata), 0x2000, len(rdata), rdata_off, 0x40000040)

    out = bytearray(bytes(dos) + bytes(pe) + bytes(opt) + hdrs)
    out += b"\x00" * (code_off - len(out))
    out += code + rdata
    return bytes(out)


def opt_pad_to(n: int) -> int:
    return n


def main() -> int:
    out = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("REKT-LOCAL/demo_crackme.exe")
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_bytes(build())
    print(f"wrote {out} ({out.stat().st_size} bytes)")
    print("real flag:   flag{S4ndb0x_F1rst_D1s4ss}  (xor 7 then base64 in .rdata)")
    print("decoy flag:  flag{n0t_th3_r34l_fl4g}   (plain, in strings)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
