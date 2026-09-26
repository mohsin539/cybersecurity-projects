"""Build a minimal, valid PE32 for tests — the smallest structure pefile/lief
both accept: DOS stub + COFF header + PE32 optional header + one .text section.

Layout (1024 bytes total, 32-aligned):
  0x000 MZ 'MZ' + e_lfanew=0x40
  0x040 'PE\\0\\0' + COFF (20 bytes)
  0x054 optional header PE32 (224 bytes)
  0x134 first section header (.text)
  0x180 section data (code + suspicious strings)

PE32 optional-header field offsets (relative to optional start 0x58):
  +0x00 Magic(2) +0x02 Linker(2) +0x04 SizeOfCode(4) +0x08 InitData(4)
  +0x0C Uninit(4) +0x10 EntryPoint(4) +0x14 BaseOfCode(4) +0x18 BaseOfData(4)
  +0x1C ImageBase(4) +0x20 SectionAlign(4) +0x24 FileAlign(4)
  +0x28 MajOS(2) +0x2A MinOS(2) +0x2C MajImg(2) +0x2E MinImg(2)
  +0x30 MajSub(2) +0x32 MinSub(2) +0x34 Win32Ver(4) +0x38 SizeOfImage(4)
  +0x3C SizeOfHeaders(4) +0x40 CheckSum(4) +0x44 Subsystem(2) +0x46 DllChars(2)
  +0x48 StackReserve(4) +0x4C StackCommit(4) +0x50 HeapReserve(4)
  +0x54 HeapCommit(4) +0x58 LoaderFlags(4) +0x5C NumRvaAndSizes(4)
  +0x60.. 16 x 8-byte data directories
"""
import struct
from pathlib import Path

DOS_LFANEW = 0x40
COFF_OFFSET = DOS_LFANEW + 4
OPT_OFFSET = COFF_OFFSET + 20
SECTION_HEADER_OFFSET = OPT_OFFSET + 224
SECTION_DATA_OFFSET = SECTION_HEADER_OFFSET + 40
SIZE_OF_IMAGE = 0x2000
SIZE_OF_HEADERS = 0x200
SAMPLE_TS = 0x67010380  # 2024-10-03 UTC-ish, plausible


def build_minimal_pe(path, machine=0x14C, bitness=32, with_strings=True):
    pe = bytearray(1024)
    pe[0:2] = b"MZ"
    struct.pack_into("<I", pe, 0x3C, DOS_LFANEW)
    pe[DOS_LFANEW:DOS_LFANEW + 4] = b"PE\x00\x00"

    # ---- COFF header -------------------------------------------------------
    struct.pack_into("<HHIIIHH", pe, COFF_OFFSET,
                     machine, 1, SAMPLE_TS, 0, 0, 224, 0x0102)

    # ---- Optional header PE32 ------------------------------------------------
    h = OPT_OFFSET
    struct.pack_into("<H", pe, h + 0x00, 0x10B)        # Magic PE32
    struct.pack_into("<B", pe, h + 0x02, 14)           # MajorLinkerVersion
    struct.pack_into("<B", pe, h + 0x03, 0)            # MinorLinkerVersion
    struct.pack_into("<I", pe, h + 0x04, 0x1000)       # SizeOfCode
    struct.pack_into("<I", pe, h + 0x08, 0x1000)       # SizeOfInitializedData
    struct.pack_into("<I", pe, h + 0x0C, 0)            # SizeOfUninitializedData
    struct.pack_into("<I", pe, h + 0x10, 0x1000)       # AddressOfEntryPoint
    struct.pack_into("<I", pe, h + 0x14, 0x1000)       # BaseOfCode
    struct.pack_into("<I", pe, h + 0x18, 0x2000)       # BaseOfData
    struct.pack_into("<I", pe, h + 0x1C, 0x400000)     # ImageBase
    struct.pack_into("<I", pe, h + 0x20, 0x1000)       # SectionAlignment
    struct.pack_into("<I", pe, h + 0x24, 0x200)        # FileAlignment
    struct.pack_into("<H", pe, h + 0x28, 6)            # MajorOperatingSystemVersion
    struct.pack_into("<H", pe, h + 0x2A, 0)            # MinorOperatingSystemVersion
    struct.pack_into("<H", pe, h + 0x2C, 0)            # MajorImageVersion
    struct.pack_into("<H", pe, h + 0x2E, 0)            # MinorImageVersion
    struct.pack_into("<H", pe, h + 0x30, 6)            # MajorSubsystemVersion
    struct.pack_into("<H", pe, h + 0x32, 0)            # MinorSubsystemVersion
    struct.pack_into("<I", pe, h + 0x34, 0)            # Win32VersionValue
    struct.pack_into("<I", pe, h + 0x38, SIZE_OF_IMAGE)    # SizeOfImage
    struct.pack_into("<I", pe, h + 0x3C, SIZE_OF_HEADERS)  # SizeOfHeaders
    struct.pack_into("<I", pe, h + 0x40, 0)            # Checksum
    struct.pack_into("<H", pe, h + 0x44, 2)            # Subsystem: Windows GUI
    struct.pack_into("<H", pe, h + 0x46, 0)            # DllCharacteristics
    struct.pack_into("<I", pe, h + 0x48, 0x100000)     # SizeOfStackReserve
    struct.pack_into("<I", pe, h + 0x4C, 0x1000)       # SizeOfStackCommit
    struct.pack_into("<I", pe, h + 0x50, 0x100000)     # SizeOfHeapReserve
    struct.pack_into("<I", pe, h + 0x54, 0x1000)       # SizeOfHeapCommit
    struct.pack_into("<I", pe, h + 0x58, 0)            # LoaderFlags
    struct.pack_into("<I", pe, h + 0x5C, 16)           # NumberOfRvaAndSizes
    # 16 data directories already zeroed

    # ---- .text section header ------------------------------------------------
    s = SECTION_HEADER_OFFSET
    pe[s:s + 8] = b".text\x00\x00\x00"
    struct.pack_into("<I", pe, s + 8, 0x1000)     # VirtualSize
    struct.pack_into("<I", pe, s + 12, 0x1000)    # VirtualAddress
    struct.pack_into("<I", pe, s + 16, len(pe) - SECTION_DATA_OFFSET)  # SizeOfRawData
    struct.pack_into("<I", pe, s + 20, SECTION_DATA_OFFSET)  # PointerToRawData
    struct.pack_into("<I", pe, s + 24, 0)         # PointerToRelocations
    struct.pack_into("<I", pe, s + 28, 0)         # PointerToLineNumbers
    struct.pack_into("<H", pe, s + 32, 0)         # reloc count
    struct.pack_into("<H", pe, s + 34, 0)         # linenum count
    struct.pack_into("<I", pe, s + 36, 0x60000020)  # CODE|EXECUTE|READ

    # ---- section data ---------------------------------------------------------
    code = bytes([0x31, 0xC0, 0x40, 0xC3])        # xor eax,eax; inc eax; ret
    data = b""
    if with_strings:
        data = (
            b"http://suspicious.invalid/drop/c.dll\0"
            b"C:\\Windows\\System32\\cmd.exe\0"
            b"VirtualAllocEx\0WriteProcessMemory\0CreateRemoteThread\0"
            b"https://evil.example/payload\x00"
            b"182.55.44.7\0"
            b"HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run\0"
        )
    pe[SECTION_DATA_OFFSET:] = code + data
    Path(path).write_bytes(bytes(pe))
    return Path(path)


if __name__ == "__main__":
    import sys
    out = build_minimal_pe(sys.argv[1] if len(sys.argv) > 1 else "sample.exe")
    print(f"wrote {out} ({out.stat().st_size} bytes)")