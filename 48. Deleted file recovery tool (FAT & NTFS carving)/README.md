# RecovPro Secure

**Deleted File Recovery Tool — FAT / NTFS metadata recovery + signature carving**

A portable, GUI-based, read-only forensic utility for Windows that recovers
deleted files from FAT12/16/32 and NTFS volumes using a **native, dependency-free
parser** (no OS driver, no third-party filesystem library) plus byte-level
**signature carving** over unallocated space.

> Build config: Windows 10/11 x64 · Python 3.12 · PySide6
> Portable bundle: `dist\RecovProSecure\RecovProSecure.exe`

---

## Highlights

| Area | Capability |
|---|---|
| **FAT (12/16/32)** | Boot-sector geometry detection, directory scan, `0xE5` deleted-entry recovery, VFAT/LFN reassembly (reverse-sequence order), free-cluster chain heuristics |
| **NTFS** | Direct `$MFT` parse (native, no driver), USN fixups, resident & non-resident data runs, `$Bitmap` re-allocation gating |
| **Carving** | 40+ header/footer signatures across images, docs, archives, audio, video, executables, databases; bounded stepwise footer probing, per-header plausibility gates, SHA-256 fingerprinting |
| **Sources** | Logical volumes (`\\.\C:`) without admin rights · physical drives (`\\.\PhysicalDriveN`, requires elevation) · forensic images (`.img`/`.dd`/`.raw`) · MBR + GPT partition parsing |
| **Security** | Tamper-evident **hash-chained** audit log, encrypted recovery vault (**AES-256-GCM**, PBKDF2 600 000 iterations), path-traversal sanitization, strict read-only IO |
| **Output** | Per-file SHA-256, confidence/anchor rating, export to CSV / JSON / HTML, encrypted `.bundle` transfer format |
| **Build** | One-dir portable EXE via PyInstaller; UAC `asInvoker` manifest; no install required |

## Quick start (portable EXE)

1. Copy the folder `dist\RecovProSecure\` to any Windows 10/11 x64 machine.
2. Run `RecovProSecure.exe`.
3. Pick a **logical volume**, **physical drive** (needs *Run as administrator*), or an
   **image file**.
4. Choose **Quick** (deleted metadata) or **Deep** (metadata + carve free space).
5. Select candidates in the results table → **Recover** into the vault, or
   **Export** encrypted.

### From source (dev)

```bat
python -m pip install -r requirements.txt
python app\main.py                  REM launch GUI
python app\main.py --selftest       REM headless engine test (read-only)
python packaging\build_portable.bat REM build the portable EXE
```

## Engine self-test

Runs a fully **read-only** verification against synthetic images that the app
builds in the temp directory (`recovpro_test_*.img`):

- **FAT16** – mounts, finds deleted entry, recovers original bytes
- **FAT32** – mounts, LFN reassembly, deleted `REPORT.DOC` (PDF magic), JPEG carving from free space
- **NTFS** – `$MFT` scan, resident + non-resident deleted files, active file listing
- **Security** – path sanitization, vault SHA-256 manifest, AES-256-GCM bundle, audit hash-chain

Passing self-test is a **build gate** (`build_portable.bat` refuses to package otherwise).

## Architecture

```
app/
  main.py                 CLI entry (GUI / --selftest)
  core/
    disk.py               Read-only Win32 raw IO, volume/physical enumeration
    partition.py          MBR + GPT parsers
    fat.py                FAT12/16/32 geometry, dir scan, LFN, deleted chains
    ntfs.py               $MFT scan, runlists, fixups, $Bitmap gating
    signatures.py         signature database + structural validation
    carver.py             bounded free-space carving engine
    engine.py             orchestration: scan → recover → carve
  security/
    sanitize.py           path traversal / naming hardening
    audit.py              hash-chained JSONL audit + chain verification
    vault.py              SHA-256 manifest vault + AES-256-GCM encrypted export
  ui/                     PySide6 app (theme, dashboard, scan worker, results, vault)
  tests/
    builders.py           synthetic FAT/NTFS image generators (test fixtures)
    smoke.py              4-phase read-only self-test
  utils/reporting.py      CSV / JSON / HTML export
packaging/                PyInstaller spec, manifest, build script, icon generator
```

## Data-safety model

- The engine opens every source with `GENERIC_READ` + `FILE_SHARE_READ|WRITE` and
  never issues write operations.
- `ReadOnlySource` clamps offsets, refuses negative/oversized reads, and sets an
  immutable `readonly` marker at open time.
- Recovered bytes are hashed (SHA-256) and stored under a sanitized, collision-safe
  name inside the dedicated **vault** directory.
- The vault manifest and the audit log both detect tampering (SHA-256 / hash chain).

## Compliance posture

RecovPro Secure is designed against **ISO/IEC 27001**, **NIST CSF**, **NIST SP 800-53**,
and **OWASP Top 10** expectations. See:

- [docs/ISO_27001_Mapping.md](docs/ISO_27001_Mapping.md)
- [docs/NIST_Mapping.md](docs/NIST_Mapping.md)
- [docs/OWASP_Top10_Mapping.md](docs/OWASP_Top10_Mapping.md)
- [SECURITY.md](SECURITY.md)

## Ethics & legality

Recovery tools process data belonging to someone. **Use only on systems you own or
have explicit written authorization to examine.** Export every scan and recovery to
the encrypted bundle for a defensible chain of custody. Never use this tool against
systems you do not own or lack authorization for.