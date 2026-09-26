# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller spec for the portable SAP builds (architecture.md §8.2).

Produces TWO portable executables from one build:
  dist/SAP.exe       - GUI triage console (console=False)
  dist/SAP-cli.exe   - headless pipeline CLI (console=True)

Both route through launcher.py (project-46 pattern):
  known CLI subcommand  -> sap.cli.main()
  otherwise             -> sap.gui.main()

Embedded:
  |- Python 3.x runtime + sap package
  |- pefile (PE parsing), PySide6 (GUI targets only)
  |- yara (optional), cryptography (optional)
  '- pack/sap_manifest.json  <- build-time hash manifest for the
                                fail-closed self_integrity_check (P9)
"""
import hashlib
import json
from pathlib import Path

VERSION = "1.0.0"

# ---- bundled data files + build-time integrity manifest -------------------
# {dest_name: sha256}; at runtime integrity.self_integrity_check(bundle_root())
# re-hashes every entry and the app FAILS CLOSED on any mismatch (P9).
datas = []
try:
    pack_dir = Path("pack")
    if not pack_dir.exists():
        pack_dir.mkdir(exist_ok=True)
    manifest = {"app": "SAP", "version": VERSION, "files": {}}
    if pack_dir.exists():
        for f in sorted(pack_dir.rglob("*")):
            # never self-reference the manifest (its own hash changes on write)
            if f.is_file() and f.name != "sap_manifest.json":
                digest = hashlib.sha256(f.read_bytes()).hexdigest()
                dest = f"pack/{f.relative_to(pack_dir).as_posix()}"
                manifest["files"][dest] = digest
                datas.append((str(f), "pack"))
    manifest_path = pack_dir / "sap_manifest.json"
    manifest_path.write_text(
        json.dumps(manifest, indent=2, sort_keys=True), encoding="utf-8")
    datas.append(("pack/sap_manifest.json", "pack"))
except Exception:
    pass  # manifest regeneration is best-effort in the spec

block_cipher = None

# ---- GUI build (includes PySide6) -------------------------------------------
a_gui = Analysis(
    ["launcher.py"],
    pathex=["src", "."],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "sap", "sap.app", "sap.cli", "sap.gui", "sap.__main__",
        "sap.security.integrity", "sap.security.audit", "sap.security.policy",
        "sap.security.crypto", "sap.engines.hashing", "sap.engines.strings_engine",
        "sap.engines.pe_engine", "sap.intel.bloom", "sap.intel.sources",
        "sap.intel.lookup", "sap.rules.heuristics", "sap.rules.bundle",
        "sap.orchestration.spec", "sap.orchestration.scheduler",
        "sap.orchestration.aggregator", "sap.data.store", "sap.data.sandbox",
        "sap.data.reporting",
        "pefile",
        "yara", "cryptography",           # only if present at build time
        "PySide6",
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "scipy", "PyQt5", "PyQt6"],
    cipher=block_cipher,
    noarchive=False,
)

pyz_gui = PYZ(a_gui.pure, a_gui.zipped_data, cipher=block_cipher)

exe_gui = EXE(
    pyz_gui,
    a_gui.scripts,
    a_gui.binaries,
    a_gui.zipfiles,
    a_gui.datas,
    [],
    name="SAP",
    debug=False,
    strip=False,
    upx=False,          # UPX triggers AV false positives - keep OFF
    console=False,      # GUI console
    icon=None,
    version=None,
)

# ---- CLI build (headless: no PySide6 to keep it slim) -----------------------
a_cli = Analysis(
    ["launcher.py"],
    pathex=["src", "."],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "sap", "sap.app", "sap.cli", "sap.__main__",
        "sap.security.integrity", "sap.security.audit", "sap.security.policy",
        "sap.security.crypto", "sap.engines.hashing", "sap.engines.strings_engine",
        "sap.engines.pe_engine", "sap.intel.bloom", "sap.intel.sources",
        "sap.intel.lookup", "sap.rules.heuristics", "sap.rules.bundle",
        "sap.orchestration.spec", "sap.orchestration.scheduler",
        "sap.orchestration.aggregator", "sap.data.store", "sap.data.sandbox",
        "sap.data.reporting",
        "pefile",
        "yara", "cryptography",           # only if present at build time
    ],
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "matplotlib", "numpy", "scipy",
              "PySide6", "PyQt5", "PyQt6"],
    cipher=block_cipher,
    noarchive=False,
)

pyz_cli = PYZ(a_cli.pure, a_cli.zipped_data, cipher=block_cipher)

exe_cli = EXE(
    pyz_cli,
    a_cli.scripts,
    a_cli.binaries,
    a_cli.zipfiles,
    a_cli.datas,
    [],
    name="SAP-cli",
    debug=False,
    strip=False,
    upx=False,          # UPX triggers AV false positives - keep OFF
    console=True,       # console CLI (headless / CI triage)
    icon=None,
    version=None,
)