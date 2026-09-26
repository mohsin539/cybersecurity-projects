# -*- mode: python ; coding: utf-8 -*-
# PyInstaller spec: builds the Log Anonymizer desktop .exe.
# Usage:  pyinstaller anonymizer_gui.spec
#
# The GUI depends on the windows-only DPAPI wrapper (ctypes/crypt32) and
# uses cryptography (Fernet/scrypt) for encrypted exports. Both are small
# and bundled automatically.

from pathlib import Path

project_root = Path(SPECPATH)

a = Analysis(
    [str(project_root / "gui_launcher.py")],
    pathex=[str(project_root / "src")],
    binaries=[],
    datas=[],
    hiddenimports=[
        "anonymizer.gui.dpapi",
        "anonymizer.gui.state_manager",
        "anonymizer.gui.memory_manager",
        "anonymizer.gui.framework",
        "anonymizer.gui.scanner",
        "anonymizer.gui.text_view",
        "anonymizer.gui.theme",
        "anonymizer.gui.main_window",
        "anonymizer.gui.security_dashboard",
        "anonymizer.gui.audit_viewer",
        "anonymizer.gui.settings_dialog",
        "anonymizer.gui.export_dialog",
        "anonymizer.gui.recent_dialog",
        "anonymizer.core.models",
        "anonymizer.detection.detection_engine",
        "anonymizer.detection.pattern_matcher",
        "anonymizer.detection.contextual_detector",
        "anonymizer.redaction.redactor",
        "anonymizer.security.audit_trail",
        "anonymizer.security.hashing",
        "anonymizer.security.input_validation",
        "anonymizer.security.framework_alignment",
        "anonymizer.services.anonymizer_service",
        "anonymizer.services.policy_engine",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tests", "uvicorn", "fastapi", "pydantic", "httpx"],
    noarchive=False,
    optimize=1,
)

pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name="LogAnonymizer",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)