# AgentJitterStudy - PyInstaller onefile spec
# Build with:  python -m PyInstaller specs\build.spec --noconfirm
import os

from PyInstaller.utils.hooks import collect_data_files

HERE = os.path.dirname(os.path.abspath(SPEC))  # SPEC is defined by PyInstaller
ROOT = os.path.dirname(HERE)

block_cipher = None

datas = collect_data_files("customtkinter", includes=["**/*.json", "**/*.png", "**/*.ttf"])

a = Analysis(
    [os.path.join(ROOT, "src", "main.py")],
    pathex=[ROOT],
    binaries=[],
    datas=datas,
    hiddenimports=[
        "customtkinter",
        "darkdetect",
        "openpyxl",
        "cryptography",
        "yaml",
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["pytest", "matplotlib", "scipy", "numpy.f2py"],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.zipfiles,
    a.datas,
    [],
    name="AgentJitterStudy",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,           # GUI app: no console window
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version=os.path.join(ROOT, "specs", "versioninfo.txt"),
)