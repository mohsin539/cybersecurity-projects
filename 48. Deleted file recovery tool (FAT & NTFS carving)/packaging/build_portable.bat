@echo off
rem ===========================================================================
rem  RecovPro Secure - portable EXE build script
rem  Usage:  build_portable.bat [--onefile] [--skip-selftest]
rem
rem  Output:
rem    dist\RecovProSecure\RecovProSecure.exe   (one-dir build; keep folder)
rem    dist\RecovProSecure.exe                  (--onefile; single file)
rem ===========================================================================
setlocal EnableExtensions
cd /d "%~dp0"

set SPEC=packaging\RecovPro.spec
for %%a in (%*) do if /I "%%a"=="--onefile" set SPEC=packaging\RecovPro_onefile.spec

if not exist "assets\app_icon.ico" (
    echo [1/4] Generating application icon ...
    python packaging\make_icon.py || exit /b 1
) else (
    echo [1/4] Application icon present.
)

echo [2/4] Installing build + runtime requirements ...
python -m pip install -r requirements.txt -q || exit /b 1

if /I "%~1"=="--skip-selftest" goto :build
for %%a in (%*) do if /I "%%a"=="--skip-selftest" goto :build
echo [3/4] Running read-only engine self-test ...
python app\main.py --selftest || exit /b 1
:build

echo [4/4] Building portable bundle with PyInstaller ...
python -m PyInstaller --noconfirm --clean %SPEC% || exit /b 1

echo.
if /I "%SPEC%"=="packaging\RecovPro.spec" (
    echo Build complete: dist\RecovProSecure\RecovProSecure.exe
    echo Copy the RecovProSecure folder to any Windows 10/11 x64 machine.
) else (
    echo Build complete: dist\RecovProSecure.exe  ^(single file, no folder needed^)
)
endlocal