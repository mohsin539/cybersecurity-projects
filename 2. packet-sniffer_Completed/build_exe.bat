@echo off
REM ============================================================
REM  PacketSniffer portable exe build script (Windows)
REM  Output: dist\PacketSniffer.exe  (single-file, self-contained)
REM ============================================================
setlocal
cd /d "%~dp0"

echo [1/4] Checking PyInstaller...
py -m PyInstaller --version >nul 2>&1
if errorlevel 1 (
    echo   Installing PyInstaller...
    py -m pip install --user pyinstaller || goto :fail
)

echo [2/4] Cleaning previous build...
if exist build rmdir /s /q build
if exist dist  rmdir /s /q dist

echo [3/4] Running PyInstaller...
py -m PyInstaller packet_sniffer.spec --noconfirm || goto :fail

echo [4/4] Done.
echo   Output: %cd%\dist\PacketSniffer.exe
echo.
echo   NOTE: Run the exe from an ADMINISTRATOR prompt for raw-socket capture.
echo         Launch with --demo for a no-privilege synthetic-traffic demo.
exit /b 0

:fail
echo BUILD FAILED - see output above.
exit /b 1
