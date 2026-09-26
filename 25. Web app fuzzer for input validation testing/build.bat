@echo off
REM **********************************************
REM  Web App Fuzzer - portable .exe build script
REM  Builds a single-file, windowed portable app.
REM  Usage: build.bat  (run from project root)
REM **********************************************
cd /d "%~dp0"

echo [1/3] Installing PyInstaller (build tool)...
python -m pip install --upgrade pyinstaller
if errorlevel 1 exit /b 1

echo [2/3] Clearing stale build output...
if exist build rmdir /s /q build
if exist dist\WebAppFuzzer.exe del /q dist\WebAppFuzzer.exe 2>nul

echo [3/3] Building portable .exe (onefile, windowed)...
python -m PyInstaller ^
  --noconfirm ^
  --clean ^
  --onefile ^
  --windowed ^
  --name WebAppFuzzer ^
  --collect-all app ^
  --exclude-module numpy ^
  --exclude-module matplotlib ^
  main.py

echo.
echo Build complete. Portable exe: dist\WebAppFuzzer.exe
pause