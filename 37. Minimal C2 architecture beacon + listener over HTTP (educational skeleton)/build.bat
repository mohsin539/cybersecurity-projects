@echo off
REM =====================================================================
REM  C2 Study Lab - portable build script (Windows / PyInstaller)
REM  Produces:
REM    dist\C2StudyLab.exe        (windowed GUI console - operator)
REM    dist\C2StudyLab_Beacon.exe (windowed beacon client - agent)
REM =====================================================================
setlocal
cd /d "%~dp0"

pip install -r requirements.txt

echo.
echo [1/2] Building GUI console ...
pyinstaller --noconfirm --clean --onefile --windowed --name C2StudyLab ^
  --add-data "architecture.html;." ^
  --add-data "COMPLIANCE.md;." ^
  main.py

echo [2/2] Building beacon client ...
pyinstaller --noconfirm --clean --onefile --windowed --name C2StudyLab_Beacon ^
  beacon_entry.py

echo.
echo BUILD COMPLETE. Output in .\dist
echo   .\dist\C2StudyLab.exe         - run the GUI console
echo   .\dist\C2StudyLab_Beacon.exe  - run a beacon: --server http://HOST:PORT --id lab-1
endlocal