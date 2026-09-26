@echo off
cd /d "%~dp0"
where pyw >nul 2>nul
if %errorlevel% == 0 (
    start "" pyw gui.py
) else (
    start "Threat-Intel Aggregator" py gui.py
)
echo GUI launched - Threat-Intel Aggregator dashboard.