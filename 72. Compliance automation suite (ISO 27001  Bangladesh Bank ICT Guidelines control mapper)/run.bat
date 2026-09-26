@echo off
setlocal
title Compliance Automation Suite v1.0.0
cd /d "%~dp0backend"

where python >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Python not found on PATH. Install Python 3.11+ first.
    pause
    exit /b 1
)

python -c "import uvicorn, fastapi, sqlalchemy, jwt, openpyxl, reportlab, docx" >nul 2>nul
if errorlevel 1 (
    echo [INFO] Installing dependencies ...
    python -m pip install -r requirements.txt
)

echo.
echo  ============================================================
echo   Compliance Automation Suite
echo   ISO 27001 ^| Bangladesh Bank ICT Guidelines ^| NIST CSF ^| OWASP
echo   ^>^> http://127.0.0.1:8000   (Ctrl+C to stop)
echo   Demo logins: ciso/Ciso@12345 ^| admin/Admin@12345 ^| regulator/Regul@12345
echo  ============================================================
echo.

start "" http://127.0.0.1:8000
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

endlocal