@echo off
setlocal enabledelayedexpansion
chcp 65001 >nul
title AEGIS-SENTINEL - WebGL Threat Globe
cd /d "%~dp0"

echo.
echo   ============================================================
echo    AEGIS-SENTINEL  -  WebGL Global Threat Feed Visualization
echo    Build + Run (Vite dev server on port 5173)
echo   ============================================================
echo.

rem ---- 1. Prerequisites: node + npm ----
where node >nul 2>nul
if errorlevel 1 (
    echo [ERROR] Node.js was not found on PATH. Install Node 18+ from https://nodejs.org
    pause
    exit /b 1
)
for /f "tokens=1 delims=." %%v in ('node -v 2^>nul') do set NODE_MAJOR=%%v
set NODE_MAJOR=%NODE_MAJOR:v=%
if %NODE_MAJOR% LSS 18 (
    echo [ERROR] Node.js version %NODE_MAJOR% detected. Node 18+ is required.
    pause
    exit /b 1
)
where npm >nul 2>nul
if errorlevel 1 (
    echo [ERROR] npm was not found on PATH.
    pause
    exit /b 1
)
echo [OK] node %NODE_MAJOR%.x + npm found.

rem ---- 2. Install dependencies (only if absent) ----
if not exist "node_modules\.bin\vite.cmd" (
    echo [INFO] node_modules missing - installing dependencies...
    call npm install
    if errorlevel 1 (
        echo [ERROR] npm install failed.
        pause
        exit /b 1
    )
) else (
    echo [OK] dependencies already present.
)

rem ---- 3. Typecheck + build ----
echo [INFO] running typecheck...
call npm run typecheck
if errorlevel 1 (
    echo [ERROR] TypeScript typecheck failed.
    pause
    exit /b 1
)
echo [OK] typecheck passed.

echo [INFO] running audit suite (ledger tamper-evidence)...
call npm test
if errorlevel 1 (
    echo [ERROR] test suite failed.
    pause
    exit /b 1
)

echo [INFO] building production bundle...
call npm run build
if errorlevel 1 (
    echo [ERROR] production build failed.
    pause
    exit /b 1
)

rem ---- 4. Launch ----
echo.
echo   ============================================================
echo    All gates passed. Starting dev server at http://localhost:5173
echo    Press Ctrl+C in this window to stop.
echo   ============================================================
echo.
start "AEGIS-SENTINEL" http://localhost:5173
call npm run dev
endlocal