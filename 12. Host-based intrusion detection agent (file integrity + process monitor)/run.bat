@echo off
cd /d "%~dp0"
set TI_NO_PAUSE=1

rem Default to the GUI console. Pass CLI args to run the headless agent instead.
rem   run.bat                     -> GUI
rem   run.bat cli --baseline      -> headless CLI (pass --cycles, --no-proc, etc.)
if "%~1"=="" (
    py gui.py
) else if /i "%~1"=="cli" (
    shift
    py main.py %*
) else (
    py main.py %*
)
echo.
echo Exit code: %ERRORLEVEL%
echo.
pause