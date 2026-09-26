@echo off
REM PathSphere 3D - one-click dev launcher (double-click this file)
REM Starts all microservices, starts the web app, opens your browser.

cd /d "%~dp0"

set PORT_AUTH=8080
set PORT_GRAPH=8081
set PORT_PATH=8082
set PORT_AUDIT=8083
set PORT_INGEST=8084
set PORT_REPORT=8085
set PORT_OPA=8181

echo.
echo  PathSphere 3D - starting services...
echo.

REM --- start each compiled service in its own window ---
start "pathsphere-auth" cmd /k "node services\auth-service\dist\main.js"
start "pathsphere-graph" cmd /k "node services\graph-query-api\dist\main.js"
start "pathsphere-path" cmd /k "node services\path-analysis\dist\main.js"
start "pathsphere-audit" cmd /k "node services\audit-ledger\dist\main.js"
start "pathsphere-ingest" cmd /k "node services\ingestion-service\dist\main.js"
start "pathsphere-report" cmd /k "node services\report-engine\dist\main.js"
start "pathsphere-opa" cmd /k "node services\policy-opa\dist\main.js"

REM --- wait for ports to open ---
powershell -NoProfile -Command "$ok=$false; for($i=0;$i -lt 30;$i++){ try{ if((Invoke-WebRequest -UseBasicParsing http://localhost:8080/service -TimeoutSec 1).StatusCode -eq 200){$ok=$true;break} }catch{}; Start-Sleep -Milliseconds 500 }; if(-not $ok){Write-Host 'WARN: auth-service not ready'}"

echo.
echo  Starting web app at http://localhost:5173
echo  (this window will show Vite output - keep it open)
echo.
echo  Login test in a browser: open http://localhost:5173
echo  API usernames:  analyst.demo / ChangeMe!123
echo.

REM --- start the vite dev server and open the browser ---
start "" http://localhost:5173
npm run dev:web

pause