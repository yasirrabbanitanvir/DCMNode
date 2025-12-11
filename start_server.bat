@echo off
REM ================================
REM   Telerad PACS Server Auto Start
REM ================================

setlocal EnableDelayedExpansion

net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Administrative privileges required. Requesting elevation...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ============================
echo Starting Telerad PACS Server
echo ============================
echo.

set "PORT=11112"
set "EXE_PATH=C:\Users\afsar\OneDrive\Desktop\Telerad PACS APK\Telerad PACS Server2.exe"

echo [CHECK] Checking if port %PORT% is in use...
echo.

netstat -ano | find "%PORT%"

echo.
echo [INFO] Attempting to kill all processes on port %PORT%...

for /f "tokens=5" %%P in ('netstat -ano ^| find ":%PORT%" ^| find "LISTENING"') do (
    echo [KILL] Terminating PID %%P...
    taskkill /PID %%P /F
)

echo.
echo [WAIT] Waiting 2 seconds...
timeout /t 2 /nobreak >nul

echo.
echo [START] Launching Telerad PACS Server...
if exist "%EXE_PATH%" (
    start "" "%EXE_PATH%"
    echo [DONE] Server started successfully!
) else (
    echo [ERROR] Cannot find: %EXE_PATH%
)

echo.
echo ===========================================
echo Press any key to close.
echo ===========================================
pause >nul
endlocal