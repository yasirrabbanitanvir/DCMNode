@echo off
REM ============================================
REM   Telerad PACS Server Auto Starter Script
REM ============================================

setlocal EnableDelayedExpansion

:: 1) Ensure running as Administrator
net session >nul 2>&1
if %errorlevel% neq 0 (
    echo [INFO] Administrative privileges required. Requesting elevation...
    powershell -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
    exit /b
)

echo ===========================================
echo Starting Telerad PACS Server
echo ===========================================
echo.

:: 2) Define port and paths
set "PORT=11112"
set "EXE_PATH=C:\Users\afsar\OneDrive\Desktop\Telerad PACS APK\Telerad PACS Server2.exe"

echo [CHECK] Checking if port %PORT% is in use...
echo.

:: Show what processes are using the port
netstat -ano | find "%PORT%"

echo.
echo [INFO] Attempting to kill all processes on port %PORT%...

:: Kill all processes using that port
for /f "tokens=5" %%P in ('netstat -ano ^| find ":%PORT%" ^| find "LISTENING"') do (
    echo [KILL] Terminating PID %%P...
    taskkill /PID %%P /F
)

:: Wait 2 seconds
echo.
echo [WAIT] Waiting 2 seconds...
timeout /t 2 /nobreak >nul

:: 3) Start the server
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