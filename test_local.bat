@echo off
echo ========================================
echo  Testing C2 Framework Locally
echo ========================================
echo.

echo [1] Checking if port 4444 is available...
netstat -ano | findstr :4444 > nul
if %ERRORLEVEL% == 0 (
    echo ❌ Port 4444 is already in use!
    echo    Kill existing process first
    exit /b 1
) else (
    echo ✅ Port 4444 is available
)

echo.
echo [2] Starting C2 Server in background...
start /min "C2 Server" cmd /c "cd /d %~dp0output && c2_server.exe"
timeout /t 3 /nobreak > nul

echo.
echo [3] Testing client connection...
echo    Client will connect to 127.0.0.1:4444
timeout /t 2 /nobreak > nul

cd /d %~dp0output
echo.
echo [4] Starting client (you should see connection in server window)...
c2_client.exe --server 127.0.0.1 --no-stealth --no-persistence

echo.
echo ========================================
echo  Test completed!
echo ========================================
pause
