@echo off
echo ======================================
echo  C2 Testing Debug Script
echo ======================================
echo.

echo [INFO] Cleaning up old processes...
taskkill /f /im c2_server.exe >nul 2>&1
taskkill /f /im c2_client.exe >nul 2>&1
timeout /t 2 /nobreak >nul

echo [INFO] Starting C2 Server...
echo        Server will listen on 0.0.0.0:4444
start "C2 Server" cmd /c "cd /d %~dp0output && c2_server.exe"
timeout /t 5 /nobreak >nul

echo [INFO] Testing connectivity...
netstat -ano | findstr :4444 >nul
if %ERRORLEVEL% == 0 (
    echo ✅ Server is listening on port 4444
) else (
    echo ❌ Server is not listening! Check for errors.
    pause
    exit /b 1
)

echo.
echo [INFO] Starting C2 Client...
echo        Client will connect to 127.0.0.1:4444
echo        Press Ctrl+C to stop the client
echo.
cd /d %~dp0output
c2_client.exe --server 127.0.0.1 --no-stealth --no-persistence
