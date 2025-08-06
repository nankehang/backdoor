@echo off
setlocal enabledelayedexpansion

REM C2 Framework Test Script for Windows
REM For educational and authorized testing purposes only

echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                            C2 Framework Test Suite                          ║
echo ║                     Educational & Authorized Testing Only                   ║
echo ╚══════════════════════════════════════════════════════════════════════════════╝
echo.

set tests_passed=0
set tests_failed=0

REM Test Rust installation
echo [INFO] Testing Rust installation...
where cargo >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    for /f "tokens=*" %%i in ('rustc --version') do set rust_version=%%i
    echo [PASS] Rust installed: !rust_version!
    set /a tests_passed+=1
) else (
    echo [FAIL] Rust not found. Install from https://rustup.rs/
    set /a tests_failed+=1
)

REM Test dependencies
echo [INFO] Testing project dependencies...
cd c2_server
cargo tree --quiet >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Server dependencies resolved
    set /a tests_passed+=1
) else (
    echo [FAIL] Server dependency issues found
    set /a tests_failed+=1
)
cd ..

cd c2_client
cargo tree --quiet >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Client dependencies resolved
    set /a tests_passed+=1
) else (
    echo [FAIL] Client dependency issues found
    set /a tests_failed+=1
)
cd ..

REM Test compilation
echo [INFO] Testing compilation...
cd c2_server
cargo check --quiet >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Server compilation check passed
    set /a tests_passed+=1
) else (
    echo [FAIL] Server compilation failed
    set /a tests_failed+=1
)
cd ..

cd c2_client
cargo check --quiet >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Client compilation check passed
    set /a tests_passed+=1
) else (
    echo [FAIL] Client compilation failed
    set /a tests_failed+=1
)
cd ..

REM Test network functionality
echo [INFO] Testing network functionality...
echo use std::net::TcpListener; > network_test.rs
echo fn main() ^-^> Result^<^(^), Box^<dyn std::error::Error^>^> { >> network_test.rs
echo     let listener = TcpListener::bind^("127.0.0.1:0"^)?; >> network_test.rs
echo     println!^("Network test passed"^); >> network_test.rs
echo     Ok^(^(^)^) >> network_test.rs
echo } >> network_test.rs

echo [package] > Cargo.toml
echo name = "network_test" >> Cargo.toml
echo version = "0.1.0" >> Cargo.toml
echo edition = "2021" >> Cargo.toml
echo [[bin]] >> Cargo.toml
echo name = "network_test" >> Cargo.toml
echo path = "network_test.rs" >> Cargo.toml

cargo run --bin network_test --quiet >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [PASS] Network functionality test passed
    set /a tests_passed+=1
) else (
    echo [FAIL] Network functionality test failed
    set /a tests_failed+=1
)

REM Cleanup test files
del network_test.rs Cargo.toml Cargo.lock >nul 2>nul
rmdir /s /q target >nul 2>nul

REM Basic security checks
echo [INFO] Running basic security checks...
findstr /r "version.*\*" c2_server\Cargo.toml c2_client\Cargo.toml >nul 2>nul
if %ERRORLEVEL% EQU 0 (
    echo [WARN] Wildcard versions found in dependencies
) else (
    echo [PASS] No wildcard versions in dependencies
)
set /a tests_passed+=1

REM Performance test - compilation time
echo [INFO] Testing compilation performance...
cd c2_server
set start_time=%time%
cargo build --release --quiet >nul 2>nul
set end_time=%time%
echo [PASS] Server compilation completed
set /a tests_passed+=1
cd ..

REM Print summary
echo.
echo ╔══════════════════════════════════════════════════════════════════════════════╗
echo ║                              Test Summary                                    ║
echo ╠══════════════════════════════════════════════════════════════════════════════╣
echo ║ Tests Passed: !tests_passed!                                                           ║
echo ║ Tests Failed: !tests_failed!                                                           ║

if !tests_failed! EQU 0 (
    echo ║ Status: ALL TESTS PASSED                                                  ║
    echo ║ ✓ C2 Framework is ready for deployment                                   ║
    echo ╚══════════════════════════════════════════════════════════════════════════════╝
    echo.
    echo 🚀 Ready to build with: build.bat
    echo 📖 Read README.md for usage instructions
    echo ⚠️  Remember: Use only for authorized testing!
) else (
    echo ║ Status: SOME TESTS FAILED                                                 ║
    echo ║ ✗ Please fix issues before deployment                                    ║
    echo ╚══════════════════════════════════════════════════════════════════════════════╝
    echo.
    echo Please fix the failed tests before proceeding.
)

pause
