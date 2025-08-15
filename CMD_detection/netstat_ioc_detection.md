# Network Command Line IOC Detection



##  Network Monitoring Commands

### Show All Network Connections
```cmd
netstat -an
```

### Show Connections with Process IDs
```cmd
netstat -ano
```

### Show Connections with Process Names
```cmd
netstat -anb
```

### Show Only TCP Connections
```cmd
netstat -ant
```

### Show Only UDP Connections
```cmd
netstat -anu
```

## IOC Detection Commands

### 1. Suspicious Port Detection

#### Common Malware Ports
```cmd
netstat -an | findstr ":4444 :8080 :8443 :9999 :31337 :1337 :6666 :7777"
```

#### Non-Standard High Ports
```cmd
netstat -an | findstr /R ":5[0-9][0-9][0-9][0-9]"
```

#### Backdoor Ports
```cmd
netstat -an | findstr ":12345 :54321 :65432 :1234 :666 :13013"
```

### 2. Process-Based Detection

#### Suspicious Processes with Network Connections
```cmd
netstat -anob | findstr /I "powershell\|cmd\|rundll32\|regsvr32\|mshta\|certutil\|bitsadmin"
```

#### System Processes on Unusual Ports
```cmd
netstat -anob | findstr /I "svchost" | findstr /V ":135 :445 :139 :53 :80 :443"
```

#### Office Applications with Network Activity
```cmd
netstat -anob | findstr /I "winword\|excel\|powerpnt\|acrobat\|notepad\|calc"
```

### 3. External Connection Detection

#### All External Connections (Non-RFC1918)
```cmd
netstat -an | findstr /V "127.0.0.1\|192.168\|10\.\|172.1[6-9]\|172.2[0-9]\|172.3[0-1]"
```

#### Connections to Specific Suspicious IPs
```cmd
netstat -an | findstr "1.1.1.1\|8.8.8.8\|suspicious.domain.com"
```

### 4. Listening Services Detection

#### Unusual Listening Ports
```cmd
netstat -an | findstr "LISTENING" | findstr /V ":80 :443 :22 :23 :21 :25 :53 :135 :139 :445"
```

#### All Listening Services with Processes
```cmd
netstat -anob | findstr "LISTENING"
```

### 5. Connection State Analysis

#### Established Connections Only
```cmd
netstat -an | findstr "ESTABLISHED"
```

#### Time_Wait Connections (Potential DoS)
```cmd
netstat -an | findstr "TIME_WAIT" | find /c "TIME_WAIT"
```

#### SYN_SENT Connections (Outbound Attempts)
```cmd
netstat -an | findstr "SYN_SENT"
```



## Real-Time Monitoring Scripts

### Continuous Connection Monitoring
```cmd
:loop
cls
echo === Network Connections Monitor ===
date /t && time /t
echo.
echo === Suspicious Ports ===
netstat -ano | findstr ":4444 :8080 :9999 :31337"
echo.
echo === Unusual Processes ===
netstat -anob | findstr /I "powershell\|cmd\|rundll32" | findstr "ESTABLISHED"
echo.
timeout /t 5 /nobreak > nul
goto loop
```

### PowerShell Real-Time Network Monitor
```cmd
REM Note: For PowerShell monitoring, see separate PowerShell IOC Detection guide
```

## Network File Share Monitoring

### Active SMB Sessions
```cmd
net session
```

### Open Files on Shares
```cmd
openfiles /query /s localhost
```

### Active Share Connections
```cmd
net use
```

## DNS and Network Resolution

### DNS Cache Analysis
```cmd
ipconfig /displaydns | findstr /I "suspicious\|malware\|bad"
```

### Clear DNS Cache
```cmd
ipconfig /flushdns
```

### Current DNS Servers
```cmd
nslookup
server
```

## Firewall and Security

### Windows Firewall Status
```cmd
netsh advfirewall show allprofiles
```

### Firewall Rules
```cmd
netsh advfirewall firewall show rule name=all
```

### Network Adapter Configuration
```cmd
ipconfig /all
```

## Network Statistics and Troubleshooting

### Protocol Statistics
```cmd
netstat -s
```

### Routing Table
```cmd
route print
```

### ARP Table
```cmd
arp -a
```

### Network Interface Statistics
```cmd
netstat -e
```

## IOC Detection One-Liners

### Quick Suspicious Connection Check
```cmd
netstat -ano | findstr /R ":[4-9][0-9][0-9][0-9] " | findstr /V ":5985 :5986 :8080"
```

### PowerShell Network Connections
```cmd
netstat -anob | findstr /I powershell | findstr ESTABLISHED
```

### Unusual Listening Services
```cmd
netstat -an | findstr LISTENING | findstr /V ":80 :443 :135 :139 :445 :53 :22 :21 :25 :993 :995 :110 :143"
```

### Count Connections by Process
```cmd
for /f "tokens=5" %i in ('netstat -ano ^| findstr ESTABLISHED') do @echo %i >> temp.txt && for /f %j in ('type temp.txt ^| sort ^| uniq -c') do @echo %j && del temp.txt
```

## Network Baseline Commands

### Establish Normal Baseline
```cmd
REM Save current network state to file
netstat -ano > baseline_connections.txt
tasklist > baseline_processes.txt
```

### Compare Current State to Baseline
```cmd
REM Compare current connections to baseline
netstat -ano > current_connections.txt
fc baseline_connections.txt current_connections.txt
```

## Network-Based Lateral Movement Detection

### SMB/CIFS Connections
```cmd
netstat -an | findstr ":445"
```

### RDP Connections
```cmd
netstat -an | findstr ":3389"
```

### WinRM Connections
```cmd
netstat -an | findstr ":5985 :5986"
```

### SSH Connections
```cmd
netstat -an | findstr ":22"
```

## Log Network Activity

### Log All Connections to File
```cmd
netstat -ano > network_connections_%date:~-4,4%%date:~-10,2%%date:~-7,2%_%time:~0,2%%time:~3,2%.txt
```

### Continuous Logging
```cmd
for /l %i in (1,0,2) do (netstat -ano >> network_log.txt && echo --- %date% %time% --- >> network_log.txt && timeout /t 60 /nobreak > nul)
```

## Quick Investigation Commands

### Process Network Activity
```cmd
netstat -ano | findstr "PID_NUMBER"
```

### Port Owner Identification
```cmd
netstat -ano | findstr ":PORT_NUMBER"
```

### Remote IP Investigation
```cmd
netstat -an | findstr "REMOTE_IP"
```

### Process Command Line
```cmd
wmic process where processid=PID get commandline
```

