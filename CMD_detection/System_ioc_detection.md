# Command Line IOC Detection Methods

## Overview
These commands focus on process analysis, file system monitoring, registry changes, service activities, and system anomalies.

## Process and Service Detection

### Running Processes Analysis
```cmd
tasklist /svc
```

### Processes with Full Paths
```cmd
wmic process get processid,parentprocessid,commandline,executablepath
```

### Suspicious Process Names
```cmd
tasklist | findstr /I "powershell\|cmd\|rundll32\|regsvr32\|mshta\|certutil\|bitsadmin\|wmic"
```

### Processes Running from Temp Directories
```cmd
wmic process where "executablepath like '%temp%' or executablepath like '%tmp%'" get processid,commandline,executablepath
```

### Unsigned Processes
```cmd
wmic process where "executablepath is not null" get processid,executablepath | findstr /V "Windows\|Program Files"
```

### Parent-Child Process Relationships
```cmd
wmic process get processid,parentprocessid,name,commandline
```

### High CPU Usage Processes
```cmd
wmic process get processid,name,workingsetsize,percentprocessortime
```

## Service Monitoring

### All Services Status
```cmd
sc query state= all
```

### Recently Modified Services
```cmd
wmic service get name,displayname,pathname,startmode,state
```

### Services Running from Unusual Locations
```cmd
wmic service where "pathname not like '%windows%' and pathname not like '%program files%'" get name,pathname,startmode
```

### Services with Suspicious Names
```cmd
sc query | findstr /I "temp\|update\|security\|antivirus\|system"
```

### Service Configuration Details
```cmd
sc qc ServiceName
```

### Service Failure Actions
```cmd
sc qfailure ServiceName
```

## File System Analysis

### Recently Created Files
```cmd
forfiles /p c:\ /s /m *.exe /d +0 /c "cmd /c echo @path @fdate @ftime"
```

### Files in System Directories
```cmd
dir c:\windows\system32\*.exe /s /od
```

### Hidden Files and Directories
```cmd
dir /ah /s c:\
```

### Alternate Data Streams Detection
```cmd
dir /r c:\windows\system32\
```

### Large Files (Potential Data Staging)
```cmd
forfiles /p c:\ /s /m *.* /c "cmd /c if @fsize gtr 104857600 echo @path @fsize"
```

### Recently Modified System Files
```cmd
forfiles /p c:\windows\system32 /m *.exe /d +0 /c "cmd /c echo @path @fdate @ftime"
```

### Executable Files in User Directories
```cmd
dir c:\users\*\*.exe /s
```

### Files with Double Extensions
```cmd
dir *.*.* /s /b | findstr /I "\.exe\.\|\.scr\.\|\.com\.\|\.bat\.\|\.cmd\."
```

## Registry Monitoring

### Startup Programs (Run Keys)
```cmd
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\RunOnce
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\RunOnce
```

### Service Registry Entries
```cmd
reg query HKLM\SYSTEM\CurrentControlSet\Services
```

### Winlogon Registry Keys
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon"
```

### Image File Execution Options (IFEO)
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options"
```

### Recently Modified Registry Keys
```cmd
reg query HKLM\SOFTWARE /s | findstr /I "LastWrite"
```

### AppInit DLLs
```cmd
reg query "HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows" /v AppInit_DLLs
```

### Shell Folders
```cmd
reg query "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
```

## User Account Analysis

### Local Users and Groups
```cmd
net user
net localgroup
```

### User Account Details
```cmd
net user username
```

### Recently Created Accounts
```cmd
wmic useraccount get name,sid,status,disabled,lockout,passwordchangeable,passwordexpires
```

### Administrative Users
```cmd
net localgroup administrators
```

### Guest Account Status
```cmd
net user guest
```

### Password Policy
```cmd
net accounts
```

### Logon Sessions
```cmd
query user
query session
```

## System Configuration

### Installed Programs
```cmd
wmic product get name,version,installdate
```

### System Information
```cmd
systeminfo
```

### Environment Variables
```cmd
set
```

### Scheduled Tasks
```cmd
schtasks /query /fo table /v
```

### Startup Programs
```cmd
wmic startup get caption,command,location
```

### System Drivers
```cmd
driverquery /v
```

### Boot Configuration
```cmd
bcdedit /enum
```

## Security Settings

### Windows Firewall Status
```cmd
netsh advfirewall show allprofiles
```

### User Rights Assignment
```cmd
whoami /priv
```

### Security Policies
```cmd
secedit /export /cfg security_config.txt
type security_config.txt
```

### Audit Policy
```cmd
auditpol /get /category:*
```

### Windows Defender Status
```cmd
sc query windefend
```

## Log Analysis

### System Event Logs (Basic)
```cmd
wevtutil qe System /c:20 /rd:true /f:text
```

### Security Event Logs
```cmd
wevtutil qe Security /c:20 /rd:true /f:text
```

### Application Event Logs
```cmd
wevtutil qe Application /c:20 /rd:true /f:text
```

### Recent Logon Events
```cmd
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:10 /rd:true /f:text
```

### Failed Logon Events
```cmd
wevtutil qe Security /q:"*[System[(EventID=4625)]]" /c:10 /rd:true /f:text
```

### Process Creation Events
```cmd
wevtutil qe Security /q:"*[System[(EventID=4688)]]" /c:10 /rd:true /f:text
```

## Performance and Resource Monitoring

### Performance Monitoring
```cmd
typeperf "\Processor(_Total)\% Processor Time" -sc 5
```

### Memory Usage
```cmd
wmic OS get FreePhysicalMemory,TotalVisibleMemorySize
```

### Disk Usage
```cmd
wmic logicaldisk get size,freespace,caption
```

### Running Services Resource Usage
```cmd
wmic service get name,processid,status | findstr "Running"
```

## IOC Detection Scripts

### Comprehensive System Scan
```cmd
@echo off
echo === IOC Detection Scan Started ===
echo Time: %date% %time%
echo.

echo === Suspicious Processes ===
tasklist | findstr /I "powershell\|cmd\|rundll32\|regsvr32\|mshta\|certutil\|bitsadmin"
echo.

echo === Unusual Services ===
wmic service where "pathname not like '%%windows%%' and pathname not like '%%program files%%'" get name,pathname,startmode
echo.

echo === Recent Files in System32 ===
forfiles /p c:\windows\system32 /m *.exe /d +0 /c "cmd /c echo @path @fdate @ftime" 2>nul
echo.

echo === Startup Programs ===
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run
echo.

echo === Administrative Users ===
net localgroup administrators
echo.

echo === Recent Logons ===
wevtutil qe Security /q:"*[System[(EventID=4624)]]" /c:5 /rd:true /f:text
echo.

echo === Scan Completed ===
echo Time: %date% %time%
```

### Process Monitoring Loop
```cmd
@echo off
:loop
cls
echo === Process Monitor ===
echo Time: %date% %time%
echo.

echo === Current Processes ===
tasklist | findstr /I "powershell\|cmd\|rundll32\|regsvr32\|mshta\|certutil\|bitsadmin"
echo.

echo === High Memory Processes ===
wmic process get processid,name,workingsetsize | sort /r /+3
echo.

timeout /t 300 /nobreak > nul
goto loop
```

### File System Monitoring
```cmd
@echo off
echo === File System IOC Check ===
echo.

echo === Checking for suspicious file locations ===
dir c:\users\*\*.exe /s /b 2>nul | findstr /I "temp\|appdata\|downloads"
echo.

echo === Checking for hidden files ===
dir /ah c:\windows\system32\*.exe 2>nul
echo.

echo === Checking for recently modified system files ===
forfiles /p c:\windows\system32 /m *.exe /d +1 /c "cmd /c echo @path @fdate @ftime" 2>nul
echo.

echo === Checking for alternate data streams ===
dir /r c:\windows\system32\*.exe | findstr ":.*:"
echo.
```

## Automated Collection Scripts

### Evidence Collection
```cmd
@echo off
set OUTPUT_DIR=IOC_Collection_%date:~6,4%%date:~3,2%%date:~0,2%_%time:~0,2%%time:~3,2%
mkdir %OUTPUT_DIR%
cd %OUTPUT_DIR%

echo Collecting system information...
systeminfo > systeminfo.txt
tasklist /svc > tasklist.txt
netstat -ano > netstat.txt
sc query state= all > services.txt
wmic process get processid,parentprocessid,commandline,executablepath > processes.txt
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run > startup_hklm.txt
reg query HKCU\Software\Microsoft\Windows\CurrentVersion\Run > startup_hkcu.txt
net user > users.txt
net localgroup > groups.txt
schtasks /query /fo table /v > scheduled_tasks.txt
driverquery /v > drivers.txt
wmic product get name,version,installdate > installed_programs.txt

echo Collection completed in %OUTPUT_DIR%
```

### Quick Triage Script
```cmd
@echo off
echo === Quick Triage - %date% %time% ===
echo.

echo [+] Checking for suspicious processes...
tasklist | findstr /I "powershell\|cmd\|rundll32\|regsvr32\|mshta\|certutil\|bitsadmin" && echo SUSPICIOUS PROCESSES FOUND || echo No suspicious processes

echo.
echo [+] Checking for unusual services...
wmic service where "pathname not like '%%windows%%' and pathname not like '%%program files%%'" get name,pathname | find /c "Name" > nul && echo UNUSUAL SERVICES FOUND || echo No unusual services

echo.
echo [+] Checking for recent system file changes...
forfiles /p c:\windows\system32 /m *.exe /d +0 /c "cmd /c echo @path" 2>nul | find /c ":" > nul && echo RECENT SYSTEM FILE CHANGES || echo No recent system file changes

echo.
echo [+] Checking administrative users...
net localgroup administrators | findstr /V "Alias name\|Comment\|Members\|----\|The command completed"

echo.
echo [+] Checking running services count...
sc query state= all | find /c "RUNNING"

echo.
echo === Triage Complete ===
```

## Performance Monitoring

### Resource Usage Monitoring
```cmd
@echo off
:monitor
cls
echo === Resource Monitor ===
echo Time: %date% %time%
echo.

echo === Top CPU Processes ===
wmic process get processid,name,percentprocessortime | sort /r
echo.

echo === Memory Usage ===
wmic OS get FreePhysicalMemory,TotalVisibleMemorySize
echo.

echo === Disk Usage ===
wmic logicaldisk get size,freespace,caption
echo.

timeout /t 30 /nobreak > nul
goto monitor
```

### Service Status Monitoring
```cmd
@echo off
echo === Service Status Check ===
echo.

echo === Critical Security Services ===
sc query windefend | findstr "STATE"
sc query wuauserv | findstr "STATE"
sc query eventlog | findstr "STATE"
sc query wscsvc | findstr "STATE"
echo.

echo === Recently Stopped Services ===
wmic service where "state='stopped'" get name,displayname,startmode
echo.

echo === Services in Manual Start Mode ===
wmic service where "startmode='Manual'" get name,displayname,state
```

## Investigation Commands

### Process Investigation
```cmd
REM Replace PID with actual process ID
set PID=1234
echo === Investigating Process %PID% ===
wmic process where processid=%PID% get processid,name,commandline,executablepath,parentprocessid
wmic process where parentprocessid=%PID% get processid,name,commandline
netstat -ano | findstr %PID%
```

### User Activity Investigation
```cmd
REM Replace USERNAME with actual username
set USERNAME=testuser
echo === Investigating User %USERNAME% ===
net user %USERNAME%
wmic process where "owner='%USERNAME%'" get processid,name,commandline
query user %USERNAME%
```

### File Investigation
```cmd
REM Replace FILEPATH with actual file path
set FILEPATH=c:\suspicious\file.exe
echo === Investigating File %FILEPATH% ===
dir "%FILEPATH%" /q
wmic datafile where name="%FILEPATH:\=\\%" get creationdate,lastmodified,size
tasklist | findstr /I "%~nxFILEPATH%"
```

## Common IOC Patterns

### Malware Indicators
```cmd
REM Check for common malware file locations
dir c:\windows\temp\*.exe /s /b
dir c:\users\*\appdata\local\temp\*.exe /s /b
dir c:\programdata\*.exe /s /b

REM Check for persistence mechanisms
reg query HKLM\Software\Microsoft\Windows\CurrentVersion\Run | findstr /I "temp\|appdata\|programdata"
schtasks /query | findstr /I "temp\|appdata\|programdata"

REM Check for process injection indicators
tasklist /m | findstr /I "ntdll\|kernel32\|advapi32"
```

### Lateral Movement Indicators
```cmd
REM Check for remote access tools
tasklist | findstr /I "psexec\|winrs\|teamviewer\|vnc\|rdp"
netstat -ano | findstr ":3389\|:5900\|:5800"
net session
net use
```

### Data Exfiltration Indicators
```cmd
REM Check for archiving tools
tasklist | findstr /I "rar\|7z\|winzip\|tar"
dir c:\*.rar /s /b
dir c:\*.7z /s /b
dir c:\*.zip /s /b

REM Check for staging directories
dir c:\temp /s
dir c:\users\public /s
```
