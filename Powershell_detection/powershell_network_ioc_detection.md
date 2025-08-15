# PowerShell IOC Detection Methods

## Overview
These scripts leverage PowerShell's rich object manipulation capabilities for advanced process analysis, file system monitoring, registry inspection, and security assessment.

## Process and Service Analysis

### Advanced Process Information
```powershell
Get-Process | Select-Object Name, Id, CPU, WorkingSet, Path, Company, ProductVersion, StartTime | Sort-Object CPU -Descending
```

### Processes with Command Line Arguments
```powershell
Get-WmiObject Win32_Process | Select-Object ProcessId, Name, CommandLine, ExecutablePath, ParentProcessId | Where-Object {$_.CommandLine -ne $null}
```

### Suspicious Process Detection
```powershell
Get-Process | Where-Object {
    $_.ProcessName -match "powershell|cmd|rundll32|regsvr32|mshta|certutil|bitsadmin|wmic" -or
    $_.Path -match "temp|appdata|programdata" -or
    $_.Company -eq $null -or
    $_.Path -eq $null
} | Select-Object Name, Id, Path, Company, StartTime
```

### Parent-Child Process Tree
```powershell
function Get-ProcessTree {
    $processes = Get-WmiObject Win32_Process
    
    function Get-Children($parentId, $level = 0) {
        $children = $processes | Where-Object {$_.ParentProcessId -eq $parentId}
        foreach ($child in $children) {
            $indent = "  " * $level
            "$indent$($child.Name) (PID: $($child.ProcessId)) - $($child.CommandLine)"
            Get-Children $child.ProcessId ($level + 1)
        }
    }
    
    $rootProcesses = $processes | Where-Object {$_.ParentProcessId -eq 0 -or -not ($processes | Where-Object {$_.ProcessId -eq $_.ParentProcessId})}
    foreach ($root in $rootProcesses) {
        "$($root.Name) (PID: $($root.ProcessId)) - $($root.CommandLine)"
        Get-Children $root.ProcessId 1
    }
}

Get-ProcessTree
```

### Unsigned Executable Detection
```powershell
Get-Process | Where-Object {$_.Path -ne $null} | ForEach-Object {
    $signature = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue
    if ($signature.Status -ne "Valid") {
        [PSCustomObject]@{
            ProcessName = $_.Name
            PID = $_.Id
            Path = $_.Path
            SignatureStatus = $signature.Status
            Signer = $signature.SignerCertificate.Subject
        }
    }
}
```

### Service Analysis
```powershell
Get-Service | Where-Object {
    $_.Status -eq "Running" -and
    (Get-WmiObject Win32_Service | Where-Object {$_.Name -eq $_.Name}).PathName -notmatch "windows|program files"
} | Select-Object Name, Status, @{Name="Path";Expression={(Get-WmiObject Win32_Service | Where-Object {$_.Name -eq $_.Name}).PathName}}
```

### Process Module Analysis
```powershell
function Get-ProcessModules {
    param([int]$ProcessId)
    
    Get-Process -Id $ProcessId | Select-Object -ExpandProperty Modules | 
    Select-Object ModuleName, FileName, Company, ProductVersion | 
    Where-Object {$_.Company -eq $null -or $_.FileName -notmatch "windows|program files"}
}

# Usage: Get-ProcessModules -ProcessId 1234
```

## File System Monitoring

### Recently Created Files
```powershell
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | 
Where-Object {$_.CreationTime -gt (Get-Date).AddDays(-1)} | 
Select-Object FullName, CreationTime, Length | 
Sort-Object CreationTime -Descending
```

### Suspicious File Locations
```powershell
$suspiciousPaths = @("C:\Windows\Temp", "C:\Temp", "C:\Users\*\AppData\Local\Temp", "C:\ProgramData")
foreach ($path in $suspiciousPaths) {
    Get-ChildItem -Path $path -Recurse -File -Include "*.exe","*.dll","*.scr","*.bat","*.cmd" -ErrorAction SilentlyContinue | 
    Select-Object FullName, CreationTime, LastWriteTime, Length
}
```

### Alternate Data Streams Detection
```powershell
Get-ChildItem -Path C:\Windows\System32 -File | ForEach-Object {
    $streams = Get-Item $_.FullName -Stream * -ErrorAction SilentlyContinue | Where-Object {$_.Stream -ne ":$DATA"}
    if ($streams) {
        foreach ($stream in $streams) {
            [PSCustomObject]@{
                File = $_.FullName
                Stream = $stream.Stream
                Length = $stream.Length
            }
        }
    }
}
```

### File Hash Analysis
```powershell
function Get-FileHashAnalysis {
    param([string]$Path)
    
    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue | 
    Where-Object {$_.Extension -in @(".exe",".dll",".scr",".bat",".cmd")} |
    ForEach-Object {
        $hash = Get-FileHash -Path $_.FullName -Algorithm SHA256 -ErrorAction SilentlyContinue
        [PSCustomObject]@{
            File = $_.FullName
            Size = $_.Length
            Created = $_.CreationTime
            Modified = $_.LastWriteTime
            SHA256 = $hash.Hash
        }
    }
}

# Usage: Get-FileHashAnalysis -Path "C:\Windows\System32"
```

### Large File Detection (Potential Data Staging)
```powershell
Get-ChildItem -Path C:\ -Recurse -File -ErrorAction SilentlyContinue | 
Where-Object {$_.Length -gt 100MB} | 
Select-Object FullName, @{Name="SizeMB";Expression={[math]::Round($_.Length/1MB,2)}}, CreationTime, LastWriteTime | 
Sort-Object SizeMB -Descending
```

### Hidden File Detection
```powershell
Get-ChildItem -Path C:\ -Recurse -Hidden -ErrorAction SilentlyContinue | 
Where-Object {$_.Extension -in @(".exe",".dll",".scr",".bat",".cmd")} |
Select-Object FullName, Attributes, CreationTime, LastWriteTime
```

## Registry Analysis

### Startup Program Analysis
```powershell
$runKeys = @(
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
    "HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Run"
)

foreach ($key in $runKeys) {
    if (Test-Path $key) {
        Get-ItemProperty -Path $key | ForEach-Object {
            $_.PSObject.Properties | Where-Object {$_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")} | ForEach-Object {
                [PSCustomObject]@{
                    Registry = $key
                    Name = $_.Name
                    Value = $_.Value
                    Suspicious = ($_.Value -match "temp|appdata|programdata|\.tmp|\.bat|powershell|cmd")
                }
            }
        }
    }
}
```

### Registry Persistence Locations
```powershell
$persistenceKeys = @(
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows",
    "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options",
    "HKLM:\SYSTEM\CurrentControlSet\Services",
    "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders"
)

foreach ($key in $persistenceKeys) {
    if (Test-Path $key) {
        Write-Host "Checking: $key" -ForegroundColor Yellow
        Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | Format-List
    }
}
```

### Recently Modified Registry Keys
```powershell
function Get-RecentRegistryChanges {
    param([int]$DaysBack = 1)
    
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    
    Get-ChildItem -Path "HKLM:\SOFTWARE" -Recurse -ErrorAction SilentlyContinue | 
    Where-Object {$_.LastWriteTime -gt $cutoffDate} |
    Select-Object Name, LastWriteTime | 
    Sort-Object LastWriteTime -Descending
}

Get-RecentRegistryChanges -DaysBack 1
```

### Suspicious Registry Values
```powershell
function Find-SuspiciousRegistryValues {
    $suspiciousPatterns = @("temp","appdata","programdata","\.tmp","\.bat","powershell","cmd","rundll32","regsvr32","mshta")
    
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" -ErrorAction SilentlyContinue | 
    ForEach-Object {
        $_.PSObject.Properties | Where-Object {
            $_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider") -and
            ($suspiciousPatterns | Where-Object {$_.Value -match $_})
        } | ForEach-Object {
            [PSCustomObject]@{
                Key = "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run"
                Name = $_.Name
                Value = $_.Value
                Reason = "Matches suspicious pattern"
            }
        }
    }
}

Find-SuspiciousRegistryValues
```

## User and Security Analysis

### User Account Analysis
```powershell
Get-LocalUser | Select-Object Name, Enabled, LastLogon, PasswordLastSet, PasswordExpires, Description | 
Where-Object {$_.Enabled -eq $true}
```

### Administrative Users
```powershell
Get-LocalGroupMember -Group "Administrators" | 
Select-Object Name, ObjectClass, PrincipalSource
```

### Recent Logon Analysis
```powershell
Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624} -MaxEvents 50 | 
ForEach-Object {
    $xml = [xml]$_.ToXml()
    [PSCustomObject]@{
        Time = $_.TimeCreated
        User = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"} | Select-Object -ExpandProperty '#text'
        LogonType = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "LogonType"} | Select-Object -ExpandProperty '#text'
        SourceIP = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "IpAddress"} | Select-Object -ExpandProperty '#text'
        WorkstationName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "WorkstationName"} | Select-Object -ExpandProperty '#text'
    }
} | Where-Object {$_.SourceIP -ne "-" -and $_.SourceIP -ne "127.0.0.1"}
```

### Privilege Analysis
```powershell
whoami /priv | ConvertFrom-Csv -Delimiter ' ' -Header "Privilege","Description","State" | 
Where-Object {$_.State -eq "Enabled"}
```

### Security Policy Analysis
```powershell
secedit /export /cfg temp_security.txt | Out-Null
Get-Content temp_security.txt | Where-Object {$_ -match "MinimumPasswordLength|MaximumPasswordAge|LockoutThreshold"}
Remove-Item temp_security.txt
```

## System Configuration Analysis

### Installed Software Detection
```powershell
Get-WmiObject -Class Win32_Product | 
Select-Object Name, Version, InstallDate, Vendor | 
Where-Object {$_.Vendor -notmatch "Microsoft|Intel|AMD|NVIDIA" -and $_.Name -notmatch "Windows|Visual C\+\+"}
```

### Scheduled Tasks Analysis
```powershell
Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | 
ForEach-Object {
    $task = $_
    $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction SilentlyContinue
    $action = $task.Actions | Select-Object -First 1
    
    [PSCustomObject]@{
        TaskName = $task.TaskName
        TaskPath = $task.TaskPath
        State = $task.State
        LastRunTime = $info.LastRunTime
        NextRunTime = $info.NextRunTime
        Execute = $action.Execute
        Arguments = $action.Arguments
        WorkingDirectory = $action.WorkingDirectory
        Suspicious = ($action.Execute -match "powershell|cmd|rundll32|regsvr32|mshta" -or $action.Execute -match "temp|appdata|programdata")
    }
} | Where-Object {$_.Suspicious -eq $true}
```

### System Driver Analysis
```powershell
Get-WmiObject Win32_SystemDriver | 
Where-Object {$_.State -eq "Running"} |
Select-Object Name, DisplayName, PathName, Started | 
Where-Object {$_.PathName -notmatch "windows|system32|drivers"}
```

### Startup Program Analysis
```powershell
Get-WmiObject Win32_StartupCommand | 
Select-Object Name, Command, Location, User | 
Where-Object {$_.Command -match "temp|appdata|programdata|\.bat|\.cmd|powershell|cmd"}
```

## Event Log Analysis

### Security Event Analysis
```powershell
function Get-SecurityEvents {
    param(
        [int[]]$EventIDs = @(4624,4625,4672,4688,4720,4728),
        [int]$Hours = 24
    )
    
    $startTime = (Get-Date).AddHours(-$Hours)
    
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=$EventIDs; StartTime=$startTime} | 
    ForEach-Object {
        $xml = [xml]$_.ToXml()
        [PSCustomObject]@{
            Time = $_.TimeCreated
            EventID = $_.Id
            Level = $_.LevelDisplayName
            Message = $_.Message
            User = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "TargetUserName"} | Select-Object -ExpandProperty '#text'
        }
    }
}

Get-SecurityEvents -Hours 24
```

### PowerShell Execution Monitoring
```powershell
Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-PowerShell/Operational'; ID=4103,4104} -MaxEvents 100 | 
ForEach-Object {
    $xml = [xml]$_.ToXml()
    $scriptBlock = $xml.Event.EventData.Data.'#text' | Where-Object {$_ -match "Invoke-|DownloadString|EncodedCommand|FromBase64String"}
    if ($scriptBlock) {
        [PSCustomObject]@{
            Time = $_.TimeCreated
            EventID = $_.Id
            ScriptBlock = $scriptBlock
            Suspicious = ($scriptBlock -match "Invoke-Expression|DownloadString|bypass|hidden|EncodedCommand|FromBase64String|Invoke-Shellcode|Invoke-Mimikatz")
        }
    }
} | Where-Object {$_.Suspicious -eq $true}
```

### System Event Analysis
```powershell
Get-WinEvent -FilterHashtable @{LogName='System'; ID=7034,7035,7036,7040,7045} -MaxEvents 50 | 
ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        EventID = $_.Id
        Level = $_.LevelDisplayName
        Source = $_.ProviderName
        Message = $_.Message
    }
} | Sort-Object Time -Descending
```

### Application Crash Analysis
```powershell
Get-WinEvent -FilterHashtable @{LogName='Application'; ID=1000,1001} -MaxEvents 20 | 
ForEach-Object {
    [PSCustomObject]@{
        Time = $_.TimeCreated
        Application = ($_.Message -split '\r?\n')[0]
        FaultingModule = ($_.Message -split '\r?\n')[1]
        ExceptionCode = ($_.Message -split '\r?\n')[2]
    }
}
```

## Malware Detection Functions

### Behavioral Analysis
```powershell
function Get-SuspiciousBehavior {
    $results = @()
    
    # Check for processes with suspicious characteristics
    Get-Process | ForEach-Object {
        $suspicious = $false
        $reasons = @()
        
        # Check for unsigned executables
        if ($_.Path) {
            $signature = Get-AuthenticodeSignature -FilePath $_.Path -ErrorAction SilentlyContinue
            if ($signature.Status -ne "Valid") {
                $suspicious = $true
                $reasons += "Unsigned executable"
            }
        }
        
        # Check for unusual locations
        if ($_.Path -match "temp|appdata|programdata") {
            $suspicious = $true
            $reasons += "Running from suspicious location"
        }
        
        # Check for high resource usage
        if ($_.CPU -gt 80 -or $_.WorkingSet -gt 500MB) {
            $suspicious = $true
            $reasons += "High resource usage"
        }
        
        # Check for suspicious process names
        if ($_.ProcessName -match "svchost|explorer|winlogon" -and $_.Path -notmatch "windows") {
            $suspicious = $true
            $reasons += "Suspicious process name mimicking system process"
        }
        
        if ($suspicious) {
            $results += [PSCustomObject]@{
                ProcessName = $_.ProcessName
                PID = $_.Id
                Path = $_.Path
                StartTime = $_.StartTime
                CPU = $_.CPU
                WorkingSet = [math]::Round($_.WorkingSet/1MB,2)
                Reasons = $reasons -join "; "
            }
        }
    }
    
    return $results
}

Get-SuspiciousBehavior
```

### Injection Detection
```powershell
function Get-ProcessInjection {
    Get-Process | ForEach-Object {
        try {
            $modules = $_.Modules | Where-Object {
                $_.FileName -notmatch "windows|program files" -or
                $_.ModuleName -match "ntdll|kernel32|advapi32" -and $_.FileName -notmatch "system32"
            }
            
            if ($modules) {
                [PSCustomObject]@{
                    ProcessName = $_.ProcessName
                    PID = $_.Id
                    SuspiciousModules = ($modules | Select-Object -ExpandProperty FileName) -join "; "
                }
            }
        }
        catch {
            # Access denied - might be suspicious
            [PSCustomObject]@{
                ProcessName = $_.ProcessName
                PID = $_.Id
                SuspiciousModules = "Access Denied (Potential Protection)"
            }
        }
    }
}

Get-ProcessInjection
```

### Persistence Mechanism Detection
```powershell
function Get-PersistenceMechanisms {
    $results = @()
    
    # Check Run keys
    $runKeys = @(
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run",
        "HKLM:\Software\Microsoft\Windows\CurrentVersion\RunOnce",
        "HKCU:\Software\Microsoft\Windows\CurrentVersion\RunOnce"
    )
    
    foreach ($key in $runKeys) {
        if (Test-Path $key) {
            Get-ItemProperty -Path $key -ErrorAction SilentlyContinue | ForEach-Object {
                $_.PSObject.Properties | Where-Object {$_.Name -notin @("PSPath","PSParentPath","PSChildName","PSDrive","PSProvider")} | ForEach-Object {
                    $results += [PSCustomObject]@{
                        Type = "Registry Run Key"
                        Location = $key
                        Name = $_.Name
                        Value = $_.Value
                        Suspicious = ($_.Value -match "temp|appdata|programdata|powershell|cmd")
                    }
                }
            }
        }
    }
    
    # Check scheduled tasks
    Get-ScheduledTask | Where-Object {$_.State -eq "Ready"} | ForEach-Object {
        $action = $_.Actions | Select-Object -First 1
        if ($action.Execute -match "temp|appdata|programdata|powershell|cmd|rundll32|regsvr32|mshta") {
            $results += [PSCustomObject]@{
                Type = "Scheduled Task"
                Location = $_.TaskPath
                Name = $_.TaskName
                Value = "$($action.Execute) $($action.Arguments)"
                Suspicious = $true
            }
        }
    }
    
    # Check services
    Get-WmiObject Win32_Service | Where-Object {
        $_.PathName -match "temp|appdata|programdata" -or
        $_.PathName -notmatch "windows|program files"
    } | ForEach-Object {
        $results += [PSCustomObject]@{
            Type = "Service"
            Location = "Services"
            Name = $_.Name
            Value = $_.PathName
            Suspicious = $true
        }
    }
    
    return $results
}

Get-PersistenceMechanisms | Where-Object {$_.Suspicious -eq $true}
```

## Advanced Threat Hunting

### Memory Analysis
```powershell
function Get-MemoryAnomalies {
    Get-Process | Where-Object {$_.WorkingSet -gt 100MB} | 
    Select-Object ProcessName, Id, @{Name="WorkingSetMB";Expression={[math]::Round($_.WorkingSet/1MB,2)}}, 
    @{Name="PrivateMemoryMB";Expression={[math]::Round($_.PrivateMemorySize64/1MB,2)}}, Path | 
    Sort-Object WorkingSetMB -Descending
}

Get-MemoryAnomalies
```

### Network Process Correlation
```powershell
function Get-NetworkProcessCorrelation {
    $connections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
    $processes = Get-Process
    
    $connections | ForEach-Object {
        $process = $processes | Where-Object {$_.Id -eq $_.OwningProcess}
        [PSCustomObject]@{
            ProcessName = $process.ProcessName
            PID = $_.OwningProcess
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            ProcessPath = $process.Path
            Suspicious = (
                $process.ProcessName -match "powershell|cmd|rundll32|regsvr32|mshta" -or
                $process.Path -match "temp|appdata|programdata" -or
                $_.RemotePort -in @(4444,8080,8443,9999,31337,1337,6666,7777)
            )
        }
    } | Where-Object {$_.Suspicious -eq $true}
}

Get-NetworkProcessCorrelation
```

### File System Timeline Analysis
```powershell
function Get-FileSystemTimeline {
    param(
        [string]$Path = "C:\",
        [int]$DaysBack = 1
    )
    
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    
    Get-ChildItem -Path $Path -Recurse -File -ErrorAction SilentlyContinue |
    Where-Object {
        $_.CreationTime -gt $cutoffDate -or 
        $_.LastWriteTime -gt $cutoffDate -or
        $_.LastAccessTime -gt $cutoffDate
    } |
    Select-Object FullName, CreationTime, LastWriteTime, LastAccessTime, Length |
    Sort-Object CreationTime -Descending
}

Get-FileSystemTimeline -DaysBack 1
```

### Registry Timeline Analysis
```powershell
function Get-RegistryTimeline {
    param([int]$DaysBack = 1)
    
    $cutoffDate = (Get-Date).AddDays(-$DaysBack)
    
    Get-ChildItem -Path "HKLM:\SOFTWARE","HKCU:\SOFTWARE" -Recurse -ErrorAction SilentlyContinue |
    Where-Object {$_.LastWriteTime -gt $cutoffDate} |
    Select-Object Name, LastWriteTime |
    Sort-Object LastWriteTime -Descending
}

Get-RegistryTimeline -DaysBack 1
```

## Automated IOC Detection Suite

### Comprehensive IOC Scanner
```powershell
function Start-IOCDetection {
    param(
        [string]$OutputPath = "IOC_Detection_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
    )
    
    Write-Host "Starting IOC Detection..." -ForegroundColor Green
    
    $results = @{
        SuspiciousProcesses = Get-SuspiciousBehavior
        PersistenceMechanisms = Get-PersistenceMechanisms | Where-Object {$_.Suspicious -eq $true}
        NetworkAnomalies = Get-NetworkProcessCorrelation
        RecentFiles = Get-FileSystemTimeline -DaysBack 1 | Select-Object -First 20
        SecurityEvents = Get-SecurityEvents -Hours 24 | Select-Object -First 20
        MemoryAnomalies = Get-MemoryAnomalies | Select-Object -First 10
    }
    
    # Generate HTML Report
    $html = @"
    <html>
    <head>
        <title>IOC Detection Report - $(Get-Date)</title>
        <style>
            body { font-family: Arial, sans-serif; margin: 20px; }
            h1 { color: #d32f2f; }
            h2 { color: #1976d2; border-bottom: 2px solid #1976d2; }
            table { border-collapse: collapse; width: 100%; margin-bottom: 20px; }
            th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
            th { background-color: #f2f2f2; }
            .suspicious { background-color: #ffebee; }
            .summary { background-color: #e3f2fd; padding: 15px; margin-bottom: 20px; }
        </style>
    </head>
    <body>
        <h1>IOC Detection Report</h1>
        <div class="summary">
            <p><strong>Report Generated:</strong> $(Get-Date)</p>
            <p><strong>Suspicious Processes Found:</strong> $($results.SuspiciousProcesses.Count)</p>
            <p><strong>Persistence Mechanisms Found:</strong> $($results.PersistenceMechanisms.Count)</p>
            <p><strong>Network Anomalies Found:</strong> $($results.NetworkAnomalies.Count)</p>
        </div>
"@
    
    if ($results.SuspiciousProcesses) {
        $html += "<h2>Suspicious Processes</h2>"
        $html += $results.SuspiciousProcesses | ConvertTo-Html -Fragment
    }
    
    if ($results.PersistenceMechanisms) {
        $html += "<h2>Persistence Mechanisms</h2>"
        $html += $results.PersistenceMechanisms | ConvertTo-Html -Fragment
    }
    
    if ($results.NetworkAnomalies) {
        $html += "<h2>Network Anomalies</h2>"
        $html += $results.NetworkAnomalies | ConvertTo-Html -Fragment
    }
    
    $html += "<h2>Recent File Activity</h2>"
    $html += $results.RecentFiles | ConvertTo-Html -Fragment
    
    $html += "<h2>Recent Security Events</h2>"
    $html += $results.SecurityEvents | ConvertTo-Html -Fragment
    
    $html += "<h2>Memory Usage Anomalies</h2>"
    $html += $results.MemoryAnomalies | ConvertTo-Html -Fragment
    
    $html += "</body></html>"
    
    $html | Out-File -FilePath $OutputPath -Encoding UTF8
    Write-Host "Report saved to: $OutputPath" -ForegroundColor Yellow
    
    return $results
}

# Run comprehensive scan
$scanResults = Start-IOCDetection
```

### Real-Time Monitoring System
```powershell
function Start-RealTimeMonitoring {
    param([int]$IntervalSeconds = 30)
    
    Write-Host "Starting Real-Time IOC Monitoring..." -ForegroundColor Green
    Write-Host "Press Ctrl+C to stop monitoring" -ForegroundColor Yellow
    
    $baseline = @{
        Processes = Get-Process | Select-Object Name, Id, Path
        Services = Get-Service | Where-Object {$_.Status -eq "Running"}
        NetworkConnections = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
    }
    
    while ($true) {
        Clear-Host
        Write-Host "=== Real-Time IOC Monitor ===" -ForegroundColor Green
        Write-Host "Time: $(Get-Date)" -ForegroundColor Yellow
        Write-Host "Monitoring interval: $IntervalSeconds seconds" -ForegroundColor Cyan
        Write-Host ""
        
        # Check for new processes
        $currentProcesses = Get-Process | Select-Object Name, Id, Path
        $newProcesses = Compare-Object $baseline.Processes $currentProcesses -Property Name,Id | 
                       Where-Object {$_.SideIndicator -eq "=>"}
        
        if ($newProcesses) {
            Write-Host "NEW PROCESSES DETECTED:" -ForegroundColor Red
            $newProcesses | ForEach-Object {
                $process = Get-Process -Id $_.Id -ErrorAction SilentlyContinue
                if ($process) {
                    Write-Host "  - $($process.ProcessName) (PID: $($process.Id)) Path: $($process.Path)" -ForegroundColor Yellow
                }
            }
            Write-Host ""
        }
        
        # Check for new services
        $currentServices = Get-Service | Where-Object {$_.Status -eq "Running"}
        $newServices = Compare-Object $baseline.Services $currentServices -Property Name | 
                      Where-Object {$_.SideIndicator -eq "=>"}
        
        if ($newServices) {
            Write-Host "NEW SERVICES DETECTED:" -ForegroundColor Red
            $newServices | ForEach-Object {
                Write-Host "  - $($_.Name)" -ForegroundColor Yellow
            }
            Write-Host ""
        }
        
        # Check for suspicious behavior
        $suspicious = Get-SuspiciousBehavior
        if ($suspicious) {
            Write-Host "SUSPICIOUS BEHAVIOR DETECTED:" -ForegroundColor Red
            $suspicious | Select-Object ProcessName, PID, Reasons | Format-Table -AutoSize
        }
        
        # Update baseline
        $baseline.Processes = $currentProcesses
        $baseline.Services = $currentServices
        
        Start-Sleep $IntervalSeconds
    }
}

# Start real-time monitoring
# Start-RealTimeMonitoring -IntervalSeconds 30
```

### Evidence Collection Script
```powershell
function Collect-IOCEvidence {
    param([string]$OutputDir = "IOC_Evidence_$(Get-Date -Format 'yyyyMMdd_HHmmss')")
    
    Write-Host "Collecting IOC Evidence..." -ForegroundColor Green
    
    New-Item -Path $OutputDir -ItemType Directory -Force | Out-Null
    
    # System Information
    Get-ComputerInfo | Out-File "$OutputDir\SystemInfo.txt"
    
    # Process Information
    Get-Process | Select-Object * | Export-Csv "$OutputDir\Processes.csv" -NoTypeInformation
    Get-WmiObject Win32_Process | Select-Object * | Export-Csv "$OutputDir\ProcessDetails.csv" -NoTypeInformation
    
    # Service Information
    Get-Service | Export-Csv "$OutputDir\Services.csv" -NoTypeInformation
    Get-WmiObject Win32_Service | Export-Csv "$OutputDir\ServiceDetails.csv" -NoTypeInformation
    
    # Network Information
    Get-NetTCPConnection | Export-Csv "$OutputDir\NetworkConnections.csv" -NoTypeInformation
    Get-NetUDPEndpoint | Export-Csv "$OutputDir\UDPEndpoints.csv" -NoTypeInformation
    
    # Registry Information
    Get-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Run" | Export-Csv "$OutputDir\Registry_Run_HKLM.csv" -NoTypeInformation
    Get-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Run" | Export-Csv "$OutputDir\Registry_Run_HKCU.csv" -NoTypeInformation
    
    # Scheduled Tasks
    Get-ScheduledTask | Export-Csv "$OutputDir\ScheduledTasks.csv" -NoTypeInformation
    
    # Event Logs
    Get-WinEvent -FilterHashtable @{LogName='Security'; ID=4624,4625,4672,4688} -MaxEvents 1000 | 
    Export-Csv "$OutputDir\SecurityEvents.csv" -NoTypeInformation
    
    # File Hashes
    Get-ChildItem -Path "C:\Windows\System32" -File | 
    ForEach-Object {
        [PSCustomObject]@{
            File = $_.FullName
            SHA256 = (Get-FileHash -Path $_.FullName -Algorithm SHA256).Hash
            Size = $_.Length
            Created = $_.CreationTime
            Modified = $_.LastWriteTime
        }
    } | Export-Csv "$OutputDir\System32Hashes.csv" -NoTypeInformation
    
    Write-Host "Evidence collected in: $OutputDir" -ForegroundColor Yellow
}

# Collect evidence
# Collect-IOCEvidence
```

