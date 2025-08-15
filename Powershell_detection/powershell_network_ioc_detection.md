# PowerShell Network IOC Detection


## PowerShell Network Commands

### Get All Network Connections
```powershell
Get-NetTCPConnection
```

### Network Connections with Process Details
```powershell
Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
```

### UDP Connections
```powershell
Get-NetUDPEndpoint | Select-Object LocalAddress, LocalPort, OwningProcess, @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
```

## IOC Detection Scripts

### 1. Suspicious Outbound Connections

#### External Connections (Non-RFC1918)
```powershell
Get-NetTCPConnection | Where-Object {
    $_.State -eq "Established" -and 
    $_.RemoteAddress -notmatch "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\."
} | Select-Object LocalPort, RemoteAddress, RemotePort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
```

#### Connections to Suspicious Ports
```powershell
Get-NetTCPConnection | Where-Object {
    $_.RemotePort -in @(4444,8080,8443,9999,31337,1337,6666,7777,12345,54321)
} | Select-Object LocalPort, RemoteAddress, RemotePort, State, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
```

#### Unusual Process Network Activity
```powershell
Get-NetTCPConnection | Where-Object {
    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $process.ProcessName -match "powershell|cmd|rundll32|regsvr32|mshta|certutil|bitsadmin|wmic|notepad|calc|winword|excel"
} | Select-Object LocalPort, RemoteAddress, RemotePort, State, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
```

### 2. Process Analysis

#### Processes with High Connection Count
```powershell
Get-NetTCPConnection | Group-Object OwningProcess | Where-Object {$_.Count -gt 10} | 
Select-Object @{Name="ProcessName";Expression={(Get-Process -Id $_.Name -ErrorAction SilentlyContinue).ProcessName}}, 
@{Name="ProcessID";Expression={$_.Name}}, Count | Sort-Object Count -Descending
```

#### System Processes on Unusual Ports
```powershell
Get-NetTCPConnection | Where-Object {
    $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
    $process.ProcessName -eq "svchost" -and $_.LocalPort -notin @(135,445,139,53,80,443,993,995,587,25,110,143,993,995)
} | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State
```

#### Non-Standard Listening Services
```powershell
Get-NetTCPConnection | Where-Object {
    $_.State -eq "Listen" -and 
    $_.LocalPort -notin @(80,443,22,21,25,53,135,139,445,993,995,587,110,143,3389,5985,5986)
} | Select-Object LocalAddress, LocalPort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess).ProcessName}}
```

### 3. Network Pattern Analysis

#### Foreign Address Analysis
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | 
Group-Object RemoteAddress | Sort-Object Count -Descending | 
Select-Object Name, Count, @{Name="Processes";Expression={
    ($_.Group | ForEach-Object {(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName} | Sort-Object -Unique) -join ", "
}}
```

#### Port Usage Statistics
```powershell
Get-NetTCPConnection | Where-Object {$_.State -eq "Established"} | 
Group-Object RemotePort | Sort-Object Count -Descending | 
Select-Object Name, Count | Format-Table -AutoSize
```

#### Connection State Summary
```powershell
Get-NetTCPConnection | Group-Object State | 
Select-Object Name, Count | Sort-Object Count -Descending
```

## Real-Time Monitoring Scripts

### Continuous Network Monitor
```powershell
while ($true) {
    Clear-Host
    Write-Host "=== Network IOC Monitor ===" -ForegroundColor Green
    Write-Host "Time: $(Get-Date)" -ForegroundColor Yellow
    
    Write-Host "`n=== Suspicious Connections ===" -ForegroundColor Red
    Get-NetTCPConnection | Where-Object {
        $_.RemotePort -in @(4444,8080,8443,9999,31337,1337,6666,7777) -or
        (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName -match "powershell|cmd|rundll32|regsvr32|mshta"
    } | Select-Object LocalPort, RemoteAddress, RemotePort, State, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -AutoSize
    
    Write-Host "`n=== External Connections ===" -ForegroundColor Cyan
    Get-NetTCPConnection | Where-Object {
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\."
    } | Select-Object RemoteAddress, RemotePort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | 
    Group-Object RemoteAddress | Select-Object Name, Count | Format-Table -AutoSize
    
    Write-Host "`n=== High Connection Processes ===" -ForegroundColor Yellow
    Get-NetTCPConnection | Group-Object OwningProcess | Where-Object {$_.Count -gt 5} | 
    Select-Object @{Name="Process";Expression={(Get-Process -Id $_.Name -ErrorAction SilentlyContinue).ProcessName}}, Count | 
    Sort-Object Count -Descending | Format-Table -AutoSize
    
    Start-Sleep 10
}
```

### Network Change Detection
```powershell
$baseline = @()
$alertThreshold = 5

while ($true) {
    $current = Get-NetTCPConnection | Where-Object {$_.State -eq "Established"}
    
    if ($baseline.Count -gt 0) {
        $new = Compare-Object $baseline $current -Property RemoteAddress,RemotePort,OwningProcess | 
               Where-Object {$_.SideIndicator -eq "=>"}
        
        if ($new.Count -gt $alertThreshold) {
            Write-Host "ALERT: $($new.Count) new connections detected!" -ForegroundColor Red
            $new | ForEach-Object {
                $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
                Write-Host "New connection: $($_.RemoteAddress):$($_.RemotePort) from $($process.ProcessName)" -ForegroundColor Yellow
            }
        }
    }
    
    $baseline = $current
    Start-Sleep 30
}
```

## Advanced Analysis Functions

### Network Connection Analysis Function
```powershell
function Analyze-NetworkConnections {
    param(
        [string]$ProcessName,
        [int]$Port,
        [string]$RemoteIP
    )
    
    $connections = Get-NetTCPConnection
    
    if ($ProcessName) {
        $connections = $connections | Where-Object {
            (Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName -like "*$ProcessName*"
        }
    }
    
    if ($Port) {
        $connections = $connections | Where-Object {$_.LocalPort -eq $Port -or $_.RemotePort -eq $Port}
    }
    
    if ($RemoteIP) {
        $connections = $connections | Where-Object {$_.RemoteAddress -eq $RemoteIP}
    }
    
    $connections | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, 
    @{Name="ProcessName";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}},
    @{Name="ProcessID";Expression={$_.OwningProcess}}
}

# Usage examples:
# Analyze-NetworkConnections -ProcessName "powershell"
# Analyze-NetworkConnections -Port 4444
# Analyze-NetworkConnections -RemoteIP "192.168.1.100"
```

### Suspicious Process Network Activity
```powershell
function Get-SuspiciousNetworkActivity {
    $suspiciousProcesses = @("powershell", "cmd", "rundll32", "regsvr32", "mshta", "certutil", "bitsadmin", "wmic")
    $suspiciousPorts = @(4444, 8080, 8443, 9999, 31337, 1337, 6666, 7777, 12345, 54321)
    
    $results = @()
    
    # Check for suspicious processes with network activity
    Get-NetTCPConnection | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        if ($process -and $suspiciousProcesses -contains $process.ProcessName) {
            $results += [PSCustomObject]@{
                Type = "Suspicious Process"
                Process = $process.ProcessName
                PID = $_.OwningProcess
                LocalPort = $_.LocalPort
                RemoteAddress = $_.RemoteAddress
                RemotePort = $_.RemotePort
                State = $_.State
            }
        }
    }
    
    # Check for connections to suspicious ports
    Get-NetTCPConnection | Where-Object {$_.RemotePort -in $suspiciousPorts} | ForEach-Object {
        $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
        $results += [PSCustomObject]@{
            Type = "Suspicious Port"
            Process = $process.ProcessName
            PID = $_.OwningProcess
            LocalPort = $_.LocalPort
            RemoteAddress = $_.RemoteAddress
            RemotePort = $_.RemotePort
            State = $_.State
        }
    }
    
    return $results
}

# Usage:
# Get-SuspiciousNetworkActivity | Format-Table -AutoSize
```

## Network Baseline and Comparison

### Create Network Baseline
```powershell
function Create-NetworkBaseline {
    param([string]$BaselinePath = "network_baseline.xml")
    
    $baseline = @{
        Timestamp = Get-Date
        Connections = Get-NetTCPConnection | Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State, OwningProcess
        Processes = Get-Process | Select-Object ProcessName, Id, Path
        ListeningPorts = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | Select-Object LocalPort, OwningProcess
    }
    
    $baseline | Export-Clixml -Path $BaselinePath
    Write-Host "Baseline saved to $BaselinePath"
}
```

### Compare to Baseline
```powershell
function Compare-NetworkBaseline {
    param([string]$BaselinePath = "network_baseline.xml")
    
    if (-not (Test-Path $BaselinePath)) {
        Write-Error "Baseline file not found: $BaselinePath"
        return
    }
    
    $baseline = Import-Clixml -Path $BaselinePath
    $current = Get-NetTCPConnection
    
    Write-Host "Baseline created: $($baseline.Timestamp)" -ForegroundColor Green
    Write-Host "Current time: $(Get-Date)" -ForegroundColor Green
    
    # New listening ports
    $currentListening = $current | Where-Object {$_.State -eq "Listen"}
    $newPorts = Compare-Object $baseline.ListeningPorts $currentListening -Property LocalPort | 
                Where-Object {$_.SideIndicator -eq "=>"}
    
    if ($newPorts) {
        Write-Host "`nNew listening ports detected:" -ForegroundColor Yellow
        $newPorts | ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            Write-Host "Port $($_.LocalPort) - Process: $($process.ProcessName)" -ForegroundColor Red
        }
    }
    
    # New external connections
    $currentExternal = $current | Where-Object {
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\."
    }
    
    $baselineExternal = $baseline.Connections | Where-Object {
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\."
    }
    
    $newExternal = Compare-Object $baselineExternal $currentExternal -Property RemoteAddress,RemotePort | 
                   Where-Object {$_.SideIndicator -eq "=>"}
    
    if ($newExternal) {
        Write-Host "`nNew external connections detected:" -ForegroundColor Yellow
        $newExternal | ForEach-Object {
            Write-Host "Connection to $($_.RemoteAddress):$($_.RemotePort)" -ForegroundColor Red
        }
    }
}
```

## Network Traffic Analysis

### DNS Resolution Monitoring
```powershell
function Monitor-DNSResolution {
    $dnsEvents = Get-WinEvent -FilterHashtable @{LogName='Microsoft-Windows-DNS-Client/Operational'; ID=3008} -MaxEvents 100
    
    $dnsEvents | ForEach-Object {
        $xml = [xml]$_.ToXml()
        $queryName = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "QueryName"} | Select-Object -ExpandProperty '#text'
        
        if ($queryName -match "suspicious|malware|bad|evil|temp|dynamic") {
            [PSCustomObject]@{
                Time = $_.TimeCreated
                QueryName = $queryName
                ProcessId = $xml.Event.EventData.Data | Where-Object {$_.Name -eq "ProcessId"} | Select-Object -ExpandProperty '#text'
            }
        }
    } | Format-Table -AutoSize
}
```

### Network Interface Statistics
```powershell
Get-NetAdapter | Where-Object {$_.Status -eq "Up"} | ForEach-Object {
    $stats = Get-NetAdapterStatistics -Name $_.Name
    [PSCustomObject]@{
        Interface = $_.Name
        BytesReceived = $stats.BytesReceived
        BytesSent = $stats.BytesSent
        PacketsReceived = $stats.PacketsReceived
        PacketsSent = $stats.PacketsSent
    }
} | Format-Table -AutoSize
```

## Automated Reporting

### Generate Network Security Report
```powershell
function Generate-NetworkSecurityReport {
    param([string]$OutputPath = "NetworkSecurityReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html")
    
    $html = @"
    <html>
    <head><title>Network Security Report - $(Get-Date)</title></head>
    <body>
    <h1>Network Security Report</h1>
    <p>Generated: $(Get-Date)</p>
    
    <h2>Suspicious Network Activity</h2>
"@
    
    $suspicious = Get-SuspiciousNetworkActivity
    if ($suspicious) {
        $html += $suspicious | ConvertTo-Html -Fragment
    } else {
        $html += "<p>No suspicious activity detected.</p>"
    }
    
    $html += @"
    <h2>External Connections</h2>
"@
    
    $external = Get-NetTCPConnection | Where-Object {
        $_.State -eq "Established" -and 
        $_.RemoteAddress -notmatch "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\."
    } | Select-Object RemoteAddress, RemotePort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
    
    $html += $external | ConvertTo-Html -Fragment
    
    $html += @"
    <h2>Listening Services</h2>
"@
    
    $listening = Get-NetTCPConnection | Where-Object {$_.State -eq "Listen"} | 
                 Select-Object LocalAddress, LocalPort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}}
    
    $html += $listening | ConvertTo-Html -Fragment
    
    $html += "</body></html>"
    
    $html | Out-File -FilePath $OutputPath
    Write-Host "Report saved to: $OutputPath"
}
```

## Quick Investigation Commands

### Investigate Specific Process
```powershell
function Investigate-ProcessNetwork {
    param([int]$ProcessID)
    
    $process = Get-Process -Id $ProcessID -ErrorAction SilentlyContinue
    if (-not $process) {
        Write-Error "Process with ID $ProcessID not found"
        return
    }
    
    Write-Host "Investigating process: $($process.ProcessName) (PID: $ProcessID)" -ForegroundColor Green
    Write-Host "Path: $($process.Path)" -ForegroundColor Yellow
    
    Write-Host "`nNetwork Connections:" -ForegroundColor Cyan
    Get-NetTCPConnection | Where-Object {$_.OwningProcess -eq $ProcessID} | 
    Select-Object LocalAddress, LocalPort, RemoteAddress, RemotePort, State | Format-Table -AutoSize
    
    Write-Host "`nUDP Endpoints:" -ForegroundColor Cyan
    Get-NetUDPEndpoint | Where-Object {$_.OwningProcess -eq $ProcessID} | 
    Select-Object LocalAddress, LocalPort | Format-Table -AutoSize
}

# Usage: Investigate-ProcessNetwork -ProcessID 1234
```

### Investigate Remote IP
```powershell
function Investigate-RemoteIP {
    param([string]$IPAddress)
    
    Write-Host "Investigating connections to: $IPAddress" -ForegroundColor Green
    
    $connections = Get-NetTCPConnection | Where-Object {$_.RemoteAddress -eq $IPAddress}
    
    if ($connections) {
        $connections | ForEach-Object {
            $process = Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue
            [PSCustomObject]@{
                LocalPort = $_.LocalPort
                RemotePort = $_.RemotePort
                State = $_.State
                Process = $process.ProcessName
                PID = $_.OwningProcess
                ProcessPath = $process.Path
            }
        } | Format-Table -AutoSize
    } else {
        Write-Host "No active connections found to $IPAddress"
    }
}

# Usage: Investigate-RemoteIP -IPAddress "192.168.1.100"
```

## Usage Examples

### Daily Security Check
```powershell
Write-Host "=== Daily Network Security Check ===" -ForegroundColor Green
Write-Host "Date: $(Get-Date)" -ForegroundColor Yellow

Write-Host "`n1. Checking for suspicious network activity..." -ForegroundColor Cyan
$suspicious = Get-SuspiciousNetworkActivity
if ($suspicious) {
    $suspicious | Format-Table -AutoSize
} else {
    Write-Host "No suspicious activity detected." -ForegroundColor Green
}

Write-Host "`n2. External connections summary..." -ForegroundColor Cyan
Get-NetTCPConnection | Where-Object {$_.State -eq "Established" -and $_.RemoteAddress -notmatch "^192\.168\.|^10\.|^172\.(1[6-9]|2[0-9]|3[0-1])\.|^127\."} | 
Group-Object RemoteAddress | Select-Object Name, Count | Sort-Object Count -Descending | Format-Table -AutoSize

Write-Host "`n3. Unusual listening ports..." -ForegroundColor Cyan
Get-NetTCPConnection | Where-Object {$_.State -eq "Listen" -and $_.LocalPort -notin @(80,443,22,21,25,53,135,139,445,3389,5985,5986)} | 
Select-Object LocalPort, @{Name="Process";Expression={(Get-Process -Id $_.OwningProcess -ErrorAction SilentlyContinue).ProcessName}} | Format-Table -AutoSize
```

