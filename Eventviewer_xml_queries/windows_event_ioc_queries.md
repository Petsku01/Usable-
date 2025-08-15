# Windows Event Viewer IOC Detection Queries


## Queries

### 1. Initial Access & Authentication

#### Failed Authentication Attacks (Brute Force Detection)
**Event IDs**: 4625  
**Purpose**: Detect brute force and password spray attacks
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4625)] and EventData[Data[@Name='Status']='0xC000006A' or Data[@Name='Status']='0xC0000064']]
    </Select>
  </Query>
</QueryList>
```

#### Remote Desktop Logon Monitoring
**Event IDs**: 4624  
**Purpose**: Monitor remote desktop logons for unauthorized access
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4624)] and EventData[Data[@Name='LogonType']='10']]
    </Select>
  </Query>
</QueryList>
```

### 2. Execution & Process Activity

#### Suspicious Process Creation
**Event IDs**: 4688  
**Purpose**: Detect execution of potentially malicious tools and scripts
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4688)] and EventData[Data[@Name='NewProcessName'] and (
        contains(., 'powershell.exe') or 
        contains(., 'cmd.exe') or 
        contains(., 'wscript.exe') or 
        contains(., 'cscript.exe') or 
        contains(., 'mshta.exe') or
        contains(., 'rundll32.exe') or
        contains(., 'regsvr32.exe') or
        contains(., 'certutil.exe') or
        contains(., 'bitsadmin.exe')
      )]]
      and EventData[Data[@Name='CommandLine'] and (
        contains(., '-enc') or 
        contains(., 'bypass') or 
        contains(., 'hidden') or 
        contains(., 'downloadstring') or
        contains(., 'invoke-expression') or
        contains(., 'iex') or
        contains(., 'base64')
      )]
    </Select>
  </Query>
</QueryList>
```

#### PowerShell Execution Monitoring
**Event IDs**: 4103, 4104  
**Purpose**: Monitor PowerShell script execution for malicious activity
```xml
<QueryList>
  <Query Id="0" Path="Microsoft-Windows-PowerShell/Operational">
    <Select Path="Microsoft-Windows-PowerShell/Operational">
      *[System[(EventID=4103 or EventID=4104)] and EventData[Data and (
        contains(., 'Invoke-Expression') or 
        contains(., 'DownloadString') or 
        contains(., 'System.Net.WebClient') or 
        contains(., 'bypass') or 
        contains(., 'unrestricted') or
        contains(., 'EncodedCommand') or
        contains(., 'FromBase64String') or
        contains(., 'Invoke-Shellcode') or
        contains(., 'Invoke-Mimikatz')
      )]]
    </Select>
  </Query>
</QueryList>
```

### 3. Privilege Escalation

#### Special Privileges Assigned
**Event IDs**: 4672  
**Purpose**: Detect privilege escalation attempts and administrative access
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4672)] and EventData[Data[@Name='PrivilegeList'] and (
        contains(., 'SeDebugPrivilege') or 
        contains(., 'SeTakeOwnershipPrivilege') or 
        contains(., 'SeLoadDriverPrivilege') or
        contains(., 'SeTcbPrivilege') or
        contains(., 'SeBackupPrivilege') or
        contains(., 'SeRestorePrivilege')
      )]]
      and EventData[Data[@Name='SubjectUserName'] != 'SYSTEM' and Data[@Name='SubjectUserName'] != 'LOCAL SERVICE' and Data[@Name='SubjectUserName'] != 'NETWORK SERVICE']
    </Select>
  </Query>
</QueryList>
```

#### Privileged Service Operations
**Event IDs**: 4673, 4674  
**Purpose**: Monitor privileged service calls and object access
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4673 or EventID=4674)] and EventData[Data[@Name='PrivilegeList'] and (
        contains(., 'SeDebugPrivilege') or 
        contains(., 'SeLoadDriverPrivilege') or 
        contains(., 'SeTakeOwnershipPrivilege')
      )]]
      and EventData[Data[@Name='ProcessName'] and (
        contains(., 'powershell.exe') or 
        contains(., 'cmd.exe') or 
        contains(., 'wmic.exe') or
        contains(., 'reg.exe') or
        contains(., 'net.exe')
      )]
    </Select>
  </Query>
</QueryList>
```

### 4. Defense Evasion & Persistence

#### Account Manipulation
**Event IDs**: 4720, 4722, 4724, 4726, 4738  
**Purpose**: Detect account creation, modification, and suspicious changes
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4720 or EventID=4722 or EventID=4724 or EventID=4726 or EventID=4738)]]
    </Select>
  </Query>
</QueryList>
```

#### Administrative Group Changes
**Event IDs**: 4728, 4732, 4756  
**Purpose**: Monitor additions to privileged groups
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4728 or EventID=4732 or EventID=4756)] and EventData[Data[@Name='TargetUserName'] and (
        contains(., 'Administrators') or 
        contains(., 'Domain Admins') or 
        contains(., 'Enterprise Admins') or 
        contains(., 'Backup Operators') or
        contains(., 'Account Operators') or
        contains(., 'Server Operators')
      )]]
    </Select>
  </Query>
</QueryList>
```

#### Service Installation/Modification
**Event IDs**: 7034, 7035, 7036, 7040, 7045  
**Purpose**: Detect service-based persistence mechanisms
```xml
<QueryList>
  <Query Id="0" Path="System">
    <Select Path="System">
      *[System[(EventID=7045)] and EventData[Data[@Name='ServiceName'] and not(
        contains(., 'Windows') or 
        contains(., 'Microsoft') or
        contains(., 'Intel') or
        contains(., 'AMD') or
        contains(., 'NVIDIA')
      )]]
      or
      *[System[(EventID=7034 or EventID=7035 or EventID=7036 or EventID=7040)]]
    </Select>
  </Query>
</QueryList>
```

#### Registry Persistence Monitoring
**Event IDs**: 4657  
**Purpose**: Monitor registry modifications in common persistence locations
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4657)] and EventData[Data[@Name='ObjectName'] and (
        contains(., 'CurrentVersion\Run') or 
        contains(., 'CurrentVersion\RunOnce') or 
        contains(., 'Winlogon') or 
        contains(., 'Image File Execution Options') or
        contains(., 'AppInit_DLLs') or
        contains(., 'Shell Folders') or
        contains(., 'Load') or
        contains(., 'Userinit')
      )]]
    </Select>
  </Query>
</QueryList>
```

### 5. Credential Access & File System

#### Critical File Access
**Event IDs**: 4663, 4656  
**Purpose**: Monitor access to sensitive files and directories
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=4663 or EventID=4656)] and EventData[Data[@Name='ObjectName'] and (
        contains(., 'system32') or 
        contains(., 'SysWOW64') or 
        contains(., 'Program Files') or
        contains(., 'SAM') or
        contains(., 'SECURITY') or
        contains(., 'SYSTEM') or
        contains(., 'ntds.dit') or
        contains(., 'lsass')
      )]]
      and EventData[Data[@Name='AccessMask']='0x2' or Data[@Name='AccessMask']='0x40000']
    </Select>
  </Query>
</QueryList>
```

### 6. Lateral Movement & Network Activity

#### Network Share Access Anomalies
**Event IDs**: 5140, 5145  
**Purpose**: Detect suspicious network share access patterns
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=5140 or EventID=5145)] and EventData[Data[@Name='ShareName'] and (
        contains(., 'ADMIN$') or 
        contains(., 'C$') or 
        contains(., 'IPC$')
      )]]
      and EventData[Data[@Name='SubjectUserName'] != 'SYSTEM' and Data[@Name='SubjectUserName'] != '-']
    </Select>
  </Query>
</QueryList>
```

#### Suspicious Network Connections
**Event IDs**: 5156  
**Purpose**: Monitor network connections from suspicious processes
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=5156)] and EventData[Data[@Name='Direction']='%%14593']]
      and (
        EventData[Data[@Name='Application'] and (
          contains(., 'powershell.exe') or 
          contains(., 'cmd.exe') or 
          contains(., 'rundll32.exe') or
          contains(., 'regsvr32.exe') or
          contains(., 'mshta.exe') or
          contains(., 'certutil.exe') or
          contains(., 'bitsadmin.exe') or
          contains(., 'wmic.exe')
        )]
        or
        EventData[Data[@Name='DestPort'] and (
          .='4444' or .='8080' or .='8443' or .='9999' or 
          .='31337' or .='1337' or .='6666' or .='7777'
        )]
      )
    </Select>
  </Query>
</QueryList>
```

#### Lateral Movement via RDP/WinRM
**Event IDs**: 5156  
**Purpose**: Detect lateral movement using common administrative protocols
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      *[System[(EventID=5156)] and EventData[Data[@Name='Direction']='%%14593']]
      and EventData[Data[@Name='DestPort'] and (
        .='135' or .='139' or .='445' or .='3389' or 
        .='5985' or .='5986'
      )]
      and EventData[Data[@Name='DestAddress'] and (
        starts-with(., '10.') or 
        starts-with(., '172.') or 
        starts-with(., '192.168.')
      )]
    </Select>
  </Query>
</QueryList>
```

## Comprehensive Multi-Stage Attack Detection

### Combined Privilege Escalation and Network Activity
```xml
<QueryList>
  <Query Id="0" Path="Security">
    <Select Path="Security">
      (
        *[System[(EventID=4672)] and EventData[Data[@Name='PrivilegeList'] and contains(., 'SeDebugPrivilege')]
        and EventData[Data[@Name='SubjectUserName'] != 'SYSTEM']
      )
      or
      (
        *[System[(EventID=4688)] and EventData[Data[@Name='NewProcessName'] and contains(., 'powershell.exe')]
        and EventData[Data[@Name='TokenElevationType']='%%1937']
      )
      or
      (
        *[System[(EventID=5156)] and EventData[Data[@Name='Direction']='%%14593']]
        and EventData[Data[@Name='Application'] and contains(., 'powershell.exe')]
      )
    </Select>
  </Query>
</QueryList>
```

## Usage Guidelines

### Performance Considerations
- **Resource Impact**: These queries can be resource-intensive; consider using during maintenance windows for large historical searches
- **Batch Processing**: Consider scheduled tasks for regular monitoring
- **Log Volume**: Monitor log file sizes as these queries will return more results without time filters

### Customization Tips
- Modify `contains()` functions to add environment-specific indicators
- Adjust time ranges based on your monitoring requirements
- Add exclusions for known-good applications and processes

### Alert Prioritization
1. **Critical**: Events 4672, 4688 with suspicious command lines
2. **High**: Network connections from system tools (5156)
3. **Medium**: Account modifications (4720-4738)
4. **Low**: Service changes (7045)

### Correlation Recommendations
- Combine multiple event types for complete attack timeline
- Cross-reference with threat intelligence feeds
- Correlate with endpoint detection and response (EDR) tools
- Monitor trends and patterns over time

## Event ID Quick Reference

| Event ID | Category | Description |
|----------|----------|-------------|
| 4624 | Authentication | Successful logon |
| 4625 | Authentication | Failed logon |
| 4672 | Privilege | Special privileges assigned |
| 4673/4674 | Privilege | Privileged service/object access |
| 4688 | Execution | Process creation |
| 4720-4738 | Account Mgmt | Account/group modifications |
| 4656/4663 | File Access | File/object access |
| 4657 | Registry | Registry modification |
| 5140/5145 | Network | Network share access |
| 5156 | Network | Network connection allowed |
| 7034-7045 | Service | Service events |
| 4103/4104 | PowerShell | PowerShell execution |

## Implementation Checklist

- [ ] Enable Security Auditing policies
- [ ] Configure PowerShell logging
- [ ] Set appropriate log retention
- [ ] Test queries in development environment
- [ ] Establish baseline for false positive reduction
- [ ] Create automated alerting mechanisms
- [ ] Document incident response procedures
- [ ] Regular review and tuning of detection rules