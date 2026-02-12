# Threat Hunt Report (CorpHealth Traceback)

## Bad Actor Activity Summary:
1. Identify the suspicious endpoint where CorpHealth/Ops maintenance PowerShell activity deviated from baseline (CH-OPS-WKS02).
2. Confirm a host-unique maintenance script executed only on CH-OPS-WKS02 (MaintenanceRunner_Distributed.ps1).
3. Validate the script generated outbound network activity and identify the destination (loopback 127.0.0.1:8080) and the successful connection timestamp.
4. Track staging activity in trusted directories, including CorpHealth diagnostics inventory artifacts (inventory_6ECFD4DF.csv and a temp duplicate inventory_tmp_6ECFD4DF.csv).
5. Identify registry tampering related to EventLog and persistence attempts (TaskCache Tree key, Run key value).
6. Confirm simulated privilege escalation indicators (ConfigAdjust) and token manipulation events, including the initiating process ID and the user SID impacted.
7. Identify external tool ingress via curl, including the exact tunnel URL used to download an executable (revshell.exe).
8. Confirm execution of the staged binary, outbound C2-like traffic attempts (external IP and port), and persistence via Startup folder placement.
9. Pivot on remote session metadata to identify the attacker session device name, remote session IPs (entry and internal pivot), and the earliest successful logon event (timestamp, IP, account).
10. Reconstruct early attacker actions after initial access, including the first process launched, first credential-related file accessed, and the next account accessed.

---

## MDE Tables Referenced:

| Parameter | Description |
| --- | --- |
| Name | DeviceProcessEvents |
| Info | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceprocessevents-table |
| Purpose | Used to identify suspicious script execution, encoded PowerShell execution, AV exclusion attempts, first post-logon process activity, and execution context for attacker actions. |
| Name | DeviceNetworkEvents |
| Info | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicenetworkevents-table |
| Purpose | Used to identify script-driven beaconing behavior, remote session metadata, and outbound connection attempts from revshell.exe (including IP/port). |
| Name | DeviceFileEvents |
| Info | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicefileevents-table |
| Purpose | Used to identify staging artifacts in trusted directories, integrity (SHA256), external tool download creation, and Startup folder persistence placement. |
| Name | DeviceRegistryEvents |
| Info | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceregistryevents-table |
| Purpose | Used to identify registry tampering, TaskCache persistence artifacts, and Run key persistence behavior. |
| Name | DeviceEvents |
| Info | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-deviceevents-table |
| Purpose | Used to identify ConfigAdjust events and token modification telemetry tied to the malicious maintenance script execution. |
| Name | DeviceLogonEvents |
| Info | https://learn.microsoft.com/en-us/defender-xdr/advanced-hunting-devicelogonevents-table |
| Purpose | Used to identify earliest suspicious logon event, source IP, account used, and geographic context tied to attacker remote access. |

---

## Detection Queries

```sql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where ActionType == "ProcessCreated"
| where AccountName has_any ("CorpHealth", "corp", "cp")
| where AdditionalFields !contains "linux"
| project TimeGenerated, AccountName, AccountDomain, ActionType, DeviceName,
AdditionalFields, ProcessCommandLine, FileName
| sort by TimeGenerated asc
```

```sql
let StartTime = datetime(2025-11-15);
let EndTime = datetime(2025-12-16);
let TargetDevice = "ch-ops-wks02";

let ScriptRuns =
 DeviceProcessEvents
 | where TimeGenerated between (StartTime .. EndTime)
 | where ActionType == "ProcessCreated"
 | where ProcessCommandLine has ".ps1"
 | where ProcessCommandLine has_any (@"\Corp\Ops\", "CorpHealth", "maintenance", "ops")
 | extend ScriptName = extract(@"([^\\]+\.ps1)", 1, ProcessCommandLine)
 | where isnotempty(ScriptName)
 | project TimeGenerated, DeviceName, AccountName, ScriptName, ProcessCommandLine;

let OnTarget =
 ScriptRuns
 | where DeviceName == TargetDevice
 | summarize TargetCount = count(),
             FirstSeen = min(TimeGenerated),
             LastSeen = max(TimeGenerated),
             CommandLine = any(ProcessCommandLine)
   by ScriptName;

let OnOthers =
 ScriptRuns
 | where DeviceName != TargetDevice
 | summarize OtherDeviceCount = dcount(DeviceName) by ScriptName;

OnTarget
| join kind=leftouter OnOthers on ScriptName
| extend OtherDeviceCount = coalesce(OtherDeviceCount, 0)
| project ScriptName, TargetCount, OtherDeviceCount, FirstSeen, LastSeen, CommandLine
| order by FirstSeen asc
```

```sql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project
    TimeGenerated,
    ActionType,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName,
    RemoteIP,
    RemoteIPType,
    RemotePort,
    Protocol
| order by TimeGenerated asc
```

```sql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has_any ("MaintenanceRunner_Distributed.ps1")
| project
    TimeGenerated,
    ActionType,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessCommandLine,
    InitiatingProcessFileName,
    RemoteIP,
    RemoteIPType,
    RemotePort,
    Protocol
| order by TimeGenerated asc 
```

```sql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| where ActionType == "ConnectionSuccess"
| summarize LatestConnection = max(TimeGenerated),
            RemoteIP = "127.0.0.1",
            RemotePort = "8080"
```

```sql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
 and ActionType == "FileCreated"
| where FolderPath has_any ("Diagnostics", "CorpHealth")
| project TimeGenerated, ActionType, DeviceName, FolderPath, FileName
| order by TimeGenerated desc
```

```sql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
    and ActionType == "FileCreated"
| where FolderPath contains @"C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv"
| project TimeGenerated, ActionType, DeviceName, FolderPath, FileName, SHA256
| order by TimeGenerated desc
```

```sql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
    and ActionType == "FileCreated"
// | where FolderPath contains @"C:\ProgramData\Microsoft\Diagnostics\CorpHealth"
| where FileName has_any ( "inventory_")
| project TimeGenerated, ActionType, DeviceName, FolderPath, FileName, SHA256
| order by TimeGenerated desc
```

```sql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26))
| where DeviceName == "ch-ops-wks02"
| where ActionType has_any ("RegistryKeyCreated", "RegistryValueSet")
| where InitiatingProcessCommandLine contains ".ps1"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, RegistryKey
| order by TimeGenerated desc
```

```sql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26))
| where DeviceName == "ch-ops-wks02"
| where ActionType has_any ("RegistryKeyCreated", "RegistryValueSet")
| where RegistryKey contains "TaskCache"
| project TimeGenerated, InitiatingProcessAccountName, ActionType, DeviceName, InitiatingProcessCommandLine, RegistryKey
| order by TimeGenerated asc
```

```sql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26))
| where DeviceName == "ch-ops-wks02"
| where ActionType has_any ("RegistryKeyCreated", "RegistryValueSet", "RegistryKeyDeleted")
| where InitiatingProcessCommandLine contains ".ps1"
| where InitiatingProcessAccountName == "ops.maintenance"
| project TimeGenerated, InitiatingProcessAccountName, ActionType, InitiatingProcessCommandLine, RegistryKey, RegistryValueName
| order by TimeGenerated desc
```

```sql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-11-26))
| where DeviceName =~ "ch-ops-wks02"
| where InitiatingProcessFileName =~ "powershell.exe" or ProcessCommandLine has "powershell"
| where tostring(AdditionalFields) has "ConfigAdjust"
| project TimeGenerated, ActionType, AccountName, InitiatingProcessFileName, ProcessCommandLine, AdditionalFields
| order by TimeGenerated asc
```

```sql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName =~ "ch-ops-wks02"
| where ProcessCommandLine has_any ("-ExclusionPath ",  "Add-MpPreference")
| project TimeGenerated, ActionType, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc
```

```sql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName =~ "ch-ops-wks02"
| where ProcessCommandLine has "-EncodedCommand"
| where AccountName !in ("system", "nt authority\\system", "local system")
| extend Enc = extract(@"(?i)-EncodedCommand\s+([A-Za-z0-9+/=]+)", 1, ProcessCommandLine)
| extend Bytes = base64_decode_toarray(Enc)
| mv-expand b = Bytes
| where tolong(b) != 0
| summarize Decoded = unicode_codepoints_to_string(make_list(tolong(b)))
    by TimeGenerated, DeviceName, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc
| take 1
| project TimeGenerated, AccountName, Decoded
```

```sql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-26))
| where DeviceName =~ "ch-ops-wks02"
| where ( tostring(AdditionalFields) has_any ("Add-tokenChangeDescription", "Privileges were added"))
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project
    TimeGenerated,
    ActionType,
    AccountName,
    InitiatingProcessId,
    InitiatingProcessCommandLine,
    AdditionalFields
| order by TimeGenerated asc
```

```sql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-26))
| where DeviceName =~ "ch-ops-wks02"
| where AdditionalFields contains "tokenChangeDescription"
| where InitiatingProcessCommandLine has "MaintenanceRunner_Distributed.ps1"
| project
    TimeGenerated,
    ActionType,
    AccountName,
    InitiatingProcessId,
    InitiatingProcessCommandLine,
    AdditionalFields
| order by TimeGenerated asc
```
## Created By:

- **Author Name**: Juan Saravia
- **Author Contact**: https://www.linkedin.com/in/juan-francisco-saravia-300634233/
- **Date**: January 25, 2026
