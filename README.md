# Threat Hunt Report (CorpHealth Traceback)

## Scenario

During the mid-November maintenance window, routine CorpHealth activity on the operations workstation CH-OPS-WKS02 initially appeared normal (health checks, scheduled runs, configuration updates, and inventory sync). Deeper review showed multiple anomalies:

- Activity occurred outside expected maintenance windows
- Script execution patterns deviated from baseline
- Diagnostic utilities were launched manually instead of via automation
- Several actions aligned with credential compromise or script misuse

Time range used throughout this hunt (unless otherwise noted):
- StartTime: 2025-11-15
- EndTime: 2025-12-16

Primary system of interest:
- CH-OPS-WKS02

---

## High-Level IoC Discovery Plan

1. Identify the workstation showing suspicious CorpHealth activity
2. Establish what “maintenance” script activity is unique vs common across endpoints
3. Validate whether maintenance scripts triggered network activity and identify the destination
4. Track staging activity in trusted directories (Diagnostics / CorpHealth paths)
5. Identify persistence attempts (registry keys, scheduled tasks, Run key behavior)
6. Confirm privilege escalation indicators (token modification) and ownership (SID)
7. Confirm ingress, execution, outbound comms, and persistence of external tooling
8. Pivot on remote session metadata to map attacker origin, pivot host, and first access
9. Reconstruct early attacker actions: initial file access and next account accessed

---

# Findings

## Flag 0: Identify the device

On November 30, 2025, at 12:58 AM UTC, suspicious process activity was observed on ch-ops-wks02 where notepad.exe was used to open a PowerShell script located at C:\ProgramData\Corp\Ops\Generate-CorpHealthTelemetry.ps1. The use of a service account and a script stored in ProgramData indicates potential malicious staging or persistence activity on this device.

Confirmed device:
 - Malicious device identified: ch-ops-wks022
<img width="1700" height="500" alt="image" src="https://github.com/user-attachments/assets/0ae9348b-5218-40ca-96b4-8cb486e93ceb" />



KQL used (Identify Malicious Device via Process Creation):
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

----------------------------------------

## FLAG 1 – Unique Maintenance Script (DeviceProcessEvents)

On November 25, 2025, analysis of maintenance-related script activity during the mid-November window revealed that MaintenanceRunner_Distributed.ps1 was executed exclusively on CH-OPS-WKS02 and did not appear on any other endpoints in the environment. While CorpHealth maintenance scripts are typically standardized and observed across multiple devices, this script was unique to the workstation of interest, indicating it was not part of normal baseline operations. The presence of a host-specific maintenance script establishes CH-OPS-WKS02 as anomalous and provides an early indicator of suspicious activity prior to outbound communication and follow-on attacker actions.

Confirmed flag: 
- MaintenanceRunner_Distributed.ps1
<img width="1071" height="365" alt="image" src="https://github.com/user-attachments/assets/4df65534-30fa-4f17-ac2d-98c3f26a0fc0" />

KQL used (Suspicious Maintenance Script ):

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

---

## Flag 2: Outbound beacon indicator

Between November 23, 2025, and December 2, 2025, a maintenance PowerShell script executed on the affected endpoint generated outbound network activity. The earliest network activity tied to this script occurred on November 23, 2025, at 3:46 AM UTC, when powershell.exe, running the maintenance script, attempted an outbound TCP connection on port 8080. The presence of the script name within the initiating process command line confirms that the network activity was directly triggered by the script’s execution rather than normal background system behavior.

Confirmed timestamp:

- 2025-11-23T03:46:08.400686Z
<img width="1700" height="500" alt="image" src="https://github.com/user-attachments/assets/2af05a8a-fb6d-42d7-a154-42bb8eca27b9" />

KQL used (Outbound network Activity):
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

---

## Flag 3: Identify the Beacon Destination

On November 23, 2025, the malicious maintenance script initiated network activity by launching PowerShell with ExecutionPolicy Bypass and attempting a TCP connection to the loopback address 127.0.0.1 on port 8080. This behavior indicates the script was designed to communicate with a locally hosted service or listener on the endpoint, rather than an external destination, suggesting staged or internally proxied command-and-control–like behavior.

Confirmed Flag:

- 127.0.0.1:8080
<img width="1700" height="500" alt="image" src="https://github.com/user-attachments/assets/637ca4c5-87f8-4ee1-a885-e7e002f90986" />

KQL used (Beacon Identified):

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

---

## Flag 4: Confirm the Successful Beacon Timestamp

On November 30, 2025, at 01:03:17 UTC, the malicious maintenance script executed from C:\ProgramData\Corp\Ops was observed initiating network communication via PowerShell, successfully connecting to a local listener at 127.0.0.1 on port 8080.

Confirmed Flag:

- 2025-11-30T01:03:17.6985973Z
<img width="1600" height="500" alt="image" src="https://github.com/user-attachments/assets/147e7d1b-08a9-4219-b0b8-47de9fd549e6" />

KQL used (LatestConnection): 

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

---

## Flag 5 — Unexpected Staging Activity Detected

On 2025-11-25 04:15 UTC, a diagnostic inventory file named inventory_6ECFD4DF.csv was created under C:\ProgramData\Microsoft\Diagnostics\CorpHealth, indicating the malicious script staged host inventory data in a trusted diagnostics directory, consistent with attacker preparation for data tampering or exfiltration.
Confirmed staging path:

- C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv
<img width="1700" height="500" alt="image" src="https://github.com/user-attachments/assets/3bf757db-39bb-4bde-b487-8d0942812e1c" />

KQL used (StagingDetected):
```sql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
 and ActionType == "FileCreated"
| where FolderPath has_any ("Diagnostics", "CorpHealth")
| project TimeGenerated, ActionType, DeviceName, FolderPath, FileName
| order by TimeGenerated desc

```

---

## Flag 6: Confirm the Staged File’s Integrity

On November 25, 2025, at 04:15:02 UTC, the staged diagnostic inventory file inventory_6ECFD4DF.csv was recovered from C:\ProgramData\Microsoft\Diagnostics\CorpHealth, and its cryptographic fingerprint was identified with a SHA256 hash of 7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8, enabling integrity verification and comparison against threat intelligence sources.

Confirmed Flag:

- 7f6393568e414fc564dad6f49a06a161618b50873404503f82c4447d239f12d8
<img width="1700" height="500" alt="image" src="https://github.com/user-attachments/assets/0207be66-a279-46f2-becc-ecbec77528bf" />

KQL used (IntegrityConfirmed):
```sql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
    and ActionType == "FileCreated"
| where FolderPath contains @"C:\ProgramData\Microsoft\Diagnostics\CorpHealth\inventory_6ECFD4DF.csv"
| project TimeGenerated, ActionType, DeviceName, FolderPath, FileName, SHA256
| order by TimeGenerated desc

```

---

## Flag 7: Identify the Duplicate Staged Artifact

On November 25, 2025, at 04:15:02 UTC, a temporary inventory file named inventory_tmp_6ECFD4DF.csv was created under a user’s AppData Temp directory with a completely different SHA256 hash than the staged diagnostic inventory file, indicating the attacker generated intermediary or decoy versions of the inventory data, likely to test detection, preserve working copies, or confuse responders.

Confirmed Flag:

- C:\Users\ops.maintenance\AppData\Local\Temp\CorpHealth\inventory_tmp_6ECFD4DF.csv
<img width="1085" height="405" alt="image" src="https://github.com/user-attachments/assets/f91a4b04-7383-4f84-b50e-d6c36488a8b5" />

KQL used (DuplicateArtifact):

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

---

## Flag 8: Suspicious Registry Activity

On November 25, 2025, at 04:14:40 UTC, the malicious maintenance PowerShell script modified a registry key at HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent, indicating an attempt to tamper with system configuration tied to the attacker’s credential harvesting simulation stage.

Confirmed Flag:

- HKEY_LOCAL_MACHINE\SYSTEM\ControlSet001\Services\EventLog\Application\CorpHealthAgent
<img width="848" height="386" alt="image" src="https://github.com/user-attachments/assets/82be740e-1172-41c7-a08d-2358c3bb79d0" />

KQL used (SuspiciousRegActivity):

```sql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26))
| where DeviceName == "ch-ops-wks02"
| where ActionType has_any ("RegistryKeyCreated", "RegistryValueSet")
| where InitiatingProcessCommandLine contains ".ps1"
| project TimeGenerated, ActionType, DeviceName, InitiatingProcessCommandLine, RegistryKey
| order by TimeGenerated desc
```

---

## Flag 9: Scheduled Task Persistence

On November 25, 2025 at 04:15:26 UTC, an unauthorized scheduled task was successfully created under HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64, indicating the attacker established a persistence mechanism outside of CorpHealth’s approved task set despite other failed attempts.

Confirmed Flag:

- HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Schedule\TaskCache\Tree\CorpHealth_A65E64
<img width="838" height="311" alt="image" src="https://github.com/user-attachments/assets/b1affec8-19b9-4826-a77b-48fe9cc3f427" />

KQL used (SuccessfulRegEvent): 
```sql
DeviceRegistryEvents
| where TimeGenerated between (datetime(2025-11-25) .. datetime(2025-11-26))
| where DeviceName == "ch-ops-wks02"
| where ActionType has_any ("RegistryKeyCreated", "RegistryValueSet")
| where RegistryKey contains "TaskCache"
| project TimeGenerated, InitiatingProcessAccountName, ActionType, DeviceName, InitiatingProcessCommandLine, RegistryKey
| order by TimeGenerated asc
```

---

## Flag 10: Registry-based Persistence

On November 25, 2025 at 04:24:48 UTC, a new Run key value named MaintenanceRunner was written under HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows\CurrentVersion\Run, pointing to the execution of a PowerShell script, and was deleted shortly after, indicating the attacker used short-lived, ephemeral persistence to execute the script while reducing long-term detection.

Confirmed Flag:

- MaintenanceRunner
<img width="1086" height="333" alt="image" src="https://github.com/user-attachments/assets/61659bf0-5d6d-4d3f-beb2-1176275f1172" />

KQL used:

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

---

## Flag 11: Privilege Escalation Event Timestamp

On November 23, 2025, at 03:47:21 UTC, a PowerShell Application event was generated referencing a “ConfigAdjust” action, indicating the attacker executed a simulated privilege escalation step as part of the MaintenanceRunner sequence prior to establishing persistence.

Confirmed Flag:

- 2025-11-23T03:47:21.8529749Z
<img width="714" height="413" alt="image" src="https://github.com/user-attachments/assets/f536f202-f486-4525-a78e-c21e4bf35666" />

KQL used (#1EscTimeStamp):
```sql
DeviceEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-11-26))
| where DeviceName =~ "ch-ops-wks02"
| where InitiatingProcessFileName =~ "powershell.exe" or ProcessCommandLine has "powershell"
| where tostring(AdditionalFields) has "ConfigAdjust"
| project TimeGenerated, ActionType, AccountName, InitiatingProcessFileName, ProcessCommandLine, AdditionalFields
| order by TimeGenerated asc

```

---

## Flag 12: Identify the AV Exclusion Attempt

On November 23, 2025, at 03:46:37 UTC, PowerShell executed a command attempting to add a Microsoft Defender exclusion for C:\ProgramData\Corp\Ops\staging using Add-MpPreference, and the same command was repeatedly re-executed multiple times across different users throughout the investigation window, indicating the exclusion change likely did not persist, and the attacker repeatedly retried the action to bypass endpoint defenses.

Confirmed Flag:

- C:\ProgramData\Corp\Ops\staging
<img width="1079" height="366" alt="image" src="https://github.com/user-attachments/assets/fadeeb42-0d06-4580-acdf-58123bf4dddb" />

KQL Used (ExcPath):
```sql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName =~ "ch-ops-wks02"
| where ProcessCommandLine has_any ("-ExclusionPath ",  "Add-MpPreference")
| project TimeGenerated, ActionType, AccountName, InitiatingProcessFileName, ProcessCommandLine
| order by TimeGenerated asc
```

---

## Flag 13: PowerShell Encoded Command Execution

On November 23, 2025 at 03:46:25 UTC, a PowerShell process executed using the -EncodedCommand flag, and the decoded plaintext command was Write-Output ‘token-6D5E4E08227’, showing the attacker ran an encoded PowerShell payload early in the intrusion as part of the simulated sequence.

Confirmed Flag:

- Write-Output ‘token-6D5E4E08227
<img width="1000" height="524" alt="image" src="https://github.com/user-attachments/assets/39498aff-5cae-4601-af58-3a9621c8e60b" />

KQL Used (EncCommandEx):

KQL Logic: The lab’s base64_decode_tostring() can display the right text, but sometimes keeps hidden UTF-16LE null characters, which can cause copy/paste or grading issues. This method strips those nulls so the plaintext is clean and consistent.
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
1. extract(): Pulls the Base64 string that appears after -EncodedCommand from ProcessCommandLine.
2. base64_decode_toarray(): Decodes the Base64 string into raw bytes, instead of guessing the text encoding.
3. mv-expand: Splits the byte array into one row per byte so we can clean it.
4. where tolong(b) != 0: Removes null bytes (0x00), which are common in PowerShell EncodedCommand because it uses UTF-16LE.
5. unicode_codepoints_to_string(): Rebuilds the decoded command into a clean readable string without hidden characters.

---

## Flag 14: Privilege Token Modification

On November 25, 2025 at 04:14:07 UTC, Windows recorded a ProcessPrimaryTokenModified event where the malicious MaintenanceRunner_Distributed.ps1 execution was linked to a token modification attempt, and the initiating process responsible for performing the token change was Process ID 4888, consistent with privilege escalation or token manipulation activity.

Confirmed Flag:

- 4888
<img width="1082" height="358" alt="image" src="https://github.com/user-attachments/assets/2db33d5c-9c49-495e-8007-6b4a9664dea7" />

KQL Used (ModToken):

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

---

## Flag 15: Whose Token Was Modified?

On November 25, 2025, at 04:14:07 UTC, the MaintenanceRunner_Distributed.ps1 execution triggered a ProcessPrimaryTokenModified event, and analysis of the AdditionalFields data shows the modified token belonged to the user SID S-1-5-21-1605642021-30596605-784192815-1000, matching both OriginalTokenUserSid and CurrentTokenUserSid for the same token modification.

Confirmed Flag:

- SID S-1-5-21-1605642021-30596605-784192815-1000
<img width="730" height="481" alt="image" src="https://github.com/user-attachments/assets/a0b57ee1-61ff-4f4e-bb83-5a4622220f48" />

KQL used (SIDOwner):

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

---

## Flag 16: Ingress Tool Transfer from External Dynamic & Tunnel &
## Flag 17: Identify the External Download Source

On December 2, 2025, at 12:56:55 UTC, a new executable named revshell.exe was written to disk on CH-OPS-WKS02 via a curl command that reached out to https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe (Flag 17), indicating the attacker staged an external payload for follow-on activity after privilege escalation.

Confirmed Flags:

- revshell.exe
-  https://unresuscitating-donnette-smothery.ngrok-free.dev/revshell.exe 
<img width="974" height="323" alt="image" src="https://github.com/user-attachments/assets/f91343d0-c8e0-463a-9925-93f49122d260" />

KQL used (IngressToolidentified):

```sql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
    and ActionType == "FileCreated"
| where FileName has_any ( ".exe")
| where InitiatingProcessCommandLine contains "curl"
| project TimeGenerated, ActionType, DeviceName, FolderPath, FileName, InitiatingProcessCommandLine
| order by TimeGenerated desc
```

---

## Flag 18: Execution of the Staged Unsigned Binary 

On December 2, 2025, at 12:57:29 UTC, the downloaded executable revshell.exe was launched from the user’s profile directory on CH-OPS-WKS02, and process telemetry shows it was executed by explorer.exe, indicating the attacker transitioned from staging the payload to actively running their tooling in a manner resembling normal user interaction.

Confirmed Flag:

- explorer.exe
<img width="778" height="405" alt="image" src="https://github.com/user-attachments/assets/cbf93955-37d0-4681-b20e-c55669a07d05" />

KQL used (UnsignedBin):

```sql
DeviceProcessEvents
| where TimeGenerated between (datetime(2025-12-02 12:56:00) .. datetime(2025-12-03))
| where DeviceName =~ "ch-ops-wks02"
| where FileName =~ "revshell.exe"
| project
    TimeGenerated,
    DeviceName,
    AccountName,
    FileName,
    FolderPath,
    ProcessCommandLine,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine
| order by TimeGenerated asc
```

---

## Flag 19: Identify the External IP Contacted by the Executable

On December 2, 2025 at 12:57:50 UTC, shortly after execution, revshell.exe attempted outbound TCP communication from CH-OPS-WKS02 to the external IP 13.228.171.119 over the nonstandard port 11746. Defender recorded the connection as failed, but the activity confirms the binary was actively attempting external command-and-control communication rather than remaining dormant.

Confirmed Flag:

- 13.228.171.119
<img width="904" height="339" alt="image" src="https://github.com/user-attachments/assets/53a2c592-77cd-464a-95e0-a2391ebccc1f" />

KQL used (FailRemoteIPCN):

```sql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-12-02 12:56:00) .. datetime(2025-12-03))
| where DeviceName =~ "ch-ops-wks02"
| where InitiatingProcessFileName =~ "revshell.exe"
| where ActionType in ("ConnectionFailed","ConnectionAttempted","ConnectionSuccess")
| where RemotePort == 11746
| project
    TimeGenerated,
    ActionType,
    DeviceName,
    InitiatingProcessAccountName,
    InitiatingProcessFileName,
    InitiatingProcessCommandLine,
    RemoteIP,
    RemoteIPType,
    RemotePort,
    Protocol
| order by TimeGenerated asc
```

---

## Flag 20: Persistence via Startup Folder Placement

On December 2, 2025 at 12:28:26 UTC, Defender observed revshell.exe being copied into the Windows Startup directory at C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe. This action indicates the attacker attempted to establish persistence by ensuring the malicious executable would automatically run upon user logon, a common and simple persistence technique.

Confirmed Flag:

- C:\ProgramData\Microsoft\Windows\Start Menu\Programs\StartUp\revshell.exe
<img width="613" height="325" alt="image" src="https://github.com/user-attachments/assets/09eab6c7-217a-4b32-8aec-8642febd3733" />

KQL used (PersistStartPath):

```sql
DeviceFileEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-26))
| where DeviceName =~ "ch-ops-wks02"
| where FileName contains "revshell.exe"
| where FolderPath has "Start"
| where FolderPath has @"C:\ProgramData\"
| project TimeGenerated, ActionType, RequestAccountName, FolderPath, FileName
| order by TimeGenerated asc
```

---

## Flag 21: Identify the Remote Session Source Device & 
## Flag 22: Identify the Remote Session IP Address 

On November 23, 2025, multiple ConnectionSuccess events tied to suspicious activity on CH-OPS-WKS02 consistently reference the same remote session metadata. The field InitiatingProcessRemoteSessionDeviceName shows the device name “对手,” (flag 21), indicating the attacker interacted with the system through a remote session rather than local physical access. These events also reveal a consistent remote session IP of 100.64.100.6 (Flag 22), which represents the network source used by the adversary to access the host and can be used to correlate entry activity with authentication logs, lateral movement, or other external access patterns.

Confirmed Flags:

- 对手
-  100.64.100.6
<img width="1066" height="364" alt="image" src="https://github.com/user-attachments/assets/c0ff19df-5a24-4999-8da8-8f9f116cbf3a" />

KQL used (RemoteSessionDevID):
```kql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessRemoteSessionDeviceName == "对手"
    and ActionType == "ConnectionSuccess"
| project 
    InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP, TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIPType, RemotePort, Protocol
| order by TimeGenerated asc
```

---

## Flag 23: Identify the Internal Pivot Host Used by the Attacker

On December 2, 2025, additional remote session activity tied to the attacker shows multiple source IP addresses beyond the original 100.64.100.6 entry point. Among these, the internal IP address 10.168.0.7 appears repeatedly in the remote session metadata associated with the device name “对手.” This indicates the attacker likely pivoted through an internal Azure virtual network host, suggesting prior compromise of another VM or the use of an internal hop before accessing CH-OPS-WKS02.

Confirmed Flag:

- 10.168.0.7
<img width="524" height="323" alt="image" src="https://github.com/user-attachments/assets/ef7cefc0-7abb-493c-b07d-66d7c65028e9" />

KQL used (PivotHostDetected):

```sql
DeviceNetworkEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
| where InitiatingProcessRemoteSessionDeviceName == "对手"
    and ActionType == "ConnectionSuccess"
    and InitiatingProcessRemoteSessionIP != "100.64.100.6"
| project 
    InitiatingProcessRemoteSessionDeviceName, InitiatingProcessRemoteSessionIP, TimeGenerated, ActionType, DeviceName, InitiatingProcessAccountName, InitiatingProcessCommandLine, InitiatingProcessFileName, RemoteIPType, RemotePort, Protocol
| order by TimeGenerated asc
```

---

## Flag 24: Identify the First Suspicious Logon Event & 
## Flag 25: IP Address Used During the First Suspicious Logon 

On November 23, 2025, at 03:08:31 UTC(Flag 24), it was recorded that the earliest successful logon to CH-OPS-WKS02 was associated with the attacker’s remote session activity. This logon originated from the external IP address 104.164.168.17 (Flag 25) and represents the first confirmed access point in the intrusion timeline. While additional remote session IPs appear later, this event marks the true beginning of the attacker’s presence on the system and serves as the anchor for reconstructing subsequent actions

Confirmed Flags:

- 2025-11-23T03:08:31.1849379Z
- 104.164.168.17
<img width="523" height="322" alt="image" src="https://github.com/user-attachments/assets/09fc2978-2639-4e86-bf4e-820883e5e28a" />


KQL used (FistLogonEvent):

```sql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
| where DeviceName == "ch-ops-wks02"
| where RemoteDeviceName == "对手"
| project TimeGenerated, RemoteIP, ActionType
| sort by TimeGenerated asc
```

---

## Flag 26: Account Used During the First Suspicious Logon

On November 23, 2025, analysis of the earliest suspicious logon event on CH-OPS-WKS02 reveals that the account chadmin was used to authenticate successfully from an external source. This logon aligns with the first observed remote access tied to the attacker’s activity and marks the initial point of compromise for the system. Identifying chadmin as the account involved confirms that the adversary leveraged valid credentials, highlighting potential credential theft or misuse of an existing administrative account as the entry method.

Confirmed Flag: 
- chadmin
<img width="529" height="218" alt="image" src="https://github.com/user-attachments/assets/f87c3296-1fa4-4dde-a10f-8f556b7ed9c6" />

KQL used (CompAcc):

```sql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
    and TimeGenerated == todatetime('2025-11-23T03:08:31.1849379Z')
| where DeviceName == "ch-ops-wks02"
| where RemoteDeviceName == "对手"
| project TimeGenerated, RemoteIP, AccountName
| sort by TimeGenerated asc
```

---

## Flag 27: Determine the Attacker’s Geographic Region

On November 23, 2025, review of authentication activity on CH-OPS-WKS02 shows multiple successful logon events tied to the attacker’s remote session activity. These logons originate from public IP addresses that are consistently associated with the same suspicious session behavior observed earlier in the investigation. Analysis of these IP addresses indicates they originate from Vietnam, confirming the attacker was operating from an external foreign location rather than from within the organization’s network. This geographic context further supports the conclusion that the activity represents unauthorized remote access and helps define the attacker’s point of origin.

Confirmed Flag: 
- Vietnam
<img width="692" height="229" alt="image" src="https://github.com/user-attachments/assets/b3dfcce3-721f-4a67-a34e-dcdaa0bcbb99" />

KQL used (GeoConfirmed):

```sql
DeviceLogonEvents
| where TimeGenerated between (datetime(2025-11-15) .. datetime(2025-12-16))
    and TimeGenerated == todatetime('2025-11-23T03:08:31.1849379Z')
| where DeviceName == "ch-ops-wks02"
| where RemoteDeviceName == "对手"
| extend Geo =  geo_info_from_ip_address("104.164.168.17")
| project TimeGenerated, RemoteIP, AccountName, Geo.country, Geo.city
| sort by TimeGenerated asc
```

---

## Flag 28: First Process Launched After the Attacker Logged In

On 2025-11-23 at 03:08:52 UTC, userinit.exe launched explorer.exe on ch-ops-wks02, confirming a successful interactive logon and initial user shell execution.

Confirmed Flag:
- explorer.exe
<img width="821" height="358" alt="image" src="https://github.com/user-attachments/assets/2d3face1-364b-4410-8f60-3bb0f7beb5ba" />

KQL used (FirstProcess):

```sql
DeviceProcessEvents
| where TimeGenerated between ( datetime(2025-11-23T03:08:31.1849379Z) .. datetime(2025-11-23T03:08:53Z))
| where DeviceName == "ch-ops-wks02"
    and AccountName == "chadmin"
| where ProcessRemoteSessionDeviceName == "对手"
| project TimeGenerated, InitiatingProcessRemoteSessionDeviceName, ProcessRemoteSessionIP, InitiatingProcessFileName, FileName
| sort by TimeGenerated asc 
```

---

## Flag 29: Identify the First File the Attacker Accessed

On November 23, 2025, shortly after authenticating into CH-OPS-WKS02, the attacker’s first observable action was opening a sensitive file containing credentials. At 03:11:00 UTC, Notepad.exe was launched via explorer.exe to access the file CH-OPS-WKS02 user-pass.txt located in the chadmin user’s Documents directory. This immediate focus on a credential-related file indicates the attacker’s priority was to obtain stored usernames and passwords, confirming credential harvesting as one of their initial objectives following successful access.

Confirmed Flag: 
- CH-OPS-WKS02 user-pass.txt
<img width="971" height="452" alt="image" src="https://github.com/user-attachments/assets/77747347-04cb-4785-b792-32f3b398e48a" />

KQL used (FirstFileAccess):

```sql
DeviceProcessEvents
| where TimeGenerated between ( datetime(2025-11-23T03:08:31.1849379Z) .. datetime(2025-11-23T23:59:00Z))
// | where TimeGenerated >= datetime(2025-11-23T03:08:31)
| where DeviceName == "ch-ops-wks02"
    and AccountName == "chadmin"
| where InitiatingProcessFileName == "explorer.exe"
| where ProcessRemoteSessionDeviceName == "对手"
| project
    TimeGenerated,
    InitiatingProcessRemoteSessionDeviceName,
    ProcessRemoteSessionIP,
    ProcessCommandLine,
    InitiatingProcessFileName,
    FileName
| sort by TimeGenerated asc 
```

---

## Flag 30: Determine the Attacker’s Next Action After Reading the File

On November 23, 2025, after completing their initial reconnaissance under the chadmin account, the attacker transitioned to account-level interaction on CH-OPS-WKS02. By narrowing the investigation window from the first suspicious logon at 03:08:31 UTC through the remainder of the day and correlating remote session activity tied to the same attacker device, logon events show the next account accessed was ops.maintenance. This shift indicates the adversary began testing or leveraging additional credentials shortly after enumeration, suggesting an attempt to expand privileges or prepare for further persistence and operational activity.

Confirmed Flag: 
- ops.maintenance
<img width="567" height="325" alt="image" src="https://github.com/user-attachments/assets/a307480c-6d0c-4b7c-9b90-27c2e3a6cd0f" />


KQL used (CompAccTwo):

```sql
DeviceLogonEvents
| where TimeGenerated between ( datetime(2025-11-23T03:08:31.1849379Z) .. datetime(2025-11-23T15:59:00Z))
| where DeviceName == "ch-ops-wks02"
| where RemoteDeviceName == "对手"
| project TimeGenerated, RemoteIP, ActionType, AccountName
| sort by TimeGenerated asc
```

---

# Summary

This hunt confirmed suspicious activity centered on CH-OPS-WKS02 that deviated from CorpHealth maintenance baselines. A host-unique maintenance script (MaintenanceRunner_Distributed.ps1) was tied to loopback beaconing behavior, suspicious staging in trusted diagnostics paths, registry modifications, unauthorized task artifacts, and token manipulation. The attacker later staged and executed an external payload (revshell.exe), attempted outbound TCP communication to 13.228.171.119:11746, and attempted persistence via Startup folder placement. Remote session metadata identified a consistent attacker session device name (对手), a primary remote session IP (100.64.100.6), an internal pivot host (10.168.0.7), and the earliest suspicious logon (2025-11-23T03:08:31.1849379Z) from 104.164.168.17, originating from Vietnam. Early post-logon actions focused on credential harvesting via CH-OPS-WKS02 user-pass.txt and pivoted to ops.maintenance, supporting a credential-driven intrusion chain.

---

# Response Taken

CH-OPS-WKS02 was isolated to stop further attacker activity, and the identified malicious artifacts (revshell.exe, Startup folder persistence, and the non-standard scheduled task/Run key activity) were removed. Compromised accounts (chadmin and ops.maintenance) had credentials reset, and sign-in activity was reviewed to ensure no additional sessions remained active. Indicators like the tunnel URL, remote session IPs, and related hashes were used to hunt for the same behavior across other endpoints and to confirm scope.



