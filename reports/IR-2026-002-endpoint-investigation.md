# Incident Investigation Report: IR-2026-002

## Incident Overview

| Field | Details |
| :--- | :--- |
| Incident ID | IR-2026-002 |
| Alert Title | Suspicious Encoded PowerShell Execution & LOLBAS Ingress |
| Severity | Medium |
| Status | Closed (Authorized Simulation) |
| Date & Time | 2026-11-14 11:49:39 UTC |
| Hostname | Youssef |
| User Account | Youssef\youss |
| MITRE ATT&CK | T1059.001 (PowerShell), T1105 (Ingress Tool Transfer), T1033 (Discovery) |

## Forensic Evidence

### 1. Encoded Command Execution (Sysmon Event ID 1)
Splunk detected obfuscated command execution utilizing Base64 encoding to bypass inspection:
- **Timestamp:** 2026-11-14 11:49:39.522
- **Image:** `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe`
- **Command Line:** `powershell.exe -NoP -NonI -W Hidden -Enc VwByAGkAdABlAC0ASABvAHMAdAAgACIASABhAGMAawBlAHIAIABBAGwAZQByAHQAIgA=`
- **Decoded Command:** `Write-Host "Hacker Alert"`
- **User:** `Youssef\youss`

### 2. LOLBAS Utility Activity (Sysmon Event ID 1)
Splunk captured native Windows utility `curl.exe` initiated with silent parameters targeting external egress:
- **Timestamp:** 2026-11-14 11:49:49.470
- **Image:** `C:\Windows\System32\curl.exe`
- **Command Line:** `"C:\WINDOWS\system32\curl.exe" -s http://example.com -o NUL`
- **Target:** `http://example.com`

### 3. Account & Privilege Enumeration
- **Commands Executed:** `whoami /priv`, `net user`
- **Observation:** Reconnaissance activity commonly executed post-initial access.

## Triage & Root Cause Analysis
- **Binary Path Verification:** Both `powershell.exe` and `curl.exe` executed from legitimate `C:\Windows\System32\` paths.
- **Payload Verification:** De-obfuscation proved the Base64 script was a benign simulation test.
- **Verdict:** True Positive (Controlled Lab Exercise).

## Recommendations & Containment
- Restrict PowerShell execution via AppLocker / WDAC (Constrained Language Mode).
- Monitor LOLBAS binaries (`curl.exe`, `certutil.exe`) and correlate with Sysmon Event ID 3 (Network Connection) and Event ID 22 (DNS Queries).

**Analyst:** Youssef
