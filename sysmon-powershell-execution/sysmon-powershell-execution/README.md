# Sysmon — PowerShell Execution (EventCode 1)

## Goal
Detect and monitor PowerShell executions using Sysmon.  
This matters because attackers often abuse PowerShell for malicious purposes.

## Queries

**Raw — show each PowerShell execution**
index=sysmon sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 → Sysmon process-start events
Image="powershell.exe" → Only PowerShell
| table _time, host, Image, CommandLine, ParentImage → Show when, where, what, and parent
| sort - _time → Newest first

**Example Output**
![PowerShell Execution Example](threat-detection-labs/sysmon-powershell-execution/screenshots
/
Screenshot 2025-08-27 101220.png)


**Summary — which commands run most**
index=sysmon sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 → Sysmon process-start events
Image="powershell.exe" → Only PowerShell
| stats count by CommandLine → Count by exact command line
| sort - count → Most frequent first

**Suspicious — flag risky commands**
index=sysmon sourcetype="WinEventLog:Microsoft-Windows-Sysmon/Operational" EventCode=1 → Sysmon process-start events
Image="powershell.exe"
(CommandLine="EncodedCommand" OR CommandLine="Bypass" OR CommandLine="Invoke-Expression") → Suspicious flags
| table _time, host, CommandLine, ParentImage → Show details
| sort - _time → Newest first

## Why it matters
PowerShell is powerful for admins—and for attackers. Monitoring process starts (Sysmon EventCode 1) with command lines helps detect living-off-the-land attacks and script-based malware.
- Normal PowerShell helps admins.  
- Suspicious PowerShell helps attackers.  
- With Sysmon + Splunk, I can see every start, summarize usage, and flag risky commands (EncodedCommand, B
