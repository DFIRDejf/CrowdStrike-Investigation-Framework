# Execution — CrowdStrike CQL

> **7 CQL entries** | CrowdStrike Falcon / NG-SIEM | MITRE: TA0002

Identify suspicious process launches, script execution, and remote execution indicators.

> **Validation notice:** Entries marked *User-reported validated source* were provided as working queries, but publication copies were sanitized and must be re-tested. Entries marked *Candidate* and *Community-derived* have **not** been tested in this environment.

## Query Index

1. [Script Control Detection Events](#01-script-control-detection-events)
2. [Remote Command Response Events](#02-remote-command-response-events)
3. [PowerShell Child Process Within One Minute](#03-powershell-child-process-within-one-minute)
4. [Suspicious PowerShell Interpreter Arguments](#04-suspicious-powershell-interpreter-arguments)
5. [WMI Remote Process Creation Commands](#05-wmi-remote-process-creation-commands)
6. [Windows Shell and Command Interpreter Activity](#06-windows-shell-and-command-interpreter-activity)
7. [Selected Offensive Tool Names in Command Lines](#07-selected-offensive-tool-names-in-command-lines)

---

## 01. Script Control Detection Events

**Description:** Retrieves investigation-scoped scripting or remote command telemetry.

**MITRE ATT&CK:** T1059 (contextual)\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ScriptControlDetectInfo
| (
 ComputerName=/^(HOST_A|HOST_B|SERVER_A|SERVER_B)$/i
 OR UserName=/^(USER_ID|analyst@example.com)$/i
 OR LocalIP=/^(192\.0\.2\.10|192\.0\.2\.11)$/i
 OR @rawstring=/(USER_ID|analyst@example\.com|HOST_A|HOST_B)/i
)
```

### False Positive Considerations

Generic event retrieval; review event semantics before assigning a definitive ATT&CK technique.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 02. Remote Command Response Events

**Description:** Retrieves investigation-scoped scripting or remote command telemetry.

**MITRE ATT&CK:** T1059 (contextual)\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=RemoteCommandResponse
| (
 ComputerName=/^(HOST_A|HOST_B|SERVER_A|SERVER_B)$/i
 OR UserName=/^(USER_ID|analyst@example.com)$/i
 OR LocalIP=/^(192\.0\.2\.10|192\.0\.2\.11)$/i
 OR @rawstring=/(USER_ID|analyst@example\.com|HOST_A|HOST_B)/i
)
```

### False Positive Considerations

Generic event retrieval; review event semantics before assigning a definitive ATT&CK technique.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 03. PowerShell Child Process Within One Minute

**Description:** Correlates PowerShell execution with subsequent child process creation within a one-minute window.

**MITRE ATT&CK:** T1059.001\
**Origin:** Previously supplied CQL — sanitized migration copy\
**Validation:** User-reported validated source; revalidate sanitized copy\
**Required telemetry:** See event filters in query

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
correlate(
FirstQ: {
FileName=powershell.exe
} include:[FileName,TargetProcessId, RawProcessId, ComputerName],
SecondQ: {
FileName = /\.exe/i
ParentBaseFileName = powershell.exe
} include:[FileName, ParentProcessId, CommandLine],
sequence=true,
includeMatchesOnceOnly=false,
maxPerRoot=5,
within=1m,
globalConstraints=[ComputerName]
)
| format(format="%s (%s)", field=[FirstQ.FileName, FirstQ.RawProcessId], as=FirstColumn)
| groupBy([FirstQ.ComputerName, FirstColumn], function=collect(SecondQ.FileName, SecondQ.CommandLine))
```

### False Positive Considerations

Correlation uses ComputerName, not a strict parent-child process ID relationship; confirm lineage before interpreting.

### Investigation Guidance

Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

---

## 04. Suspicious PowerShell Interpreter Arguments

**Description:** Finds PowerShell executions involving encoded commands and common remote content execution strings.

**MITRE ATT&CK:** T1059.001\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/(encodedcommand|\-enc\s|downloadstring|invoke-expression|iex\s*\(|invoke-webrequest)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, TargetProcessId])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Legitimate management frameworks, automation agents and administrators.

### Investigation Guidance

Examine parent processes and subsequent network or file activity.

</details>

---

## 05. WMI Remote Process Creation Commands

**Description:** Searches command-line arguments often associated with WMI or CIM remote process execution.

**MITRE ATT&CK:** T1047\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(wmic\s+.*process\s+call\s+create|invoke-wmimethod|invoke-cimmethod|win32_process)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Remote configuration and inventory tooling.

### Investigation Guidance

Inspect remote targets, authenticated users and related WMI events.

</details>

---

## 06. Windows Shell and Command Interpreter Activity

**Description:** Examines command-shell execution with potentially interesting shell switches.

**MITRE ATT&CK:** T1059.003\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(cmd|powershell|pwsh)\.exe$/i
| CommandLine=/(\/c\s|\/k\s|\-command\s|\-encodedcommand\s)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Normal installer scripts, scheduled jobs, login scripts.

### Investigation Guidance

Use contextual baselining; command interpreter use alone is not suspicious.

</details>

---

## 07. Selected Offensive Tool Names in Command Lines

**Description:** Provides a targeted keyword hunt for commonly abused tool names; keyword matching does not establish malicious intent.

**MITRE ATT&CK:** T1059 / T1204 (contextual)\
**Origin:** OneNote-derived adaptation\
**Validation:** Candidate — requires validation in Falcon\
**Required telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

### Hunting Query (CQL)

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(mimikatz|nanodump|rubeus|certipy|impacket|secretsdump|wmiexec|smbexec|psexec|sharphound|bloodhound|nmap|masscan|netexec)/i
| select([@timestamp, aid, ComputerName, UserName, FileName, ParentBaseFileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

### False Positive Considerations

Security testing and approved red-team operations; names may appear in file paths or benign text.

### Investigation Guidance

Add path and signer filters, review approved tools and validate the actual binary.

</details>

---
