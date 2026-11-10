[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Execution

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0002`  ·  **10 queries**

Find suspicious commands, scripts, and process execution patterns.

---

## Query library

| Hunt | MITRE | Status |
|:--|:--|:--|
| [01. Script Control Detection Events](#01-script-control-detection-events) | T1059 (contextual) | `Migration recheck` |
| [02. Remote Command Response Events](#02-remote-command-response-events) | T1059 (contextual) | `Migration recheck` |
| [03. PowerShell Child Process Within One Minute](#03-powershell-child-process-within-one-minute) | T1059.001 | `Migration recheck` |
| [04. Suspicious PowerShell Interpreter Arguments](#04-suspicious-powershell-interpreter-arguments) | T1059.001 | `Candidate` |
| [05. WMI Remote Process Creation Commands](#05-wmi-remote-process-creation-commands) | T1047 | `Candidate` |
| [06. Windows Shell and Command Interpreter Activity](#06-windows-shell-and-command-interpreter-activity) | T1059.003 | `Candidate` |
| [07. Selected Offensive Tool Names in Command Lines](#07-selected-offensive-tool-names-in-command-lines) | T1059 / T1204 (contextual) | `Candidate` |
| [08. Shell and Packed Executable Event Inventory](#08-shell-and-packed-executable-event-inventory) | T1059 / T1027 | `Requires Validation` |
| [09. Command History and New Script Telemetry](#09-command-history-and-new-script-telemetry) | T1059 | `Requires Validation` |
| [10. Baseline Process and Ancestry Context](#10-baseline-process-and-ancestry-context) | T1059 (context) | `Requires Validation` |

---

### 01. Script Control Detection Events

Retrieves investigation-scoped scripting or remote command telemetry.

**MITRE:** T1059 (contextual)

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ScriptControlDetectInfo
| (
 ComputerName=/^(HOST_A|HOST_B|SERVER_A|SERVER_B)$/i
 OR UserName=/^(USER_ID|analyst@example.com)$/i
 OR LocalIP=/^(192\.0\.2\.10|192\.0\.2\.11)$/i
 OR @rawstring=/(USER_ID|analyst@example\.com|HOST_A|HOST_B)/i
)
```

**False positives:** Generic event retrieval; review event semantics before assigning a definitive ATT&CK technique.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

### 02. Remote Command Response Events

Retrieves investigation-scoped scripting or remote command telemetry.

**MITRE:** T1059 (contextual)

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=RemoteCommandResponse
| (
 ComputerName=/^(HOST_A|HOST_B|SERVER_A|SERVER_B)$/i
 OR UserName=/^(USER_ID|analyst@example.com)$/i
 OR LocalIP=/^(192\.0\.2\.10|192\.0\.2\.11)$/i
 OR @rawstring=/(USER_ID|analyst@example\.com|HOST_A|HOST_B)/i
)
```

**False positives:** Generic event retrieval; review event semantics before assigning a definitive ATT&CK technique.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

### 03. PowerShell Child Process Within One Minute

Correlates PowerShell execution with subsequent child process creation within a one-minute window.

**MITRE:** T1059.001

<details>
<summary><strong>If you want to see more details</strong></summary>

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

**False positives:** Correlation uses ComputerName, not a strict parent-child process ID relationship; confirm lineage before interpreting.

**Analyst pivot:** Scope by host, user and narrow time window; pivot to process tree and nearby evidence before concluding malicious activity.

</details>

### 04. Suspicious PowerShell Interpreter Arguments

Finds PowerShell executions involving encoded commands and common remote content execution strings.

**MITRE:** T1059.001  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/(encodedcommand|\-enc\s|downloadstring|invoke-expression|iex\s*\(|invoke-webrequest)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, TargetProcessId])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Legitimate management frameworks, automation agents and administrators.

**Analyst pivot:** Examine parent processes and subsequent network or file activity.

*Origin: OneNote-derived adaptation*

</details>

### 05. WMI Remote Process Creation Commands

Searches command-line arguments often associated with WMI or CIM remote process execution.

**MITRE:** T1047  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(wmic\s+.*process\s+call\s+create|invoke-wmimethod|invoke-cimmethod|win32_process)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Remote configuration and inventory tooling.

**Analyst pivot:** Inspect remote targets, authenticated users and related WMI events.

*Origin: OneNote-derived adaptation*

</details>

### 06. Windows Shell and Command Interpreter Activity

Examines command-shell execution with potentially interesting shell switches.

**MITRE:** T1059.003  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(cmd|powershell|pwsh)\.exe$/i
| CommandLine=/(\/c\s|\/k\s|\-command\s|\-encodedcommand\s)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Normal installer scripts, scheduled jobs, login scripts.

**Analyst pivot:** Use contextual baselining; command interpreter use alone is not suspicious.

*Origin: OneNote-derived adaptation*

</details>

### 07. Selected Offensive Tool Names in Command Lines

Provides a targeted keyword hunt for commonly abused tool names; keyword matching does not establish malicious intent.

**MITRE:** T1059 / T1204 (contextual)  ·  **Telemetry:** ProcessRollup2

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(mimikatz|nanodump|rubeus|certipy|impacket|secretsdump|wmiexec|smbexec|psexec|sharphound|bloodhound|nmap|masscan|netexec)/i
| select([@timestamp, aid, ComputerName, UserName, FileName, ParentBaseFileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Security testing and approved red-team operations; names may appear in file paths or benign text.

**Analyst pivot:** Add path and signer filters, review approved tools and validate the actual binary.

*Origin: OneNote-derived adaptation*

</details>

### 08. Shell and Packed Executable Event Inventory

Queries endpoint shell tracing and packed executable events.

**MITRE:** T1059 / T1027  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(ShellCommandLineInfo|ProcessTrace|ProcessExecOnPackedExecutable)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Normal script activity and legitimate packed applications.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 09. Command History and New Script Telemetry

Surfaces command history and script-writing events for shell investigations.

**MITRE:** T1059  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=/^(CommandHistory|NewScriptWritten|ScriptControlDetectInfo)$/
| @rawstring=/(powershell|cmd|\.ps1|\.bat|\.vbs|\.js)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** IT automation and system scripts.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

### 10. Baseline Process and Ancestry Context

Lists process execution fields to pivot on parent, grandparent and command line.

**MITRE:** T1059 (context)  ·  **Source:** `CS Queries.one`  ·  **Status:** `Requires Validation`

<details>
<summary><strong>If you want to see more details</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| select([@timestamp, ComputerName, UserName, FileName, ParentBaseFileName, GrandParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, RawProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** High-volume baseline; narrow time and hosts before running.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>


---

`Migration recheck` = original supplied query was previously tested, but this publication copy needs validation. `Candidate` / `Community candidate` = not validated in the target Falcon environment.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
