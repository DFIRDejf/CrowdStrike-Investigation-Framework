[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)

# Execution

**CrowdStrike Falcon / NG-SIEM**  ·  **CQL**  ·  `TA0002`  ·  **10 queries**

Find suspicious commands, scripts, and process execution patterns.

---

## Query library

| Hunt | ID | MITRE | Status |
|:--|:--|:--|:--|
| [01. Script Control Detection Events](#cs-ta0002-001) | `CS-TA0002-001` | T1059 (contextual) | `Requires Validation` |
| [02. Remote Command Response Events](#cs-ta0002-002) | `CS-TA0002-002` | T1059 (contextual) | `Requires Validation` |
| [03. PowerShell Child Process Within One Minute](#cs-ta0002-003) | `CS-TA0002-003` | T1059.001 | `Requires Validation` |
| [04. Suspicious PowerShell Interpreter Arguments](#cs-ta0002-004) | `CS-TA0002-004` | T1059.001 | `Requires Validation` |
| [05. WMI Remote Process Creation Commands](#cs-ta0002-005) | `CS-TA0002-005` | T1047 | `Requires Validation` |
| [06. Windows Shell and Command Interpreter Activity](#cs-ta0002-006) | `CS-TA0002-006` | T1059.003 | `Requires Validation` |
| [07. Selected Offensive Tool Names in Command Lines](#cs-ta0002-007) | `CS-TA0002-007` | T1059 / T1204 (contextual) | `Requires Validation` |
| [08. Shell and Packed Executable Event Inventory](#cs-ta0002-008) | `CS-TA0002-008` | T1059 / T1027 | `Requires Validation` |
| [09. Command History and New Script Telemetry](#cs-ta0002-009) | `CS-TA0002-009` | T1059 | `Requires Validation` |
| [10. Baseline Process and Ancestry Context](#cs-ta0002-010) | `CS-TA0002-010` | T1059 (context) | `Requires Validation` |

---

<a name="cs-ta0002-001"></a>

### 01. Script Control Detection Events

Retrieves investigation-scoped scripting or remote command telemetry.

**Query ID:** `CS-TA0002-001` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1059 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

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

<a name="cs-ta0002-002"></a>

### 02. Remote Command Response Events

Retrieves investigation-scoped scripting or remote command telemetry.

**Query ID:** `CS-TA0002-002` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1059 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

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

<a name="cs-ta0002-003"></a>

### 03. PowerShell Child Process Within One Minute

Correlates PowerShell execution with subsequent child process creation within a one-minute window.

**Query ID:** `CS-TA0002-003` · **Platform:** `Not scoped` · **Tags:** `See query`

**MITRE:** T1059.001 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

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

<a name="cs-ta0002-004"></a>

### 04. Suspicious PowerShell Interpreter Arguments

Finds PowerShell executions involving encoded commands and common remote content execution strings.

**Query ID:** `CS-TA0002-004` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1059.001 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(powershell|pwsh)\.exe$/i
| CommandLine=/(encodedcommand|\-enc\s|downloadstring|invoke-expression|iex\s*\(|invoke-webrequest)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine, TargetProcessId])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Legitimate management frameworks, automation agents and administrators.

**Analyst pivot:** Examine parent processes and subsequent network or file activity.

</details>

<a name="cs-ta0002-005"></a>

### 05. WMI Remote Process Creation Commands

Searches command-line arguments often associated with WMI or CIM remote process execution.

**Query ID:** `CS-TA0002-005` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1047 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(wmic\s+.*process\s+call\s+create|invoke-wmimethod|invoke-cimmethod|win32_process)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Remote configuration and inventory tooling.

**Analyst pivot:** Inspect remote targets, authenticated users and related WMI events.

</details>

<a name="cs-ta0002-006"></a>

### 06. Windows Shell and Command Interpreter Activity

Examines command-shell execution with potentially interesting shell switches.

**Query ID:** `CS-TA0002-006` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1059.003 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| FileName=/^(cmd|powershell|pwsh)\.exe$/i
| CommandLine=/(\/c\s|\/k\s|\-command\s|\-encodedcommand\s)/i
| select([@timestamp, aid, ComputerName, UserName, ParentBaseFileName, FileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Normal installer scripts, scheduled jobs, login scripts.

**Analyst pivot:** Use contextual baselining; command interpreter use alone is not suspicious.

</details>

<a name="cs-ta0002-007"></a>

### 07. Selected Offensive Tool Names in Command Lines

Provides a targeted keyword hunt for commonly abused tool names; keyword matching does not establish malicious intent.

**Query ID:** `CS-TA0002-007` · **Platform:** `Windows` · **Tags:** `Process`

**MITRE:** T1059 / T1204 (contextual) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2 event_platform=Win
| CommandLine=/(mimikatz|nanodump|rubeus|certipy|impacket|secretsdump|wmiexec|smbexec|psexec|sharphound|bloodhound|nmap|masscan|netexec)/i
| select([@timestamp, aid, ComputerName, UserName, FileName, ParentBaseFileName, CommandLine])
| sort(@timestamp, order=desc, limit=1000)
```

**False positives:** Security testing and approved red-team operations; names may appear in file paths or benign text.

**Analyst pivot:** Add path and signer filters, review approved tools and validate the actual binary.

</details>

<a name="cs-ta0002-008"></a>

### 08. Shell and Packed Executable Event Inventory

Queries endpoint shell tracing and packed executable events.

**Query ID:** `CS-TA0002-008` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1059 / T1027 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(ShellCommandLineInfo|ProcessTrace|ProcessExecOnPackedExecutable)$/
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** Normal script activity and legitimate packed applications.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0002-009"></a>

### 09. Command History and New Script Telemetry

Surfaces command history and script-writing events for shell investigations.

**Query ID:** `CS-TA0002-009` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1059 · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=/^(CommandHistory|NewScriptWritten|ScriptControlDetectInfo)$/
| @rawstring=/(powershell|cmd|\.ps1|\.bat|\.vbs|\.js)/i
| select([@timestamp, #event_simpleName, ComputerName, UserName, @rawstring, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** IT automation and system scripts.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>

<a name="cs-ta0002-010"></a>

### 10. Baseline Process and Ancestry Context

Lists process execution fields to pivot on parent, grandparent and command line.

**Query ID:** `CS-TA0002-010` · **Platform:** `Not scoped` · **Tags:** `Process`

**MITRE:** T1059 (context) · **Status:** `Requires Validation`

<details>
<summary><strong>Show CrowdStrike query</strong></summary>

```cql
#event_simpleName=ProcessRollup2
| select([@timestamp, ComputerName, UserName, FileName, ParentBaseFileName, GrandParentBaseFileName, ImageFileName, CommandLine, TargetProcessId, RawProcessId, aid])
| sort(@timestamp, order=asc, limit=10000)
```

**False positives:** High-volume baseline; narrow time and hosts before running.

**Validation:** Confirm event and field availability and expected semantics in Falcon. [DO WERYFIKACJI W ŚRODOWISKU]

</details>


---

`Requires Validation` = not yet tenant-validated · `Tested` = exact-version tested · `Production reviewed` = peer-reviewed with evidence.

[← Home](../README.md) · [All queries](../QUERY-CATALOG.md)
