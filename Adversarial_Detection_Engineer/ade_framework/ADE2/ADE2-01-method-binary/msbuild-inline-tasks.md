---
id: ADE2-003
title: MSBuild Inline Tasks
ade_category: ADE2
ade_subcategory: ADE2-01
mitre_attack:
  - T1127.001 (Trusted Developer Utilities: MSBuild)
platform: Windows
testable: true
---

# MSBuild Inline Tasks

## Summary

MSBuild inline tasks allow arbitrary C# (or VB.NET) code execution through `.csproj` or `.xml` project files. The command line is completely clean — `MSBuild.exe project.csproj` — because the payload lives inside the XML file, not in any command-line argument. This defeats rules that inspect command-line strings for suspicious patterns. MSBuild is a signed Microsoft binary present on any system with .NET Framework installed, making it a trusted execution proxy.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-02 — Alternative Code Execution
**Core principle:** Rules focused on PowerShell, cmd.exe, or script interpreters miss code execution through developer tools. MSBuild compiles and runs arbitrary C# code with a completely benign-looking command line.

## The Technique

MSBuild (Microsoft Build Engine) processes XML project files containing build instructions. The `UsingTask` element with `TaskFactory="CodeTaskFactory"` allows inline C# code that MSBuild compiles and executes at build time.

### Why the command line is clean

Unlike PowerShell encoded commands or cmd.exe with suspicious arguments, MSBuild's command line reveals nothing about the payload:

```
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Users\Public\project.csproj
```

The entire payload — which can include arbitrary .NET code, network connections, process injection, file operations — lives inside the XML file. Command-line inspection is completely useless.

### Multiple .NET Framework paths

MSBuild exists in multiple locations depending on the .NET Framework version installed:

| Path | Framework |
|------|-----------|
| `C:\Windows\Microsoft.NET\Framework\v2.0.50727\MSBuild.exe` | .NET 2.0 |
| `C:\Windows\Microsoft.NET\Framework\v3.5\MSBuild.exe` | .NET 3.5 |
| `C:\Windows\Microsoft.NET\Framework\v4.0.30319\MSBuild.exe` | .NET 4.0+ (32-bit) |
| `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe` | .NET 4.0+ (64-bit) |
| `C:\Program Files\Microsoft Visual Studio\...\MSBuild.exe` | Visual Studio |
| `C:\Program Files (x86)\Microsoft Visual Studio\...\MSBuild.exe` | Visual Studio (x86) |

Rules that match only one path miss the others.

### Additional attack vectors

- **`/logger:evil.dll`** — MSBuild loads custom logger DLLs, executing arbitrary code via DLL
- **`@evil.rsp`** — Response files contain MSBuild arguments; the actual command line only shows `MSBuild @evil.rsp`
- **`/pp` or `/preprocess`** — Can be abused for information gathering

**OriginalFileName:** `MSBuild.exe` (no `.mui` suffix anomaly)

## Bypass Demonstration

### Benign test payload

Create `C:\Users\Public\test.csproj`:

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Test">
    <Message Text="Hello from MSBuild inline task — benign test" Importance="high" />
  </Target>
</Project>
```

Execute:

```cmd
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Users\Public\test.csproj
```

### Malicious inline task structure (DO NOT execute — reference only)

```xml
<Project ToolsVersion="4.0" xmlns="http://schemas.microsoft.com/developer/msbuild/2003">
  <Target Name="Execute">
    <ClassExample />
  </Target>
  <UsingTask TaskName="ClassExample"
    TaskFactory="CodeTaskFactory"
    AssemblyFile="C:\Windows\Microsoft.Net\Framework\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll">
    <Task>
      <Code Type="Class" Language="cs">
        <![CDATA[
          using System;
          using Microsoft.Build.Framework;
          using Microsoft.Build.Utilities;
          public class ClassExample : Task {
            public override bool Execute() {
              // Arbitrary C# code runs here
              return true;
            }
          }
        ]]>
      </Code>
    </Task>
  </UsingTask>
</Project>
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Sysmon EID 1 CommandLine | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Users\Public\test.csproj` — completely clean |
| File contents (requires EID 11 + content inspection) | Full C# payload in XML |
| Sysmon EID 3 (if payload makes network connections) | `MSBuild.exe` as the connecting process |
| Script Block Logging (4104) | N/A — not PowerShell |
| AMSI | .NET AMSI integration may catch known patterns in 4.8+ |

## Vulnerable Rule

```yaml
title: Suspicious Code Execution
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'Invoke-Expression'
            - '-enc'
            - 'IEX'
            - 'downloadstring'
            - 'Start-Process'
    condition: selection
```

### Why it misses

The rule scans command-line arguments for suspicious strings. MSBuild's command line contains only a path to a project file — no suspicious keywords, no encoded payloads, no script fragments. The entire payload is in the XML file on disk, which command-line inspection never sees.

## Hardened Rule

```yaml
title: MSBuild Execution Outside Developer Context (Hardened)
status: experimental
description: |
    Detects MSBuild.exe execution outside of Visual Studio or build
    automation contexts. On non-developer endpoints, ANY MSBuild
    execution is suspicious.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\MSBuild.exe'
        - OriginalFileName: 'MSBuild.exe'
    filter_devtools:
        ParentImage|endswith:
            - '\devenv.exe'
            - '\dotnet.exe'
            - '\nuget.exe'
            - '\msbuild.exe'
    filter_build_agents:
        ParentImage|contains:
            - '\agent.worker'
            - '\actions-runner'
            - '\jenkins'
            - '\TeamCity'
    condition: selection and not (filter_devtools or filter_build_agents)
falsepositives:
    - Developer workstations running manual builds from command line
    - CI/CD agents not covered by filter_build_agents
level: high
---
title: MSBuild Network Connection (High Fidelity)
status: experimental
description: |
    MSBuild making ANY outbound network connection is a near-zero false
    positive detection. Legitimate builds may download NuGet packages but
    those go through nuget.exe or dotnet.exe, not MSBuild itself. MSBuild
    connecting to an external host indicates inline task with network
    payload.
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\MSBuild.exe'
        Initiated: 'true'
    filter_loopback:
        DestinationIp|startswith:
            - '127.'
            - '::1'
    condition: selection and not filter_loopback
falsepositives:
    - Extremely rare — MSBuild does not natively make network calls
level: critical
---
title: MSBuild Custom Logger DLL Load
status: experimental
description: |
    Detects MSBuild invoked with /logger flag, which loads an arbitrary
    DLL. Legitimate use is rare outside CI/CD pipelines.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\MSBuild.exe'
        - OriginalFileName: 'MSBuild.exe'
    selection_logger:
        CommandLine|contains: '/logger'
    condition: selection and selection_logger
falsepositives:
    - Custom build logging in CI/CD
level: medium
```

## Sysmon Evidence

### Event ID 1 -- Process Create (MSBuild.exe)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe` | Full .NET Framework path |
| CommandLine | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe C:\Users\Public\test.csproj` | Clean — no payload visible |
| OriginalFileName | `MSBuild.exe` | No `.mui` anomaly |
| ParentImage | `C:\Windows\System32\cmd.exe` | Parent process |
| User | `DOMAIN\username` | Runs as invoking user |

### Event ID 7 -- Image Loaded (if present in Sysmon config)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\MSBuild.exe` | MSBuild process |
| ImageLoaded | `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\Microsoft.Build.Tasks.v4.0.dll` | CodeTaskFactory assembly — indicates inline task execution |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Command-line substring | No | Command line contains only a file path |
| Image/OriginalFileName | Yes | Detects MSBuild execution regardless of arguments |
| Network connection from MSBuild | Yes | Near-zero FP — MSBuild should never connect out |
| DLL load (Microsoft.Build.Tasks) | Yes | Indicates CodeTaskFactory inline task |
| File creation by MSBuild | Yes | Suspicious if MSBuild drops executables |
| Parent process context | Yes | MSBuild from cmd.exe or explorer.exe is suspicious |
| Script Block Logging (4104) | N/A | Not PowerShell |
| AMSI (.NET 4.8+) | Partial | May catch known malicious patterns in compiled code |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #2: Sysmon CommandLine is raw — but for MSBuild this is irrelevant because the payload is never in the command line
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #10: NTFS 8.3 short names — MSBuild paths under `C:\Windows\Microsoft.NET\` may appear shortened; rules using `Image|endswith` are safer than `Image|contains` with full paths
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #11: OriginalFileName survives binary copy/rename — catches MSBuild copies placed in attacker-controlled directories

## References

- [LOLBAS - MSBuild.exe](https://lolbas-project.github.io/lolbas/Binaries/Msbuild/)
- [MITRE ATT&CK T1127.001 - MSBuild](https://attack.mitre.org/techniques/T1127/001/)
- [Atomic Red Team - T1127.001](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1127.001/T1127.001.md)
- [Microsoft - MSBuild Inline Tasks](https://learn.microsoft.com/en-us/visualstudio/msbuild/msbuild-inline-tasks)
- [Cybereason - MSBuild Abuse](https://www.cybereason.com/blog/threat-analysis-msbuild-abuse)
