---
id: ADE2-001
title: BITS Jobs
ade_category: ADE2
ade_subcategory: ADE2-01
mitre_attack:
  - T1197 (BITS Jobs)
  - T1105 (Ingress Tool Transfer)
platform: Windows
testable: true
---

# BITS Jobs

## Summary

The Background Intelligent Transfer Service (BITS) provides an alternative file download mechanism via `bitsadmin.exe` or `Start-BitsTransfer`. Detection rules that monitor for download tools like `certutil` or `curl` miss BITS entirely. Critically, `bitsadmin.exe` creates the transfer job but `svchost.exe` (hosting the BITS service) performs the actual network connection — Sysmon EID 3 attributes the download to `svchost.exe`, not `bitsadmin.exe`.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-01 — Alternative Download Tools
**Core principle:** Rules anchored to specific download binaries (certutil, curl, Invoke-WebRequest) miss functionally equivalent alternatives. BITS adds a second evasion layer: the process making the network connection is not the process the operator invoked.

## The Technique

BITS is a Windows service designed for asynchronous, bandwidth-throttled file transfers. It is used legitimately by Windows Update, WSUS, SCCM, and other Microsoft services. This makes BITS traffic inherently difficult to distinguish from normal system behavior.

There are three interfaces to BITS:

1. **bitsadmin.exe** — legacy CLI tool, logs to Sysmon EID 1 as a process creation
2. **Start-BitsTransfer** — PowerShell cmdlet (BitsTransfer module), appears as a PowerShell command
3. **COM API** — IBackgroundCopyManager interface, callable from any language; no bitsadmin.exe or PowerShell process is created at all

The key architectural detail: `bitsadmin.exe` is a client that sends commands to the BITS service (`QMGR`) running inside `svchost.exe -k netsvcs`. The service process — not bitsadmin — opens the network socket, downloads the file, and writes it to disk. This means:

- Sysmon EID 3 (NetworkConnect) shows `svchost.exe` as the source, not `bitsadmin.exe` (documented in MITRE DET0098 and confirmed by Windows service architecture — not locally verified because most Sysmon configs exclude svchost from EID 3 to reduce noise)
- Sysmon EID 11 (FileCreate) shows `svchost.exe` as the creator
- Rules correlating "bitsadmin process + network connection" will find no match

BITS jobs also survive reboots, can be scheduled with delays, and support download-then-execute via `/SetNotifyCmdLine`. This makes BITS a persistence mechanism as well as a transfer mechanism.

**OriginalFileName:** `bitsadmin.exe` (Sysmon strips the `.mui` suffix from the PE resource — see NUANCES #4)

## Bypass Demonstration

### Benign test payload

```cmd
:: Download a known-safe file via bitsadmin
bitsadmin /transfer TestJob /download /priority foreground https://live.sysinternals.com/autoruns.exe C:\Users\Public\test.exe

:: Verify and clean up
dir C:\Users\Public\test.exe
del C:\Users\Public\test.exe
```

```powershell
# PowerShell equivalent
Start-BitsTransfer -Source "https://live.sysinternals.com/autoruns.exe" -Destination "C:\Users\Public\test.exe"
Remove-Item "C:\Users\Public\test.exe"
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Sysmon EID 1 (bitsadmin.exe) | `bitsadmin /transfer TestJob /download /priority foreground https://live.sysinternals.com/autoruns.exe C:\Users\Public\test.exe` |
| Sysmon EID 3 (NetworkConnect) | `svchost.exe` connecting to `live.sysinternals.com:443` — NOT bitsadmin |
| Sysmon EID 11 (FileCreate) | `svchost.exe` creating `C:\Users\Public\test.exe` — NOT bitsadmin |
| BITS-Client Operational Log | Event ID 3 (job created), Event ID 59 (transfer started), Event ID 60 (transfer complete) |
| Windows Event Log EID 16403 | BITS job status change with URL and local path |

## Vulnerable Rule

```yaml
title: File Download via Command Line Tool
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains:
            - 'certutil'
            - 'Invoke-WebRequest'
            - 'wget'
            - 'curl'
    condition: selection
```

### Why it misses

The rule enumerates specific download tools but does not include `bitsadmin` or `Start-BitsTransfer`. Even if it did, the network activity would still be attributed to `svchost.exe` in Sysmon network events, not to bitsadmin.

## Hardened Rule

```yaml
title: BITS Transfer Job Created (Hardened)
status: experimental
description: |
    Detects BITS transfer job creation via bitsadmin.exe or Start-BitsTransfer.
    Monitors the process creation, not the network connection, because BITS
    delegates downloads to svchost.exe (BITS service).
logsource:
    category: process_creation
    product: windows
detection:
    selection_bitsadmin:
        - Image|endswith: '\bitsadmin.exe'
        - OriginalFileName: 'bitsadmin.exe'
    selection_args:
        CommandLine|contains:
            - '/transfer'
            - '/addfile'
            - '/SetNotifyCmdLine'
            - '/Resume'
    condition: selection_bitsadmin and selection_args
falsepositives:
    - SCCM/MECM client operations
    - Windows Update troubleshooting scripts
    - Enterprise patch management tools
level: medium
---
title: BITS Transfer via PowerShell (Hardened)
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'Start-BitsTransfer'
            - '-Source'
    condition: selection
falsepositives:
    - Administrative file transfer scripts
level: medium
---
title: BITS Service Suspicious Child Process
status: experimental
description: |
    Detects svchost.exe hosting the BITS service spawning unexpected child
    processes. This catches /SetNotifyCmdLine persistence where BITS
    executes a command after download completes.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentCommandLine|contains: 'netsvcs'
        ParentImage|endswith: '\svchost.exe'
    filter_legitimate:
        Image|endswith:
            - '\WerFault.exe'
            - '\wuauclt.exe'
            - '\UsoClient.exe'
            - '\musnotification.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Legitimate software using BITS COM API
level: high
```

### Supplemental: BITS-Client event log rule

```yaml
title: BITS Job with External URL (Event Log)
status: experimental
logsource:
    service: bits-client
    product: windows
detection:
    selection:
        EventID:
            - 59
            - 60
    filter_microsoft:
        url|contains:
            - 'microsoft.com'
            - 'windowsupdate.com'
            - 'windows.com'
    condition: selection and not filter_microsoft
falsepositives:
    - Third-party software using BITS for updates
level: medium
```

## Sysmon Evidence

### Event ID 1 -- Process Create (bitsadmin.exe)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\bitsadmin.exe` | Resolved path |
| CommandLine | `bitsadmin /transfer TestJob /download /priority foreground https://live.sysinternals.com/autoruns.exe C:\Users\Public\test.exe` | URL and destination visible in command line |
| OriginalFileName | `bitsadmin.exe` | Sysmon strips `.mui` suffix |
| ParentImage | `C:\Windows\System32\cmd.exe` | Parent process |

### Event ID 3 -- Network Connect (svchost.exe, NOT bitsadmin)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\svchost.exe` | BITS service host, not bitsadmin |
| DestinationHostname | `live.sysinternals.com` | Target URL |
| DestinationPort | `443` | HTTPS |
| DestinationIp | varies | CDN-resolved IP |

### Event ID 11 -- File Create (svchost.exe, NOT bitsadmin)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\svchost.exe` | BITS service writes the file |
| TargetFilename | `C:\Users\Public\test.exe` | Download destination |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Command-line substring (certutil/curl) | No | Different binary entirely |
| bitsadmin Image/OriginalFileName | Yes | Catches bitsadmin process creation |
| Network connection from bitsadmin | No | svchost.exe makes the connection, not bitsadmin |
| svchost.exe network connection | Noisy | svchost makes thousands of legitimate connections |
| BITS-Client event log | Yes | Native BITS telemetry with URL and job details |
| svchost child process monitoring | Yes | Catches /SetNotifyCmdLine post-download execution |
| COM API detection | No | No process creation at all when using COM directly |
| Script Block Logging (4104) | Partial | Catches Start-BitsTransfer in PowerShell only |
| AMSI | Partial | Catches PowerShell BITS cmdlet usage |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #4: Sysmon strips the `.mui` suffix from OriginalFileName — bitsadmin.exe shows as `bitsadmin.exe`, not `bitsadmin.exe.mui`
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #11: OriginalFileName survives binary copy/rename — catches renamed bitsadmin copies
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #6: Correlation timeframes matter — BITS jobs can have arbitrary delays between creation and execution; `/SetNotifyCmdLine` may fire minutes or hours after the download completes

## Known APT Usage

| Threat Actor | Context |
|-------------|---------|
| APT41 (Winnti) | Used BITS jobs for payload downloads during supply chain and espionage campaigns |
| Wizard Spider (TrickBot/Conti) | Deployed BITS transfers for lateral movement and payload staging |
| APT39 (Chafer) | Used bitsadmin for tool transfer during Middle East-focused intrusions |

## References

- [LOLBAS - Bitsadmin.exe](https://lolbas-project.github.io/lolbas/Binaries/Bitsadmin/)
- [MITRE ATT&CK T1197 - BITS Jobs](https://attack.mitre.org/techniques/T1197/)
- [MITRE ATT&CK T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Atomic Red Team - T1197](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1197/T1197.md)
- [Microsoft - BITSAdmin Tool](https://learn.microsoft.com/en-us/windows/win32/bits/bitsadmin-tool)
- [FireEye - Abusing BITS](https://www.mandiant.com/resources/blog/attacker-use-of-windows-background-intelligent-transfer-service)
