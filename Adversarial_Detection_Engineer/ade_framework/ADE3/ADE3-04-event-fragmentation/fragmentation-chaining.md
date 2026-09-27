---
id: ADE3-003
title: Fragmentation and Chaining
ade_category: ADE3
ade_subcategory: ADE3-04
mitre_attack:
  - T1059.003 (Command and Scripting Interpreter: Windows Command Shell)
  - T1105 (Ingress Tool Transfer)
  - T1218 (System Binary Proxy Execution)
platform: Windows
testable: true
---

# Fragmentation and Chaining

## Summary

Many Windows binaries support interactive or script-input mode -- they read commands from stdin or a script file. An adversary who writes malicious commands to a file and then invokes the binary against that file produces process telemetry where the command line contains nothing suspicious. The actual malicious operations live in the script file, which process_creation rules never see. Only multi-event correlation across file creation and process execution catches this pattern.

## ADE Classification

**Category:** ADE3 -- Context Development
**Core principle:** The adversary games the correlation layer. The malicious activity is split into two or more events that look independently benign: a file write (stage 1) and a process execution that reads that file (stage 2). A rule looking at a single event misses it; only correlation across events catches it.

This is not ADE2 (Omit Alternatives). ADE2 would be "the rule looks for `ftp.exe` but missed `tftp.exe`" -- a missed alternative for the same unit of analysis. Here, the rule's unit of analysis is the single process-creation event, but the attack's unit of analysis is a sequence of events. The rule is looking at the wrong thing entirely.

## The Technique

The pattern:

1. **Stage 1 -- Write the script.** The attacker writes malicious commands (FTP directives, PowerShell commands, VBScript, etc.) to a text file in a temp directory.
2. **Stage 2 -- Execute.** The attacker invokes a LOLBin with a flag that reads from the script file (e.g., `ftp.exe -s:`, `cmd /c`, `powershell -File`).

The process telemetry for stage 2 shows a clean command line -- just a binary reading a file. The malicious content is in the file, not the command line.

Binaries with script-input modes:

| Binary | Script-input flag | Pattern |
|--------|-------------------|---------|
| `ftp.exe` | `-s:<file>` | Write FTP directives, run `ftp.exe -s:%TEMP%\a.txt` |
| `cmd.exe` | `/c <file>` | Write `.bat`, run `cmd /c file.bat` |
| `powershell.exe` | `-File <file>` | Write `.ps1`, run `powershell -File file.ps1` |
| `cscript.exe` | positional path | Write `.vbs` or `.js`, run `cscript file.vbs` |
| `wscript.exe` | positional path | Write `.vbs` or `.js`, run `wscript file.vbs` |

The same pattern appears in real-world incidents with piped input (e.g., `echo <password> | AnyDesk.exe --set-password`, `echo <wmic command> | wmic`). The rule expects the entire chain on one command line, but the pipe splits it across two processes.

## Bypass Demonstration

### Benign test payload

```cmd
:: Stage 1 -- write the script
echo open example.com 21       > %TEMP%\a.txt
echo user anonymous pass       >> %TEMP%\a.txt
echo ls                        >> %TEMP%\a.txt
echo bye                       >> %TEMP%\a.txt

:: Stage 2 -- execute
ftp.exe -s:%TEMP%\a.txt
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Raw command line (Stage 2) | `ftp.exe -s:C:\Users\...\Temp\a.txt` |
| OS parser | `ftp.exe` reads commands from `a.txt` |
| Sysmon EID 1 CommandLine | `ftp.exe -s:C:\Users\...\Temp\a.txt` (no domain, no credentials) |
| Sysmon EID 11 FileCreate | File `a.txt` created in `%TEMP%` (Stage 1) |
| Script Block Logging (4104) | N/A (not PowerShell in this example) |
| AMSI | N/A |

## Vulnerable Rule

```yaml
title: FTP Download from Suspicious Domain (Naive)
id: 22222222-2222-2222-2222-000000000001
status: experimental
description: Detects ftp.exe being used to download from non-corporate domains
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\ftp.exe'
    CommandLine|contains: 'malicious.example.com'
  condition: selection
level: medium
```

### Why it misses

The malicious domain never appears in the `ftp.exe` command line -- it is inside the script file, which `process_creation` telemetry does not expose. The rule will only fire if the adversary makes the mistake of passing the host on the command line directly.

## Hardened Rule

The fix is a multi-part detection strategy, not a single rule.

**Part 1 -- Single-event tripwire on script-mode flags:**

```yaml
title: FTP Script-Mode Execution (Hardened, Behavioral)
id: 22222222-2222-2222-2222-000000000002
status: stable
description: Detects ftp.exe invoked with a script (-s:) flag -- pivots to file-content review
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '\ftp.exe'
  selection_ofn:
    OriginalFileName: 'ftp.exe'
  selection_flag:
    CommandLine|re|i: '\s[-/]s:'
  filter_legit:
    ParentImage|endswith:
      - '\KnownDeployTool.exe'
  condition: (selection_image or selection_ofn) and selection_flag and not filter_legit
level: high
fields:
  - CommandLine
  - ParentImage
  - User
```

**Part 2 -- Multi-event correlation (file write then execute):**

A correlation rule that joins:

- Sysmon EID 11 (FileCreate) for a text-like file (`.txt`, `.bat`, `.ps1`, `.vbs`, `.js`)
- Sysmon EID 1 (ProcessCreate) whose CommandLine contains the path of the file from the FileCreate event
- Within ~30 seconds, same User SID

```
event_a: Sysmon EID 11 — FileCreate of text-like file
event_b: Sysmon EID 1  — ProcessCreate with CommandLine containing event_a's file path
join_key: same User SID, same file path
window:  30 seconds (a -> b)
filter:  not (parent of event_b is a known build/deploy tool)
```

**Part 3 -- Enrichment:** Surface the contents of the script file at write-time (Sysmon FileCreate logging on text files in `%TEMP%`, or EDR file-content telemetry).

The tradeoff: Part 1 is cheap and fires immediately on `ftp.exe -s:` but only on `ftp.exe`. Part 2 is general but expensive and FP-prone in dev environments. Most production deployments run both.

## Sysmon Evidence

### Key Fields (Process creation -- Part 1)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\ftp.exe` | The LOLBin invoked |
| CommandLine | `ftp.exe -s:C:\...\Temp\a.txt` | Script path visible, malicious content is not |
| OriginalFileName | `ftp.exe` | From PE VERSION_INFO |
| ParentImage | `C:\Windows\System32\cmd.exe` | Parent that staged the attack |

### Key Fields (File creation -- Part 2 correlation)

| Field | Value | Note |
|-------|-------|------|
| EventID | 11 | FileCreate |
| TargetFilename | `C:\Users\...\Temp\a.txt` | The script file |
| Image | `C:\Windows\System32\cmd.exe` | Process that wrote the file |
| CreationUtcTime | Timestamp | Correlate with subsequent process creation |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Command-line substring | No | Malicious content is in the file, not the command line |
| Image field | Partial | Identifies the LOLBin but not the malicious intent |
| OriginalFileName | Partial | Binary identity only |
| Script-mode flag detection | Yes | Catches `ftp.exe -s:` as a tripwire |
| Multi-event correlation | Yes | Joins file write + process execution across events |
| Script Block Logging | Varies | Only for PowerShell `-File` variant |
| AMSI | Varies | Only for PowerShell variant |
| File-content scanning | Yes | YARA or EDR file inspection at write-time |
| Behavioral | Yes | File write + LOLBin execution pattern is invariant |

## Implementation Nuances

- **NUANCES #1 (OriginalFileName):** Always OR `Image|endswith` and `OriginalFileName` for `ftp.exe` detection.
- **NUANCES #2 (CommandLine is raw):** The script file path is in the command line, but the file contents are not. This is the fundamental gap single-event rules cannot bridge.
- **NUANCES #6 (Correlation timeframes):** 30 seconds balances between catching fast staging and avoiding false positives from build tools. Document the tradeoff.
- **NUANCES #11 (OriginalFileName survives rename):** If `ftp.exe` is copied to `svchost.exe`, OriginalFileName still reads `ftp.exe`.
