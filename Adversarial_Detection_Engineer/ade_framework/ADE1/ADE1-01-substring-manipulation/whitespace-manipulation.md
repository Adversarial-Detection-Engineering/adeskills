---
id: ADE1-010
title: Whitespace Manipulation
ade_category: ADE1
ade_subcategory: ADE1-01
mitre_attack:
  - T1059.001 (Command and Scripting Interpreter: PowerShell)
  - T1059.003 (Command and Scripting Interpreter: Windows Command Shell)
platform: Windows
testable: true
---

# Whitespace Manipulation

## Summary

Windows command-line parsers and cmd.exe itself sometimes emit more whitespace than the operator typed. Extra spaces between tokens do not change the command's meaning, but they break detection rules that use literal substring matching with a fixed number of spaces. A rule searching for `'ipconfig /all'` (one space) misses telemetry containing `'ipconfig  /all'` (two spaces).

## ADE Classification

**Category:** ADE1 -- Reformatting in Actions
**Core principle:** The semantic meaning of the command line is identical regardless of how many whitespace characters appear between tokens. The OS parser collapses whitespace, but Sysmon logs the raw form. Substring matches that assume a specific whitespace count break.

## The Technique

Two related problems combine to defeat literal-substring detections:

1. **Parser-inserted whitespace.** Several native Windows binaries (and cmd.exe itself) emit more whitespace than the operator typed. Running `ipconfig /all` from certain invocation paths produces process telemetry showing `ipconfig  /all` -- two spaces between the binary and the flag.

2. **Attacker-inserted whitespace.** Adversaries deliberately add extra spaces between tokens to break rules tuned against the canonical one-space form.

Either way, the bytes in the CommandLine field differ from what the rule author assumed, but the execution is identical.

## Bypass Demonstration

### Benign test payload

```cmd
:: What the rule expects:
ipconfig /all
cmd.exe /c whoami

:: What the parser produces or the attacker types:
ipconfig  /all
cmd.exe  /c  whoami
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Raw command line | `ipconfig  /all` (extra space) |
| OS parser | Resolves to `ipconfig` with argument `/all` |
| Sysmon EID 1 CommandLine | `ipconfig  /all` (raw, spaces preserved) |
| Script Block Logging (4104) | N/A -- not a PowerShell technique |
| AMSI | N/A |

## Vulnerable Rule

```yaml
title: ipconfig (naive)
id: 33333333-3333-3333-3333-000000000001
status: experimental
description: Detects ipconfig /all
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'ipconfig /all'
  condition: selection
level: low
```

### Why it misses

`CommandLine|contains: 'ipconfig /all'` requires that exact byte sequence: binary name, single space, flag. Any extra space anywhere inside that span breaks the substring match. The rule fires on zero events whenever the whitespace differs.

## Hardened Rule

```yaml
title: ipconfig /all Recon (Hardened, Whitespace-Resilient)
id: 33333333-3333-3333-3333-000000000002
status: stable
description: Detects ipconfig /all execution regardless of whitespace count
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '\ipconfig.exe'
  selection_ofn:
    OriginalFileName: 'ipconfig.exe'
  selection_flag:
    CommandLine|re|i: '\s+/all\b'
  condition: (selection_image or selection_ofn) and selection_flag
falsepositives:
  - Helpdesk diagnostic scripts (scope by parent process or user)
level: low
```

The key architectural move: anchor binary identity to the `Image` field (populated from OS process metadata, not parsed from the raw command line -- so command-line whitespace tricks do not affect it) and use a `\s+` regex for the flag. The naive `'ipconfig /all'` literal becomes the resilient `Image|endswith` + `'\s+/all\b'` pair.

For binaries where the threat is the binary itself (e.g., `whoami`), dropping the command-line match entirely and detecting on `Image` / `OriginalFileName` with parent-process context is even more robust:

```yaml
detection:
  selection_image:
    Image|endswith: '\whoami.exe'
  selection_ofn:
    OriginalFileName: 'whoami.exe'
  selection_parent:
    ParentImage|endswith: '\cmd.exe'
  condition: (selection_image or selection_ofn) and selection_parent
```

## Sysmon Evidence

### Key Fields

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\ipconfig.exe` | Resolved path -- unaffected by command-line whitespace |
| CommandLine | `ipconfig  /all` | Raw form with extra whitespace preserved |
| OriginalFileName | `ipconfig.exe` | From PE VERSION_INFO |
| ParentImage | `C:\Windows\System32\cmd.exe` | Varies by invocation context |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Command-line substring | No | Assumes fixed whitespace count |
| Regex with `\s+` | Yes | Matches any non-zero run of whitespace |
| Image field | Yes | Process identity from OS metadata, not command line |
| OriginalFileName | Yes | PE header, unaffected by whitespace |
| Script Block Logging | N/A | Not a PowerShell-specific technique |
| AMSI | N/A | Not a PowerShell-specific technique |
| Behavioral | Yes | Process creation is invariant to whitespace |

## Implementation Nuances

- **NUANCES #1 (OriginalFileName):** Always OR `Image|endswith` and `OriginalFileName` to catch renamed binaries. For `ipconfig.exe`, the OriginalFileName matches the disk name.
- **NUANCES #2 (CommandLine is raw):** Sysmon preserves extra whitespace verbatim. This is the root cause of the bypass.
- **NUANCES #3 (Image field spaces):** The `Image` field itself can contain spaces (e.g., `C:\Program Files\...`), but these are real path components, not parser artifacts.
