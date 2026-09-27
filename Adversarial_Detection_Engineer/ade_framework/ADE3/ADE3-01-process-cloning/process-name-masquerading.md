---
id: ADE3-001
title: Process Name Masquerading
ade_category: ADE3
ade_subcategory: ADE3-01
mitre_attack:
  - T1036 (Masquerading)
  - T1036.003 (Rename System Utilities)
platform: Windows
testable: true
---

# Process Name Masquerading

## Summary

Copying a legitimate binary to a different location and renaming it defeats rules that match on the `Image` field. The Image field shows the new path and name, but `OriginalFileName` and the file hash remain unchanged — creating a detectable mismatch.

## ADE Classification

**Category:** ADE3 — Context Development
**Subcategory:** ADE3-01 — Process Cloning
**Core principle:** The `Image` field reflects the on-disk filename. `OriginalFileName` reflects the PE header. When these differ, masquerading is occurring.

## The Technique

When an attacker copies `whoami.exe` (or `cmd.exe`, `powershell.exe`, etc.) to a user-writable directory with a different name, they create a fully functional copy that bypasses name-based detection rules.

The copy is byte-for-byte identical to the original:
- Same file hash (SHA256, MD5, IMPHASH)
- Same PE VERSION_INFO (OriginalFileName, ProductName, CompanyName, FileDescription)
- Same functionality

The only things that change are the filesystem path and name.

## Bypass Demonstration

### Benign test payload

```cmd
copy C:\Windows\System32\whoami.exe C:\Users\Public\svchost.exe
C:\Users\Public\svchost.exe
```

### What Sysmon sees

| Field | Value |
|-------|-------|
| Image | `C:\Users\Public\svchost.exe` (NEW name) |
| OriginalFileName | `whoami.exe` (ORIGINAL PE name) |
| Hashes | `SHA256=1D4902A04D99E8CCBFE7085E63155955FEE397449D386453F6C452AE407B8743` (identical to real whoami.exe) |
| CommandLine | `"C:\Users\Public\svchost.exe"` |

## Vulnerable Rule

```yaml
title: Whoami Execution
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\whoami.exe'
    condition: selection
```

### Why it misses

Image field ends with `\svchost.exe`, not `\whoami.exe`. The rule only checks the filesystem name.

## Hardened Rule

```yaml
title: Whoami Execution (Hardened)
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\whoami.exe'
        - OriginalFileName: 'whoami.exe'
    condition: selection
```

### Why the hardened rule works

The `OriginalFileName` field comes from the PE VERSION_INFO resource — embedded in the binary, not derived from the filesystem. Copying or renaming the binary does not change this field.

### Bonus: Masquerading detection rule

```yaml
title: Binary Name Mismatch (Masquerading Indicator)
status: experimental
description: Detects when a process runs from a path that doesn't match its OriginalFileName
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        OriginalFileName:
            - 'cmd.exe'
            - 'Cmd.Exe'
            - 'powershell.exe'
            - 'PowerShell.EXE'
            - 'whoami.exe'
            - 'net.exe'
            - 'net1.exe'
    filter_legitimate:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\whoami.exe'
            - '\net.exe'
            - '\net1.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - Software that legitimately bundles renamed system utilities (rare)
level: high
```

## Sysmon Evidence

### Event ID 1 — Process Create (masqueraded binary)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Users\Public\svchost.exe` | Renamed copy of whoami.exe |
| CommandLine | `"C:\Users\Public\svchost.exe"` | Shows renamed path |
| OriginalFileName | `whoami.exe` | From PE header — MISMATCH with Image |
| Hashes | `SHA1=1915FBFDB73FDD200C47880247ACDDE5442431A9` | Matches legitimate whoami.exe |
| IMPHASH | `7FF0758B766F747CE57DFAC70743FB88` | Matches legitimate whoami.exe |

The Image-OriginalFileName mismatch is the primary detection signal.

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Image|endswith for binary name | No | Filesystem name changed |
| OriginalFileName check | Yes | PE header unchanged |
| Hash-based detection | Yes | Binary content identical, hash matches known binary |
| Image path anomaly | Yes | System binary from `C:\Users\Public\` is suspicious |
| Image-vs-OriginalFileName mismatch | Yes | Best signal — detects all masquerading |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #1: OriginalFileName anomalies — check the actual PE value before writing rules
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #11: OriginalFileName survives binary copy/rename
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #12: Sysmon hashes computed at process start, match original

## Attacker counter-moves

An attacker CAN modify the PE header's OriginalFileName with a hex editor, but this changes the file hash. Detection catch-22: keep OriginalFileName intact and get caught by metadata comparison, or modify it and get caught by hash mismatch against known binaries.

An attacker CAN modify the PEB at runtime to change the reported ImagePathName, but Sysmon captures the authentic path at process creation time via kernel callbacks. PEB manipulation only fools tools that inspect the PEB after the fact (Task Manager, Get-Process).

## References

- [Red Canary - Rename System Utilities](https://redcanary.com/threat-detection-report/techniques/rename-system-utilities/)
- [FalconForce - LOLBin File Renaming Detection](https://medium.com/falconforce/falconfriday-masquerading-lolbin-file-renaming-0xff0c-b01e0ab5a95d)
- [MITRE ATT&CK T1036 - Masquerading](https://attack.mitre.org/techniques/T1036/)
