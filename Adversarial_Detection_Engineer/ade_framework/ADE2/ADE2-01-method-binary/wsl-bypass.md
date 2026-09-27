---
id: ADE2-007
title: WSL Bypass
ade_category: ADE2
ade_subcategory: ADE2-01
mitre_attack:
  - T1059.001 (Command and Scripting Interpreter: PowerShell)
  - T1202 (Indirect Command Execution)
  - T1564.006 (Hide Artifacts: Run Virtual Instance)
platform: Windows
testable: true
---

# WSL Bypass

## Summary

Windows Subsystem for Linux (WSL) runs a real Linux kernel inside Windows. PowerShell 7 (`pwsh`) is available natively in most WSL distributions. An attacker running `pwsh` inside WSL can read/write Windows files via `/mnt/c/`, download payloads, and query network services -- all invisible to Windows process telemetry. Detection rules written for `powershell.exe` / `pwsh.exe` on the Windows host omit the alternative `pwsh` running inside WSL.

## ADE Classification

**Category:** ADE2 -- Omit Alternatives
**Core principle:** The rule covers `powershell.exe` and `pwsh.exe` on Windows but omits the alternative `pwsh` running inside WSL. Every alternative the rule does not enumerate is a free pass.

**Important caveat:** This bypass also has a telemetry-availability dimension that sits outside the ADE Framework. The framework formalizes detection logic bugs, but here, even a perfect ADE2 fix (enumerate `pwsh`-on-WSL) cannot fire if WSL telemetry never reaches the SIEM. That is a precondition problem, not a logic bug, and a production fix requires ingestion changes (WSL audit log integration) on top of any rule update.

## The Technique

WSL2 runs a real Linux kernel in a Hyper-V VM. Key properties:

| Action | Visible to Windows Sysmon? |
|--------|---------------------------|
| WSL interop (calling `.exe` from WSL) | Yes -- EID 1, parent = `wsl.exe` |
| Linux-native commands (including Linux `pwsh`) | No |
| File writes via `/mnt/c/` | Yes -- EID 11 via `dllhost.exe` |
| Network connections from WSL2 | No -- Hyper-V VM has own network stack |

Linux-native `pwsh` runs in a Linux process context: `whoami` returns the Linux username, not the Windows identity. It has no access to LSASS, Windows Credential Manager, or Win32 APIs. But it **can**:

- Read and exfiltrate files from the Windows filesystem via `/mnt/c/` (credential files, browser profiles, SSH keys)
- Download payloads and drop them for later Windows-side execution
- Query network services (LDAP, SMB, WinRM) if the attacker has credentials

None of this generates Windows process telemetry.

## Bypass Demonstration

### Benign test payload

```bash
# From inside a WSL Ubuntu shell:

# Decode a payload using Linux base64 and write to Windows filesystem
echo 'SGVsbG8gV29ybGQ=' | base64 -d > /mnt/c/Users/Public/hello.txt
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Raw command line | Linux `pwsh -c 'Invoke-WebRequest ...'` -- inside WSL |
| Windows Sysmon | Nothing -- no Windows process ran |
| Windows file system | File appears in `C:\Users\Public\` via `DllHost.exe` |
| Script Block Logging (4104) | Nothing -- logs Windows PowerShell only |
| AMSI | Nothing -- Windows AMSI does not see WSL processes |

## Vulnerable Rule

```yaml
title: PowerShell Web Download Cradle (Naive - Windows Only)
id: 77777777-7777-7777-7777-000000000001
status: experimental
description: Detects PowerShell invoking Invoke-WebRequest to download an executable
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
    CommandLine|contains|all:
      - 'Invoke-WebRequest'
      - '-OutFile'
  condition: selection
level: medium
```

### Why it misses

The `Image|endswith` clause requires a Windows-side process. WSL's `pwsh` lives at `/usr/bin/pwsh` — a Linux path. From the perspective of Windows process telemetry, no `pwsh.exe` ever ran. The rule is correct for what it sees, but it sees nothing.

## Hardened Rule

The fix is not a single rule -- it requires defense in depth across two axes:

**Part (a) -- Detect WSL invocation itself:**

`wsl.exe` is a Win32 process and does generate Windows telemetry. Flag any invocation from a non-developer parent.

**Part (b) -- Detect Windows-side artifacts:**

Files appearing from WSL writes to `/mnt/c/` are observable as file-creation events, even though no Windows process owns them.

```yaml
title: WSL-Side Artifact Drop (Hardened, Multi-Surface)
id: 77777777-7777-7777-7777-000000000002
status: stable
description: |
  Two complementary detections for WSL-as-attack-platform.
  (a) wsl.exe invocations -- flag for review with parent-process context.
  (b) File creation in user-writable paths with script/binary extensions.
logsource:
  product: windows
detection:
  selection_wsl_image:
    EventID: 1
    Image|endswith: '\wsl.exe'
  selection_wsl_ofn:
    EventID: 1
    OriginalFileName: 'wsl.exe'
  selection_file_drop:
    EventID: 11
    TargetFilename|re|i: 'C:\\Users\\Public\\.+\.(exe|dll|ps1|js|vbs|hta|bat)$'
  filter_known_good_parents:
    ParentImage|endswith:
      - '\Code.exe'
      - '\WindowsTerminal.exe'
      - '\devenv.exe'
  condition: ((selection_wsl_image or selection_wsl_ofn) and not filter_known_good_parents) or selection_file_drop
level: high
fields:
  - Image
  - ParentImage
  - TargetFilename
  - User
```

**Long-term fix:** Ingest WSL telemetry. Install SysmonForLinux (eBPF-based) or an EDR agent inside the WSL distro. Without this, WSL is a permanent blind spot -- Windows-side Sysmon cannot see into WSL2.

## Sysmon Evidence

### Key Fields (WSL invocation -- Part a)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\wsl.exe` | WSL launcher is a Win32 process |
| CommandLine | `wsl -d Ubuntu` or `wsl pwsh -c '...'` | May or may not reveal intent |
| OriginalFileName | `wsl.exe` | From PE VERSION_INFO |
| ParentImage | Varies | Key context: developer tool vs. suspicious parent |

### Key Fields (File drop -- Part b)

| Field | Value | Note |
|-------|-------|------|
| EventID | 11 | FileCreate |
| Image | `C:\Windows\System32\DllHost.exe` | WSL file writes surface through DllHost |
| TargetFilename | `C:\Users\Public\payload.exe` | The dropped file |
| CreationUtcTime | Timestamp | Correlate with nearby wsl.exe invocations |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Command-line substring | No | No Windows command line exists for WSL-internal processes |
| Image field (Windows) | No | WSL `pwsh` is a Linux process, invisible to Windows |
| WSL launcher detection | Partial | `wsl.exe` invocation visible, but not what runs inside |
| OriginalFileName | N/A | Linux processes have no PE header |
| File-drop detection | Partial | Catches artifacts on Windows filesystem |
| Script Block Logging | No | Windows SBL does not cover WSL processes |
| AMSI | No | Windows AMSI does not cover WSL processes |
| WSL-internal telemetry | Yes | SysmonForLinux or EDR inside the distro (requires ingestion) |

## Implementation Nuances

- **NUANCES #8 (WSL2 telemetry boundary):** Windows Sysmon cannot see into WSL2. WSL interop calls (`.exe` from WSL) are visible, but Linux-native commands are not. Network connections from WSL2 are invisible to Windows -- the Hyper-V VM has its own network stack.
- **NUANCES #1 (OriginalFileName):** Always OR `Image|endswith` and `OriginalFileName` for the `wsl.exe` detection.
- **NUANCES #11 (OriginalFileName survives rename):** If an attacker copies `wsl.exe` to a different name, OriginalFileName still reads `wsl.exe`.
