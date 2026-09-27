---
id: ADE2-005
title: Regsvr32 Scriptlet (Squiblydoo)
ade_category: ADE2
ade_subcategory: ADE2-01
mitre_attack:
  - T1218.010 (System Binary Proxy Execution: Regsvr32)
platform: Windows
testable: true
---

# Regsvr32 Scriptlet (Squiblydoo)

## Summary

Regsvr32 can execute COM scriptlets (`.sct` files) from local or remote URLs using the `scrobj.dll` (Windows Script Component runtime). The technique, known as "Squiblydoo," bypasses application whitelisting because regsvr32.exe is a signed Microsoft binary. The scriptlet can contain JScript or VBScript that executes arbitrary code, including launching PowerShell or dropping files. The load of `scrobj.dll` by regsvr32 is a near-zero false positive detection signal.

## ADE Classification

**Category:** ADE2 - Omit Alternatives
**Subcategory:** ADE2-02 - Alternative Code Execution
**Core principle:** Rules focused on script interpreters (powershell.exe, cscript.exe, wscript.exe) miss code execution through regsvr32 + scrobj.dll, which executes JScript/VBScript inside a trusted system binary.

## The Technique

Regsvr32 is designed to register and unregister COM DLLs. The `/i` flag specifies an "install" parameter that gets passed to a DLL's `DllInstall` function. When paired with `scrobj.dll` (the Windows Script Component runtime), the `/i` parameter is interpreted as a URL pointing to a COM scriptlet file.

The canonical Squiblydoo command:

```
regsvr32 /s /n /u /i:<URL-or-path-to-SCT> scrobj.dll
```

Flag breakdown:

| Flag | Purpose |
|------|---------|
| `/s` | Silent - suppress dialog boxes |
| `/n` | Do not call DllRegisterServer - prevents actual COM registration |
| `/u` | Unregister (combined with /n, effectively a no-op on the registration side) |
| `/i:URL` | Passes the URL to DllInstall - scrobj.dll fetches and executes the scriptlet |

### What a scriptlet contains

A COM scriptlet (.sct) is an XML file with a `<registration>` element containing a `<script>` block. The script block can contain JScript or VBScript code that runs when scrobj.dll processes the scriptlet. The code can:

- Launch processes via the WScript.Shell COM object
- Download files via the MSXML2.XMLHTTP COM object
- Access the filesystem via Scripting.FileSystemObject
- Launch PowerShell, cmd.exe, or any other binary
- Instantiate arbitrary COM objects

See [Atomic Red Team T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md) for complete payload examples.

### Local vs. remote execution

The scriptlet can be hosted remotely (HTTP/HTTPS) or placed locally:

```
regsvr32 /s /n /u /i:C:\path\to\payload.sct scrobj.dll
```

**OriginalFileName:** `REGSVR32.EXE` (Sysmon strips the `.MUI` suffix - see NUANCES #4)

## Bypass Demonstration

### Benign test payload

For a safe test, use the Atomic Red Team test case for T1218.010, which creates a benign scriptlet that simply writes a marker file. See the [Atomic Red Team T1218.010 test](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md) for the exact payload and execution steps.

The key command to observe in Sysmon:

```
regsvr32 /s /n /u /i:C:\Users\Public\test.sct scrobj.dll
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Sysmon EID 1 CommandLine | `regsvr32 /s /n /u /i:C:\Users\Public\test.sct scrobj.dll` |
| Sysmon EID 7 ImageLoaded | `scrobj.dll` loaded by regsvr32.exe |
| Sysmon EID 3 (if remote URL) | `regsvr32.exe` connecting to the SCT host |
| Sysmon EID 1 (child process) | Whatever the scriptlet launches with ParentImage = regsvr32.exe |
| Script Block Logging (4104) | N/A unless the scriptlet launches PowerShell |
| AMSI | May intercept JScript/VBScript content in Windows 10+ |

## Vulnerable Rule

```yaml
title: Script Execution via Windows Script Host
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\cscript.exe'
            - '\wscript.exe'
    condition: selection
```

### Why it misses

The rule monitors the Windows Script Host binaries (cscript/wscript) but not regsvr32 + scrobj.dll, which is an alternative JScript/VBScript execution engine. The script runs inside regsvr32.exe, not cscript or wscript.

## Hardened Rule

```yaml
title: Regsvr32 Scriptlet Execution - Squiblydoo (Hardened)
status: experimental
description: |
    Detects regsvr32.exe loading scrobj.dll via the /i flag, which
    executes COM scriptlet files containing JScript or VBScript.
    This is the canonical Squiblydoo technique.
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\regsvr32.exe'
        - OriginalFileName: 'REGSVR32.EXE'
    selection_scrobj:
        CommandLine|contains: 'scrobj'
    condition: selection_img and selection_scrobj
falsepositives:
    - Legitimate COM scriptlet registration (extremely rare on endpoints)
level: critical
---
title: Regsvr32 with Remote URL in /i Parameter (Hardened)
status: experimental
description: |
    Detects regsvr32.exe invoked with a remote URL in the /i parameter,
    indicating remote scriptlet execution.
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\regsvr32.exe'
        - OriginalFileName: 'REGSVR32.EXE'
    selection_remote:
        CommandLine|contains:
            - '/i:http'
            - '/i:ftp'
            - '/i:\\\\'
    condition: selection_img and selection_remote
falsepositives:
    - None expected
level: critical
---
title: Scrobj.dll Load by Regsvr32 (Image Load Detection)
status: experimental
description: |
    Detects scrobj.dll being loaded by regsvr32.exe. This is the
    highest-fidelity signal for Squiblydoo because scrobj.dll is the
    Script Component runtime and has near-zero legitimate use with
    regsvr32. This rule works even when command-line arguments are
    obfuscated.
logsource:
    category: image_load
    product: windows
detection:
    selection:
        Image|endswith: '\regsvr32.exe'
        ImageLoaded|endswith: '\scrobj.dll'
    condition: selection
falsepositives:
    - Legitimate COM scriptlet development (extremely rare)
level: critical
---
title: Regsvr32 Spawning Suspicious Child Process
status: experimental
description: |
    Detects regsvr32.exe spawning script interpreters or shells,
    which indicates a scriptlet executed code that launched a subprocess.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\regsvr32.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cscript.exe'
            - '\wscript.exe'
            - '\mshta.exe'
            - '\rundll32.exe'
    condition: selection
falsepositives:
    - None expected - regsvr32 should not spawn script interpreters
level: critical
```

## Sysmon Evidence

### Event ID 1 - Process Create (regsvr32.exe)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\regsvr32.exe` | Signed Microsoft binary |
| CommandLine | `regsvr32 /s /n /u /i:C:\Users\Public\test.sct scrobj.dll` | Scriptlet path and scrobj.dll visible |
| OriginalFileName | `REGSVR32.EXE` | Sysmon strips `.MUI` suffix |
| ParentImage | `C:\Windows\System32\cmd.exe` | Parent process |

### Event ID 7 - Image Loaded (scrobj.dll)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\regsvr32.exe` | Loading process |
| ImageLoaded | `C:\Windows\System32\scrobj.dll` | Script Component runtime - KEY SIGNAL |
| Signed | `true` | Microsoft-signed |

### Event ID 1 - Child Process (if scriptlet launches one)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\cmd.exe` (example) | Whatever the scriptlet launched |
| ParentImage | `C:\Windows\System32\regsvr32.exe` | regsvr32 as parent is the detection signal |
| ParentCommandLine | `regsvr32 /s /n /u /i:C:\Users\Public\test.sct scrobj.dll` | Full context in parent |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| cscript/wscript Image detection | No | Script runs inside regsvr32, not WSH |
| regsvr32 + scrobj CommandLine | Yes | Catches the canonical Squiblydoo pattern |
| scrobj.dll image load | Yes | Near-zero FP - best single signal |
| regsvr32 network connection | Yes | regsvr32 fetching remote SCT files |
| regsvr32 child process | Yes | regsvr32 should never spawn shells or interpreters |
| Image/OriginalFileName | Yes | Identifies the binary regardless of rename |
| Script Block Logging (4104) | Partial | Only if the scriptlet launches PowerShell |
| AMSI | Partial | Windows 10+ may intercept JScript/VBScript in scrobj |
| Behavioral (file creation) | Yes | Scriptlet file drops detectable via EID 11 |

## Known APT Usage

| Threat Actor | Context |
|-------------|---------|
| APT19 (Deep Panda) | Used Squiblydoo in phishing campaigns targeting law firms and investment companies |
| APT32 (OceanLotus) | Employed regsvr32 scriptlet execution in Southeast Asian espionage campaigns |
| Lazarus Group | Incorporated regsvr32 + scrobj.dll in multi-stage attack chains |
| Emotet | Used regsvr32 for DLL payload execution in banking trojan distribution |
| QakBot (Qbot) | Leveraged regsvr32 for DLL sideloading in initial access operations |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #4: Sysmon strips `.MUI` suffix - OriginalFileName shows `REGSVR32.EXE`, not `REGSVR32.EXE.MUI`
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #11: OriginalFileName survives binary copy/rename - catches regsvr32 copies placed elsewhere
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #5: Sigma `|re` regex varies by backend - if using regex to parse the `/i:` parameter value, test on your target SIEM

## References

- [LOLBAS - Regsvr32.exe](https://lolbas-project.github.io/lolbas/Binaries/Regsvr32/)
- [MITRE ATT&CK T1218.010 - Regsvr32](https://attack.mitre.org/techniques/T1218/010/)
- [Atomic Red Team - T1218.010](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.010/T1218.010.md)
- [Casey Smith - Original Squiblydoo Research](https://web.archive.org/web/2016/http://subt0x10.blogspot.com/2016/04/bypass-application-whitelisting-script.html)
- [Red Canary - Regsvr32 Threat Detection](https://redcanary.com/threat-detection-report/techniques/regsvr32/)
