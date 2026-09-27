---
id: ADE3-002
title: Parent PID Spoofing
ade_category: ADE3
ade_subcategory: ADE3-05
mitre_attack:
  - T1134.004 (Access Token Manipulation: Parent PID Spoofing)
platform: Windows
testable: false
---

# Parent PID Spoofing

## Summary

Using `CreateProcess` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`, an attacker can assign an arbitrary parent to a newly spawned process. Sysmon EID 1 logs the **spoofed** parent (ParentProcessId, ParentImage, ParentCommandLine all reflect the fake parent), but Windows Security Event 4688's `Creator Process ID` field reveals the **real** parent. This mismatch is the primary detection signal.

## ADE Classification

**Category:** ADE3 -- Context Development
**Subcategory:** ADE3-02 -- Parent Process Manipulation
**Core principle:** Sysmon trusts the OS-reported parent process relationship, which the attacker controls via `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. Other telemetry sources (Security 4688, ETW kernel-process) record the true creator, creating a detectable divergence.

## The Technique

Windows allows a process to specify a custom parent process handle when creating a child via `CreateProcess` with an extended attribute list containing `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`. The child process is created as though it were spawned by the specified parent:

1. The attacker opens a handle to the desired parent process with `PROCESS_CREATE_PROCESS` access
2. The attacker initializes a `STARTUPINFOEX` structure with an attribute list containing `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` pointing to the parent handle
3. `CreateProcess` is called with `EXTENDED_STARTUPINFO_PRESENT`
4. The new process appears in the process tree under the spoofed parent

**What gets spoofed (Sysmon EID 1):**
- `ParentProcessId` -- shows the spoofed parent's PID
- `ParentImage` -- shows the spoofed parent's image path
- `ParentCommandLine` -- shows the spoofed parent's command line

**What tells the truth:**
- Windows Security Event 4688 `Creator Process ID` -- the actual process that called `CreateProcess`
- ETW `Microsoft-Windows-Kernel-Process` provider `EventHeader.ProcessId` -- the real caller
- Elastic Defend `process.parent.Ext.real.pid` -- explicitly exposes the true parent

**Access requirements:** The calling process needs `PROCESS_CREATE_PROCESS` access on the handle to the target parent process. High-integrity processes can open handles to most user-mode processes. Opening handles to SYSTEM-level processes (e.g., services.exe, lsass.exe) typically requires `SeDebugPrivilege`.

### Why attackers use it

Parent PID spoofing serves multiple purposes:
- **Evade parent-child rules:** Rules like "alert if powershell.exe is spawned by outlook.exe" are defeated because the rule sees the spoofed parent
- **Inherit security context:** The child inherits the token of the specified parent, potentially gaining higher privileges
- **Blend into process tree:** A malicious process parented to svchost.exe or explorer.exe looks normal in process listings

### Known users

- **Cobalt Strike** -- `ppid` command sets parent PID for spawned beacons
- **DarkGate** -- uses PPID spoofing as part of its evasion chain
- **Hive ransomware** -- spoofs parent to evade behavioral detection
- **Various C2 frameworks** -- Brute Ratel, Sliver, and Mythic all support PPID spoofing

## Bypass Demonstration

> **Lab-only.** This technique requires opening handles to other processes and manipulating process creation attributes. There is no safe benign test outside an isolated lab environment.

### Conceptual pseudocode

```c
// 1. Open handle to desired fake parent (e.g., explorer.exe)
HANDLE hParent = OpenProcess(PROCESS_CREATE_PROCESS, FALSE, explorerPid);

// 2. Initialize attribute list
SIZE_T attrSize;
InitializeProcThreadAttributeList(NULL, 1, 0, &attrSize);
LPPROC_THREAD_ATTRIBUTE_LIST pAttrList = (LPPROC_THREAD_ATTRIBUTE_LIST)HeapAlloc(...);
InitializeProcThreadAttributeList(pAttrList, 1, 0, &attrSize);

// 3. Set parent process attribute
UpdateProcThreadAttribute(pAttrList, 0, PROC_THREAD_ATTRIBUTE_PARENT_PROCESS,
                          &hParent, sizeof(HANDLE), NULL, NULL);

// 4. Create process with spoofed parent
STARTUPINFOEX si = { sizeof(si) };
si.lpAttributeList = pAttrList;
CreateProcess(NULL, "cmd.exe", NULL, NULL, FALSE,
              EXTENDED_STARTUPINFO_PRESENT, NULL, NULL,
              &si.StartupInfo, &pi);
```

### What each telemetry source sees

| Telemetry Source | Field | Sees | Truthful? |
|------------------|-------|------|-----------|
| Sysmon EID 1 | ParentProcessId | Explorer.exe PID (spoofed) | No |
| Sysmon EID 1 | ParentImage | `C:\Windows\explorer.exe` (spoofed) | No |
| Sysmon EID 1 | ParentCommandLine | Explorer's command line (spoofed) | No |
| Security 4688 | Creator Process ID | Real caller's PID | **Yes** |
| Security 4688 | Creator Process Name | Real caller's name | **Yes** |
| ETW Kernel-Process | EventHeader.ProcessId | Real caller's PID | **Yes** |
| Elastic Defend | process.parent.Ext.real.pid | Real caller's PID | **Yes** |

## Vulnerable Rule

```yaml
title: Suspicious Process Spawned by Explorer
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\cmd.exe'
            - '\powershell.exe'
        ParentImage|endswith: '\outlook.exe'
    condition: selection
```

### Why it misses

The attacker spoofs the parent to `explorer.exe`. Sysmon's `ParentImage` shows `\explorer.exe`, not `\outlook.exe`. Any rule relying on Sysmon's parent fields is trivially defeated.

Even rules that look for *suspicious* parents (e.g., alert if cmd.exe is NOT spawned by explorer.exe) can be defeated by spoofing the parent to exactly the expected process.

## Hardened Rule

```yaml
title: Parent PID Spoofing Detection (4688 vs Sysmon Mismatch)
status: experimental
description: |
    Correlates Windows Security 4688 Creator Process ID with Sysmon EID 1
    ParentProcessId. A mismatch indicates the parent was spoofed.
logsource:
    category: process_creation
    product: windows
detection:
    selection_sysmon:
        EventID: 1
    condition: selection_sysmon
# NOTE: This rule requires a correlation engine that can:
# 1. Join Sysmon EID 1 and Security 4688 on the target ProcessId
# 2. Compare ParentProcessId (Sysmon) vs Creator Process ID (4688)
# 3. Alert when they differ
# Pure Sigma cannot express cross-log correlation — implement in SIEM
```

### SIEM correlation pseudocode (Splunk SPL)

```spl
index=sysmon EventCode=1
| eval sysmon_ppid=ParentProcessId
| join ProcessId [
    search index=security EventCode=4688
    | eval security_creator=Creator_Process_ID
    | rename New_Process_ID as ProcessId
]
| where sysmon_ppid != security_creator
| table _time, Image, CommandLine, sysmon_ppid, security_creator, ParentImage, User
```

### Why the hardened approach works

Windows Security 4688 is populated by the kernel's auditing subsystem, which records the actual process that made the `NtCreateProcess` call. This value cannot be manipulated by `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` -- it reflects the true creator regardless of the attribute list contents.

## Sysmon Evidence

> **Lab-only -- no benign reproduction possible.** The following describes the expected Sysmon output based on documented behavior.

### Expected Event ID 1 -- Process Create (spoofed parent)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\cmd.exe` | Child process (legitimate binary) |
| CommandLine | `"cmd.exe"` | Child command line |
| ParentProcessId | `1234` | **SPOOFED** -- PID of explorer.exe |
| ParentImage | `C:\Windows\explorer.exe` | **SPOOFED** -- attacker chose this |
| ParentCommandLine | `C:\Windows\explorer.exe` | **SPOOFED** |
| User | `DOMAIN\attacker` | Inherited from actual caller or spoofed parent |
| LogonId | `0x12345` | Can reveal mismatch if parent's session differs |

### Expected Security Event 4688

| Field | Value | Note |
|-------|-------|------|
| New Process ID | `0x5678` | The spawned cmd.exe |
| New Process Name | `C:\Windows\System32\cmd.exe` | Child process |
| Creator Process ID | `0x9ABC` | **REAL** parent -- the attacker's process |
| Creator Process Name | `C:\Temp\malware.exe` | **REAL** parent binary |

The mismatch between Sysmon's `ParentProcessId` (explorer.exe) and 4688's `Creator Process ID` (malware.exe) is the detection signal.

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Sysmon ParentImage rules | No | ParentImage is spoofed to attacker's choice |
| Security 4688 Creator Process ID | Yes | Kernel auditing records the true caller |
| 4688-vs-EID1 correlation | Yes | Mismatch between reported parents is definitive |
| ETW Kernel-Process provider | Yes | EventHeader.ProcessId is the real creator |
| Login session mismatch | Yes | Spoofed parent in Session 0 but child in Session 1 |
| Timing anomalies | Partial | Parent process started hours ago but suddenly spawns children |
| Elastic process.parent.Ext.real.pid | Yes | Explicitly surfaces the real parent PID |
| Handle access patterns | Partial | PROCESS_CREATE_PROCESS on unrelated processes is unusual |

## Detection Approaches in Detail

### 1. Creator Process ID mismatch (primary)

Enable Windows Security Auditing for process creation (4688) with command-line logging. Correlate 4688 `Creator Process ID` with Sysmon EID 1 `ParentProcessId` for each new process. Any mismatch is a strong indicator.

### 2. Login session mismatch

If the spoofed parent runs in a different logon session than the child, the `LogonId` values will not match normal parent-child inheritance patterns. A process supposedly spawned by `svchost.exe` (Session 0) but running in an interactive user session (Session 1+) is suspicious.

### 3. ETW correlation

The `Microsoft-Windows-Kernel-Process` ETW provider emits process-creation events where `EventHeader.ProcessId` is the true caller. EDR products that consume ETW directly can compare this against the reported parent PID.

### 4. Handle access auditing

Opening a handle with `PROCESS_CREATE_PROCESS` to unrelated processes (especially long-lived processes like explorer.exe, svchost.exe) generates Security Event 4656/4663. Unusual handle access patterns on these targets can serve as an early indicator.

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) -- Sysmon trusts the OS-reported parent relationship; cross-source correlation is required for detection
- Windows Security Event 4688 must have "Include command line in process creation events" enabled via Group Policy for full value
- Sysmon alone is insufficient to detect this technique -- 4688 or ETW is mandatory for ground truth
- Some EDR products (CrowdStrike, Elastic, SentinelOne) expose real vs. reported parent natively in their telemetry

## References

- [MITRE ATT&CK T1134.004 - Parent PID Spoofing](https://attack.mitre.org/techniques/T1134/004/)
- [Didier Stevens - SelectMyParent](https://blog.didierstevens.com/2009/11/22/quickpost-selectmyparent-or-playing-with-the-windows-process-tree/)
- [F-Secure - Detecting Parent PID Spoofing](https://labs.f-secure.com/blog/detecting-parent-pid-spoofing)
- [Elastic Security - PPID Spoofing Detection](https://www.elastic.co/guide/en/security/current/parent-process-pid-spoofing.html)
- [XPN InfoSec - Protecting Your Malware: Parent PID Spoofing](https://blog.xpnsec.com/protecting-your-malware/)
- [Cobalt Strike Documentation - ppid command](https://hstechdocs.helpsystems.com/manuals/cobaltstrike/current/userguide/content/topics/post-exploitation_process-options.htm)
