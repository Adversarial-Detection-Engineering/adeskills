# Windows API & WMI Alternatives

Detection rules that monitor a single method for achieving an outcome (e.g., only detecting `CreateProcess` for process creation) are vulnerable to ADE2-01 (Omit Alternatives - Method/Binary). Attackers choose whichever API or method is unmonitored. This module catalogs alternative methods grouped by attacker objective.

## Process Creation Alternatives

Multiple APIs and methods create processes on Windows, each producing different telemetry:

- **CreateProcessA/W**: Standard Win32 API. Logged by Sysmon EID 1, Security EID 4688. Most commonly monitored.
- **CreateProcessAsUserA/W**: Creates process under a different user token. Requires `SeAssignPrimaryTokenPrivilege`.
- **CreateProcessWithLogonW**: Creates process with alternate credentials. Spawns under `svchost.exe` via Secondary Logon service, breaking expected parent-child relationships.
- **CreateProcessWithTokenW**: Similar to above, uses explicit token handle.
- **ShellExecuteA/W / ShellExecuteExA/W**: Higher-level API that resolves file associations. `ShellExecute(NULL, "open", "http://evil.com", ...)` opens URLs via default browser. Process parent appears as explorer.exe in some cases.
- **WMI Win32_Process.Create**: `wmic process call create "cmd /c calc"` or PowerShell `Invoke-WmiMethod`. Parent process is `WmiPrvSE.exe`, not the calling process. Breaks parent-child detection heuristics.
- **COM objects**: `$obj = New-Object -ComObject Shell.Application; $obj.ShellExecute("cmd")`. Uses COM infrastructure, parent may appear as `svchost.exe` or `explorer.exe`.
- **Task Scheduler API**: `ITaskService::RegisterTaskDefinition` or `schtasks /run`. Executes as child of `svchost.exe` (taskeng.exe on older systems).
- **NtCreateUserProcess**: Native API (ntdll.dll). Lower-level than CreateProcess. Used to evade usermode API hooks.
- **RtlCreateUserProcess**: Another ntdll native API for process creation.

## Process Injection Techniques

Rules detecting one injection API miss alternatives:

| Technique | APIs |
|-----------|------|
| Classic injection | CreateRemoteThread + VirtualAllocEx + WriteProcessMemory |
| APC queue | QueueUserAPC + NtTestAlert |
| Section mapping | NtCreateSection + NtMapViewOfSection |
| Thread hijack | SuspendThread + SetThreadContext + ResumeThread |
| Atom bombing | GlobalAddAtom + NtQueueApcThread |
| Process hollowing | CreateProcess(SUSPENDED) + NtUnmapViewOfSection + NtMapViewOfSection |
| Early bird | CreateProcess(SUSPENDED) + QueueUserAPC (before main thread runs) |
| Module stomping | LoadLibrary + overwrite .text section |
| Syscall direct | Nt/Zw variants bypass user-mode hooks |
| Callback injection | EnumWindows, EnumChildWindows, CreateTimerQueueTimer |

Code injection into existing processes avoids creating new process telemetry entirely:


- **Classic injection**: `VirtualAllocEx` -> `WriteProcessMemory` -> `CreateRemoteThread`. Most commonly detected pattern. Each API call is hookable.
- **QueueUserAPC**: Queues an APC to a target thread. Requires thread in alertable wait state. Less monitored than CreateRemoteThread.
- **NtMapViewOfSection**: Maps a shared memory section into target process. No `WriteProcessMemory` call needed. Used in process hollowing.
- **Process hollowing**: `CreateProcess` (suspended) -> `NtUnmapViewOfSection` -> `NtMapViewOfSection`/`WriteProcessMemory` -> `ResumeThread`. Replaces the legitimate image entirely.
- **Thread hijacking**: `SuspendThread` -> `GetThreadContext` -> `SetThreadContext` (modify RIP/EIP) -> `ResumeThread`. No new thread creation, evades CreateRemoteThread monitoring.
- **AtomBombing**: Uses global atom tables and `NtQueueApcThread` with `GlobalGetAtomName` in ROP chain. No `WriteProcessMemory`.
- **Early bird injection**: APC injection into a suspended process before it initializes, running malicious code before EDR hooks are installed.
- **Module stomping**: Overwriting a loaded legitimate DLL's `.text` section with malicious code. No new memory allocation.
- **Phantom DLL hollowing**: Loading a legitimate DLL, then overwriting its content via section manipulation.
- **Transacted hollowing**: Using TxF (transactional NTFS) to create a file, write payload, map it, then rollback the transaction. File never exists on disk.

## Code Execution via Callbacks

Windows APIs accepting callback functions can be abused for code execution without explicit thread creation:

- **EnumWindows / EnumChildWindows**: Callback for each top-level window. `EnumWindows(shellcodeAddr, 0)`.
- **EnumDesktops / EnumDesktopWindows**: Enumerates desktops with callback.
- **CreateTimerQueueTimer**: Fires a callback after a timer interval. Code executes in thread pool.
- **CertEnumSystemStore**: Callback during certificate store enumeration.
- **CopyFile2 (ProgressRoutine)**: Progress callback during file copy.
- **Fiber-based execution**: `ConvertThreadToFiber` -> `CreateFiber(shellcodeAddr)` -> `SwitchToFiber`. No new thread, executes in existing thread context.

## WMI and CIM Alternatives

WMI provides extensive system management capabilities often used for lateral movement and persistence:

- **wmic.exe**: Deprecated command-line WMI client. `wmic /node:target process call create "cmd"`. Heavily monitored in modern rules.
- **PowerShell WMI cmdlets**: `Get-WmiObject`, `Invoke-WmiMethod`, `Set-WmiInstance`. Older, DCOM-based.
- **PowerShell CIM cmdlets**: `Get-CimInstance`, `Invoke-CimMethod`, `New-CimSession`. Use WS-Man (WinRM) by default. Different network protocol than WMI/DCOM -- rules monitoring DCOM miss CIM over WinRM.
- **WMI event subscriptions**: Persistent event-action pairs. `__EventFilter` (trigger condition) + `__EventConsumer` (action) + `__FilterToConsumerBinding` (link). Survives reboots. Consumer types: `CommandLineEventConsumer`, `ActiveScriptEventConsumer`, `LogFileEventConsumer`.
- **DCOM lateral movement**: WMI over DCOM to remote hosts. `Invoke-WmiMethod -ComputerName target -Class Win32_Process -Name Create -ArgumentList "cmd"`. Network traffic on TCP/135 + dynamic RPC ports.
- **WinRM lateral movement**: `Invoke-Command -ComputerName target -ScriptBlock { cmd /c calc }`. Uses TCP/5985 (HTTP) or 5986 (HTTPS). Different network signature than DCOM.

## Registry Modification Methods

Multiple methods write to the same registry keys, producing different telemetry:

- **reg.exe**: `reg add HKLM\SOFTWARE\... /v key /t REG_SZ /d value`. Command-line tool, logged via process creation events.
- **PowerShell**: `Set-ItemProperty -Path 'HKLM:\SOFTWARE\...' -Name key -Value value`. Logged in ScriptBlock logging (EID 4104).
- **regedit.exe /s**: Silent import of .reg files. Single command line, payload is in the .reg file.
- **.NET Registry class**: `[Microsoft.Win32.Registry]::SetValue(...)`. Logged only if script logging is enabled.
- **WMI StdRegProv**: `Invoke-WmiMethod -Class StdRegProv -Name SetStringValue`. Remote-capable. Different telemetry source.
- **Direct NT API**: `NtSetValueKey`. Bypasses usermode API hooks.

## Service Creation Methods

- **sc.exe**: `sc create svcname binpath= "C:\payload.exe"`. Process creation event for sc.exe.
- **PowerShell**: `New-Service -Name svcname -BinaryPathName "C:\payload.exe"`. ScriptBlock logging.
- **WMI Win32_Service**: `Invoke-WmiMethod -Class Win32_Service -Name Create`. Remote-capable, no sc.exe process.
- **Direct registry manipulation**: Writing to `HKLM\SYSTEM\CurrentControlSet\Services\svcname` directly. No service creation API called.
- **CreateServiceA/W API**: Programmatic service creation from compiled code.

## Direct Syscalls and Unhooking

To evade EDR usermode hooks on ntdll.dll:

- **Direct syscalls**: Using inline assembly or dynamically resolved syscall numbers to call NT APIs without going through ntdll.dll. Tools: SysWhispers, HellsGate, Halo's Gate.
- **NTDLL unhooking**: Reading a clean copy of ntdll.dll from disk (`\KnownDlls\ntdll.dll` or from the file on disk) and overwriting the hooked in-memory copy. Restores original API bytes.
- **Manual DLL mapping**: Loading a second copy of ntdll.dll from disk into the process and calling the unhooked exports from that copy.
- **Indirect syscalls**: Using `jmp` to the syscall instruction inside ntdll.dll rather than executing it inline, making the return address appear to come from ntdll.

## Credential Access Alternatives

| Technique | Mechanisms |
|-----------|-----------|
| LSASS dump | MiniDumpWriteDump, ProcDump, comsvcs.dll, nanodump, direct syscalls |
| SAM dump | reg save HKLM\SAM, Volume Shadow Copy, esentutl |
| DPAPI | CryptUnprotectData, Mimikatz dpapi::, SharpDPAPI |
| Token theft | DuplicateTokenEx, ImpersonateLoggedOnUser, CreateProcessWithToken |
| Kerberos | Pass-the-Ticket, Overpass-the-Hash, Kerberoasting |

## Persistence Alternatives

| Method | Locations |
|--------|-----------|
| Registry Run keys | HKCU\..\Run, HKLM\..\Run, RunOnce, RunOnceEx, RunServices |
| Scheduled tasks | schtasks, at, WMI subscription, COM task scheduler |
| Services | sc create, New-Service, registry direct, WMI Win32_Service |
| WMI events | __EventFilter + __EventConsumer + __FilterToConsumerBinding |
| COM hijack | InprocServer32 overwrite, TreatAs CLSID redirection |
| DLL side-load | Place DLL in application search path |
| Image File Execution | IFEO Debugger, GlobalFlag + SilentProcessExit |
| AppInit_DLLs | HKLM\..\Windows\AppInit_DLLs (legacy, still works) |

## Service/Process Execution

- **WMI**: Win32_Process.Create — parent is WmiPrvSE.exe
- **DCOM**: Lateral movement via DCOM objects — parent varies
- **PSExec-like**: Named pipe service creation — parent is services.exe
- **Task Scheduler**: Parent is svchost.exe (Schedule service)
- **SSH** (Win10+): Native OpenSSH server — parent is sshd.exe

## Detection Implications
- Rules checking GrantedAccess for LSASS (0x1010, 0x1FFFFF) miss direct syscalls
- Rules checking Image for procdump.exe miss comsvcs.dll MiniDump
- Registry persistence rules often check Run keys but miss WMI, COM hijacks, IFEO
- Process injection rules checking CallTrace for known DLLs miss syscall variants
