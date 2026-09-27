# Persistence Mechanism Alternatives

Persistence ensures attacker access survives reboots, logoffs, or process termination. Detection rules that monitor only common persistence locations (e.g., Run keys) miss dozens of alternative mechanisms. This is a critical instance of ADE2-01 (Omit Alternatives) -- each persistence category has multiple equivalent methods.

## Registry Run Keys

Standard Run key monitoring covers `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Run` and the HKCU equivalent. Frequently missed alternatives:

- **RunOnce**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce` -- executes once then auto-deletes the value. Used for one-shot persistence that cleans itself.
- **RunOnceEx**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnceEx` -- extended version supporting DLL loading via `Depend` values.
- **Policies\Explorer\Run**: `HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run` -- Group Policy-controlled Run equivalent. Often unmonitored.
- **User Shell Folders**: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\User Shell Folders` -- modifying `Startup` value to point to attacker-controlled directory.
- **Shell Folders**: `HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Shell Folders` -- similar to above, legacy key.
- **RunServices / RunServicesOnce**: Legacy keys (Win9x era) that may still be processed on some systems.
- **Explorer\Shell**: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell` -- replaces the default shell (explorer.exe). Setting to `explorer.exe, malware.exe` runs both.
- **RunOnce / RunOnceEx**: Similar but execute once
- **RunServices / RunServicesOnce**: Legacy, still processed
- **Winlogon\Shell / Userinit / Notify**: Shell replacement/extension
- **Explorer\Shell Folders / User Shell Folders**: Startup folder path override
- **Active Setup\StubPath**: Runs once per user
- **IFEO (Image File Execution Options)**: Debugger key, SilentProcessExit MonitorProcess
- **AppInit_DLLs**: Loaded into every process that loads user32.dll
- **AppCertDLLs**: Loaded into processes calling CreateProcess
- **SessionManager\BootExecute**: Runs before Windows fully loads
- **ScreenSaver**: HKCU\..\SCRNSAVE.EXE
- **Print Monitor DLLs**: HKLM\SYSTEM\..\Print\Monitors
- **LSA Security/Authentication Packages**: Loaded by lsass.exe
- **COM Object Hijacking**: InprocServer32 in HKCU overrides HKLM


## Scheduled Tasks

- **schtasks.exe**: `schtasks /create /tn "Updater" /tr "C:\payload.exe" /sc onlogon`. Process creation event for schtasks.exe with command-line arguments. Most commonly detected.
- **PowerShell**: `Register-ScheduledTask`, `New-ScheduledTaskTrigger`, `New-ScheduledTaskAction`. No schtasks.exe process creation. Visible in ScriptBlock logs.
- **COM Task Scheduler interface**: `$ts = New-Object -ComObject Schedule.Service; $ts.Connect(); ...` Uses COM, no schtasks.exe or PowerShell cmdlet in process events.
- **AT command**: `at 13:00 /every:M,T,W,Th,F cmd /c payload.exe`. Deprecated but functional on older systems. Creates tasks visible in Task Scheduler but using legacy interface.
- **Direct XML task file creation**: Writing XML task definitions to `C:\Windows\System32\Tasks\` directory. Bypasses command-line monitoring entirely.
- **WMI**: Win32_ScheduledJob

## Windows Services

- **sc.exe**: `sc create svcname binpath= "C:\payload.exe" start= auto`. Command-line arguments visible in process creation logs.
- **PowerShell New-Service**: `New-Service -Name svcname -BinaryPathName "C:\payload.exe" -StartupType Automatic`. ScriptBlock logging only.
- **WMI Win32_Service.Create**: Remote-capable service creation without sc.exe process.
- **Direct registry manipulation**: Writing to `HKLM\SYSTEM\CurrentControlSet\Services\svcname` with `ImagePath`, `Start`, and `Type` values. No service creation API called. Requires reboot or `sc start` to activate.

## WMI Event Subscriptions

Permanent WMI event subscriptions provide fileless persistence that survives reboots:

- Components: `__EventFilter` (trigger) + `__EventConsumer` (action) + `__FilterToConsumerBinding` (link).
- **CommandLineEventConsumer**: Executes a command line when the event triggers. Process parent is `WmiPrvSE.exe`.
- **ActiveScriptEventConsumer**: Executes VBScript or JScript. No command-line artifact.
- **LogFileEventConsumer**: Writes to a log file, exploitable for DLL planting or script drops.
- Triggers: `__InstanceCreationEvent` (process start), `__TimerEvent` (periodic), `Win32_LogonSession` creation (user logon).
- Stored in the WMI repository (`C:\Windows\System32\wbem\Repository\`), not in files or registry. Requires WMI-specific forensic tools to inspect.

## Startup Folder Variations

- **Current user**: `C:\Users\<user>\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\`
- **All users**: `C:\ProgramData\Microsoft\Windows\Start Menu\Programs\Startup\`
- Files placed here (shortcuts .lnk, scripts .bat/.vbs, executables) run at user logon.
- **LNK files**: Shortcuts can point to arbitrary commands with arguments. The shortcut target may be obfuscated in the .lnk binary structure.
- Detection rules monitoring only executable drops miss .lnk, .url, .scf, and script files.

## DLL Hijacking Persistent Locations

- Applications with known DLL search order vulnerabilities provide persistence when a malicious DLL is placed in the application directory.
- Common targets: OneDrive (`C:\Users\<user>\AppData\Local\Microsoft\OneDrive\`), Teams, Visual Studio Code update mechanisms.
- **Phantom DLL loading**: Placing DLLs with names that legitimate applications attempt to load but do not find (e.g., `version.dll`, `cryptbase.dll` in application directories).
- Persistence activates whenever the vulnerable application starts -- automatic for auto-start applications.

## COM Object Hijacking

- Modifying CLSID registry entries to point to attacker-controlled DLLs: `HKCU\SOFTWARE\Classes\CLSID\{CLSID}\InProcServer32`.
- HKCU entries override HKLM, so non-admin users can hijack COM objects used by system processes.
- Commonly hijacked CLSIDs: those loaded by explorer.exe, taskband, or scheduled tasks.
- **TreatAs key**: Redirects one CLSID to another, enabling indirect hijacking.

## Boot and Logon Autostart

- **Winlogon entries**: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit` (default: `userinit.exe,`) -- appending a payload runs it at every logon. `Winlogon\Notify` (legacy) registers DLLs for logon event notifications.
- **AppInit_DLLs**: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Windows\AppInit_DLLs` -- DLLs loaded into every process that loads user32.dll. Disabled by default with Secure Boot but still functional on misconfigured systems.
- **Image File Execution Options (IFEO)**: `HKLM\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\<binary>\Debugger` -- specifying a "debugger" for a legitimate binary causes the debugger to launch instead. `Debugger: "C:\payload.exe"` for `notepad.exe` runs the payload whenever notepad is opened.
- **IFEO GlobalFlag + SilentProcessExit**: Setting `GlobalFlag` to enable silent process exit monitoring, then configuring `MonitorProcess` under `SilentProcessExit` for a target binary. Payload runs when the target process exits.

## Linux Persistence

- **Cron jobs**: `/etc/crontab`, `/var/spool/cron/crontabs/<user>`, `/etc/cron.d/`, `/etc/cron.daily/`, etc. `crontab -e` for per-user.
- **Systemd services**: Create `.service` file in `/etc/systemd/system/` or `~/.config/systemd/user/`. `systemctl enable malicious.service`. Systemd timers (`.timer`) for periodic execution.
- **Shell profile scripts**: `~/.bashrc`, `~/.bash_profile`, `~/.profile`, `/etc/profile`, `/etc/profile.d/*.sh`. Execute on user login or shell start.
- **LD_PRELOAD**: `/etc/ld.so.preload` or `LD_PRELOAD` environment variable. Specified shared library loaded before all others, allowing function hooking in every process.
- **init.d scripts**: `/etc/init.d/` scripts for SysVinit systems. Executed during boot.
- **udev rules**: `/etc/udev/rules.d/` -- execute commands when hardware events occur (e.g., USB insertion). `RUN+="/path/to/payload"`.
- **SSH authorized_keys**: `~/.ssh/authorized_keys` -- adding attacker's public key provides persistent SSH access.
- **At jobs**: `at` command for one-time scheduled execution. `/var/spool/at/` directory.
- **~/.bashrc, ~/.profile, ~/.bash_logout**: Shell initialization
- **/etc/ld.so.preload**: Shared library injection
- **SSH authorized_keys**: ~/.ssh/authorized_keys
- **PAM modules**: /etc/pam.d/ — authentication hooks
- **at jobs**: /var/spool/at/
- **XDG autostart**: ~/.config/autostart/*.desktop
- **MOTD scripts**: /etc/update-motd.d/
- **udev rules**: /etc/udev/rules.d/

## Exotic Persistence

- **Accessibility features**: Replacing `sethc.exe` (Sticky Keys, triggered by 5x Shift), `utilman.exe` (Utility Manager, triggered by Win+U), `osk.exe` (On-Screen Keyboard), `narrator.exe`, or `magnify.exe` with cmd.exe. Provides pre-authentication command execution at the login screen.
- **Screensaver**: `HKCU\Control Panel\Desktop\SCRNSAVE.EXE` -- points to an executable run when the screensaver activates. `ScreenSaveActive` must be `1`.
- **Print monitors**: `HKLM\SYSTEM\CurrentControlSet\Control\Print\Monitors\<name>\Driver` -- DLL loaded by the spoolsv.exe service. Runs as SYSTEM.
- **Security Support Providers (SSP)**: `HKLM\SYSTEM\CurrentControlSet\Control\Lsa\Security Packages` -- DLL loaded by lsass.exe at boot. Can log plaintext credentials. Extreme privilege but high detection risk.
- **Netsh helper DLLs**: `netsh add helper C:\malicious.dll` -- registered DLL loaded whenever netsh.exe runs.

## macOS Persistence

- **LaunchAgents/LaunchDaemons**: ~/Library/LaunchAgents, /Library/LaunchDaemons
- **Login Items**: Added via osascript or direct plist manipulation
- **Startup Items**: /Library/StartupItems (legacy)
- **Authorization plugins**: /Library/Security/SecurityAgentPlugins
- **DYLD_INSERT_LIBRARIES**: Environment variable for dylib injection

## Detection Implications

- Registry persistence rules checking only Run/RunOnce miss 15+ alternative locations
- Scheduled task rules checking only schtasks.exe miss COM, WMI, PowerShell, XML methods
- Linux persistence rules checking only crontab miss systemd, shell rc, ld.so.preload, etc.
- Multi-location rules should check EventType or aggregate across registry paths
