# Credential Access Alternatives

Credential theft is a primary attacker objective for lateral movement and privilege escalation. Each credential access technique has multiple tool implementations and API-level alternatives. Detection rules targeting a single tool (e.g., mimikatz.exe) while ignoring alternatives represent a textbook ADE2-01 (Omit Alternatives - Method/Binary) logic bug.

## LSASS Memory Access

The Local Security Authority Subsystem Service (lsass.exe) holds plaintext passwords, NTLM hashes, and Kerberos tickets in memory. Extraction methods:

- **MiniDumpWriteDump API**: Called via `comsvcs.dll` -- `rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <lsass_pid> C:\temp\lsass.dmp full`. The rundll32 + comsvcs.dll pattern is detectable but distinct from mimikatz process detection.
- **ProcDump (Sysinternals)**: `procdump -ma lsass.exe lsass.dmp`. Signed Microsoft binary. Rules monitoring only unsigned binaries miss this.
- **mimikatz**: `sekurlsa::logonpasswords`. The canonical tool. Detected by process name, hash, YARA signatures, and behavioral patterns (opening lsass.exe handle with PROCESS_VM_READ).
- **nanodump**: Minimalist LSASS dumper using direct syscalls and unhooking. Avoids API hooking detection. Can dump to memory without touching disk.
- **HandleDuplicator / handledup**: Duplicates an existing handle to lsass.exe from another process (e.g., antimalware service) rather than opening a new one. Evades handle-open monitoring.
- **PPLdump / PPLFault**: Bypasses Protected Process Light (PPL) on lsass.exe to extract credentials from protected LSASS instances.
- **Silent Process Exit abuse**: Configuring IFEO `SilentProcessExit` for lsass.exe to trigger a dump via Windows Error Reporting.
- **Direct memory read via kernel driver**: Loading a vulnerable signed driver (BYOVD) to read lsass memory from kernel mode, bypassing all usermode protections.
- **Linux equivalent**: `/proc/<pid>/maps` and `/proc/<pid>/mem` for reading process memory. `gdb -p <pid>` for attaching to processes.
- **handledup from another process**: Duplicate LSASS handle, dump from 2nd process
- **WerFault.exe**: Windows Error Reporting can be abused to dump
- **Silent Process Exit**: Register monitor for lsass, dumps on exit
- **comsvcs.dll**: `rundll32 comsvcs.dll MiniDump PID file full`
- **Task Manager**: Right-click > Create dump file
- **MiniDumpWriteDump API**: Called from any custom tool

## LSASS Access Patterns (Sysmon EventID 10)

- **0x1010**: PROCESS_QUERY_LIMITED_INFORMATION | PROCESS_VM_READ — common dump access
- **0x1FFFFF**: PROCESS_ALL_ACCESS — aggressive, often detected
- **0x1410**: Another common combination for memory read
- Direct syscalls bypass user-mode hooking — CallTrace won't show ntdll transitions


## SAM Database Extraction

The Security Account Manager (SAM) stores local account password hashes:

- **reg save**: `reg save HKLM\SAM sam.hive` and `reg save HKLM\SYSTEM system.hive`. Requires admin. Command-line visible in process creation logs. Also need SYSTEM hive for the decryption boot key.
- **Volume Shadow Copy**: `vssadmin create shadow /for=C:` then copy SAM from the shadow copy path. Bypasses file locks. Shadow copy creation is a detectable event.
- **esentutl.exe**: `esentutl /y /vss C:\Windows\System32\config\SAM /d sam.hive`. Uses VSS internally. Different command-line pattern than vssadmin.
- **secretsdump.py (Impacket)**: Remote SAM extraction via SMB/RPC. No local process creation on the target -- only network telemetry.
- **PowerShell copy with VSS**: `[System.IO.File]::Copy("\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\Windows\System32\config\SAM", "C:\temp\sam")`.
- **Volume Shadow Copy**: `vssadmin create shadow` then copy from shadow
- **esentutl.exe /y /vss**: Copies locked files via VSS
- **diskshadow.exe**: Scriptable shadow copy creation
- **NTDS.dit extraction**: `ntdsutil "activate instance ntds" "ifm" "create full c:\temp"`

## Token and Credential Manipulation

- **DuplicateTokenEx**: Steal and impersonate token
- **CreateProcessWithToken/LogonUser**: Start process as another user
- **Overpass-the-Hash**: Convert NTLM hash to Kerberos TGT
- **Pass-the-Ticket**: Use stolen Kerberos tickets
- **Kerberoasting**: Request TGS for SPN, crack offline
- **AS-REP Roasting**: Request AS-REP without pre-auth, crack offline
- **DCSync**: Replicate domain credentials (DRSGetNCChanges)

## NTDS.dit Extraction

Active Directory database containing all domain account hashes:

- **ntdsutil.exe**: `ntdsutil "ac i ntds" "ifm" "create full C:\temp" q q`. Creates an Install From Media backup containing NTDS.dit. Process creation shows ntdsutil.exe with IFM arguments.
- **vssadmin**: `vssadmin create shadow /for=C:` then copy `Windows\NTDS\ntds.dit` from shadow. Same shadow copy technique as SAM extraction.
- **diskshadow.exe**: `diskshadow /s script.txt` -- script-based shadow copy creation. Less commonly monitored than vssadmin. Can execute interactively or from script files.
- **wmic shadowcopy**: `wmic shadowcopy call create Volume='C:\'`. WMI-based shadow copy creation -- different command-line pattern.
- **secretsdump.py (remote)**: DCSync-based extraction over the network. No NTDS.dit file copy needed.
- **esentutl.exe**: Can copy NTDS.dit via VSS similar to SAM extraction.
- **PowerSploit Copy-VSS**: PowerShell-based VSS copy of NTDS.dit.

## Kerberos Attacks

Exploiting Kerberos authentication for credential extraction:

- **Kerberoasting**: Requesting TGS tickets for service accounts, then cracking them offline. Tools: `Rubeus kerberoast`, Impacket `GetUserSPNs.py`, `Invoke-Kerberoast` (PowerSploit). Network telemetry: TGS-REQ for SPN accounts with RC4 encryption (etype 23). Each tool produces different host artifacts but identical network patterns.
- **AS-REP Roasting**: Requesting AS-REP for accounts without Kerberos pre-authentication. Tools: `Rubeus asreproast`, `GetNPUsers.py`. Targets accounts with `DONT_REQUIRE_PREAUTH` flag.
- **Golden Ticket**: Forged TGT using the krbtgt NTLM hash. `mimikatz kerberos::golden`, `Rubeus golden`, `ticketer.py`. Grants domain-wide access. Detection: TGT without corresponding AS-REQ.
- **Silver Ticket**: Forged TGS using a service account NTLM hash. Access to specific service only. Detection: TGS without corresponding TGS-REQ.
- **Diamond Ticket**: Modifying a legitimate TGT's PAC to add elevated group memberships. Harder to detect than golden ticket because the TGT has a legitimate encrypted portion.
- **Overpass-the-Hash**: Using NTLM hash to request a Kerberos TGT. `Rubeus asktgt /rc4:<hash>`, `sekurlsa::pth`. Converts local credential to Kerberos authentication.

## Token Manipulation

- **Token impersonation**: `ImpersonateLoggedOnUser` API with a duplicated token. Tools: `incognito`, `Rubeus`, Meterpreter `steal_token`. Requires SeImpersonatePrivilege.
- **Token duplication**: `DuplicateTokenEx` to create a new token from an existing one with modified privileges.
- **Parent PID spoofing**: `CreateProcess` with `PROC_THREAD_ATTRIBUTE_PARENT_PROCESS` set to another process. Inherits the parent's token. Breaks process tree heuristics and may inherit different access tokens.
- **Potato family**: Exploiting SeImpersonatePrivilege for SYSTEM token. JuicyPotato, PrintSpoofer, RoguePotato, GodPotato, SweetPotato. Each uses different COM/RPC abuse technique to coerce SYSTEM authentication.

## Credential File Access

Stored credentials outside of LSASS and SAM:

- **Browser password stores**: Chrome (`Login Data` SQLite database), Firefox (`logins.json` + `key4.db`), Edge (Chromium-based, same as Chrome). Tools: `SharpChromium`, `HackBrowserData`, `LaZagne`.
- **WiFi profiles**: `netsh wlan show profiles` then `netsh wlan show profile name="SSID" key=clear`. Plaintext WiFi passwords.
- **Windows Vault / Credential Manager**: `vaultcmd /list`, `cmdkey /list`. API: `CredEnumerate`. Tools: `mimikatz vault::cred`.
- **DPAPI secrets**: Master keys in `%APPDATA%\Microsoft\Protect\`. `mimikatz dpapi::masterkey` + `dpapi::cred`. Protects browser passwords, RDP saved credentials, and more.
- **Group Policy Preferences (GPP)**: `Groups.xml` in SYSVOL containing cPassword (AES-256 encrypted with publicly known key). `Get-GPPPassword` (PowerSploit).
- **SSH private keys**: `~/.ssh/id_rsa`, `id_ed25519`. Often unprotected by passphrase.

## DCSync Attack

Impersonates a domain controller to request password replication:

- **mimikatz**: `lsadump::dcsync /domain:corp.local /user:Administrator`. Uses MS-DRSR (Directory Replication Service Remote Protocol).
- **secretsdump.py (Impacket)**: `secretsdump.py corp.local/admin:password@dc.corp.local`. Same DRSR protocol, different tool.
- **DSInternals PowerShell module**: `Get-ADReplAccount -SamAccountName Administrator -Server dc.corp.local`. PowerShell-native, different artifact profile.
- **Network detection**: DCSync produces DsGetNCChanges RPC calls from a non-DC source IP. This is the most reliable detection point regardless of which tool is used.

## Network Credential Sniffing

Capturing credentials from network traffic:

- **Responder**: LLMNR/NBT-NS/MDNS poisoner. Captures NTLMv1/v2 hashes from poisoned name resolution. Also runs rogue SMB, HTTP, LDAP, SQL servers to capture authentication.
- **Inveigh**: PowerShell/.NET equivalent of Responder. `Invoke-Inveigh`. Runs entirely in memory. Different artifact profile (PowerShell vs Python process).
- **MITM6**: IPv6 DNS takeover combined with NTLM relay. `mitm6 -d corp.local` poisons DHCPv6 responses.
- **ntlmrelayx.py**: NTLM relay from one service to another. Captured authentication is relayed rather than cracked. Can relay to LDAP, SMB, HTTP, MSSQL.
- **PetitPotam**: Coerces Windows hosts to authenticate to an attacker via MS-EFSRPC. Combined with relay for full domain compromise.
- **Coercion tools**: PrinterBug/SpoolSample, DFSCoerce, ShadowCoerce -- each exploits a different Windows RPC service to coerce machine authentication.

Each technique in this module has multiple tool implementations. Detection rules must account for the underlying behavior (e.g., LSASS handle access, DCSync RPC calls, shadow copy creation events) rather than specific tool names or command-line patterns to avoid ADE2-01 gaps.

## Detection Implications

- Rules checking SourceImage for procdump miss comsvcs.dll, custom tools, syscall-based
- Rules checking GrantedAccess miss direct syscall variants that bypass hooks
- SAM dump rules checking for `reg save` miss VSS, esentutl, diskshadow
- DCSync rules should check for specific RPC calls, not just replication events