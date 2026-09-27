---
module_id: evasion_techniques_reference
module_name: "Detection Evasion Techniques Reference"
module_description: |
  Comprehensive catalog of attacker evasion techniques organized by objective 
  (credential access, execution, persistence, etc.) with cross-reference to ADE 
  categories and detection rule gaps.

evasion_by_objective:
  
  Credential_Access:
    description: "Stealing credentials from memory, files, network, or authentication protocols"
    techniques:
      
      LSASS_Memory_Access:
        description: "Extract plaintext passwords and hashes from LSASS.exe memory"
        ade_category: "ADE2-01 (Omit Alternatives)"
        methods:
          - "MiniDumpWriteDump API via rundll32 + comsvcs.dll"
          - "ProcDump (signed Sysinternals binary)"
          - "nanodump (direct syscalls, AMSI/EDR evasion)"
          - "HandleDuplicator (duplicates existing LSASS handle)"
          - "PPLdump (Protected Process Light bypass)"
          - "Kernel driver BYOVD (bring your own vulnerable driver)"
          - "Silent Process Exit abuse with Windows Error Reporting"
        detection_gap: |
          Rules monitoring only mimikatz.exe or specific API calls 
          (CreateRemoteThread, OpenProcess) miss alternatives that achieve 
          identical outcomes with different telemetry.
      
      SAM_Database_Extraction:
        description: "Extract local account hashes from SAM registry hive"
        ade_category: "ADE2-01 (Omit Alternatives)"
        methods:
          - "reg save HKLM\\SAM sam.hive (standard)"
          - "vssadmin create shadow (Shadow Copy approach)"
          - "esentutl.exe with VSS"
          - "PowerShell .NET file copy from VSS"
          - "secretsdump.py (remote SMB/RPC)"
        detection_gap: "Rules monitoring vssadmin only miss esentutl variant"
      
      NTDS_DIT_Extraction:
        description: "Extract domain account hashes from NTDS.dit (Active Directory database)"
        ade_category: "ADE2-01 (Omit Alternatives)"
        methods:
          - "ntdsutil.exe (standard)"
          - "vssadmin create shadow"
          - "diskshadow.exe (script-based, less monitored)"
          - "wmic shadowcopy (WMI-based)"
          - "secretsdump.py DCSync (remote, no file copy)"
          - "esentutl.exe with VSS"
        detection_gap: |
          Rules focusing on ntdsutil process creation miss diskshadow, wmic, 
          and remote secretsdump approaches that produce different telemetry.
      
      Kerberos_Attacks:
        description: "Exploit Kerberos protocol for credential theft"
        ade_category: "ADE2-01 (Omit Alternatives), ADE2-04 (Alternate Protocol)"
        methods:
          - "Kerberoasting (Rubeus, Impacket GetUserSPNs, Invoke-Kerberoast)"
          - "AS-REP Roasting (Rubeus, GetNPUsers.py)"
          - "Golden Ticket (mimikatz, Rubeus, ticketer.py)"
          - "Silver Ticket (forged service TGS)"
          - "Diamond Ticket (modified TGT PAC)"
          - "Overpass-the-Hash (Rubeus, sekurlsa::pth)"
        detection_gap: |
          Network-level detection (TGS-REQ for SPN accounts) is identical 
          regardless of tool used. Process-level rules must enumerate all tools.
      
      DCSync_Attack:
        description: "Impersonate DC to extract password replication"
        ade_category: "ADE2-01 (Omit Alternatives), ADE2-04 (Alternate Protocol)"
        methods:
          - "mimikatz lsadump::dcsync"
          - "secretsdump.py (Impacket)"
          - "DSInternals PowerShell module"
        detection_gap: |
          Network-level detection (DsGetNCChanges RPC from non-DC) is identical 
          regardless of tool. Process-level rules fail when tool changes.
      
      Credential_File_Access:
        description: "Extract credentials from stored files"
        ade_category: "ADE2-01 (Omit Alternatives)"
        methods:
          - "Browser password databases (Chrome, Firefox, Edge)"
          - "WiFi profiles (netsh wlan show profile)"
          - "Windows Vault / Credential Manager (vaultcmd, CredEnumerate API)"
          - "DPAPI secrets (masterkey dumping)"
          - "Group Policy Preferences (Groups.xml in SYSVOL)"
          - "SSH private keys (~/.ssh/id_rsa)"
          - "SSH authorized_keys for persistence"
        detection_gap: |
          Rules monitoring LSASS access miss file-based credential theft 
          that doesn't touch LSASS.
  
  Execution:
    description: "Execute arbitrary code on target system"
    ade_category: "ADE2-01 (Omit Alternatives)"
    
    LOLBins_Execution:
      description: "Legitimate OS binaries abused for code execution"
      ade_category: "ADE2-01"
      methods:
        - "mshta.exe (HTA files, VBScript/JScript inline)"
        - "rundll32.exe (DLL exports, JavaScript)"
        - "regsvr32.exe + scriptlet.sct (Squiblydoo attack)"
        - "wmic.exe process call create"
        - "cmstp.exe (INF files, AppLocker/UAC bypass)"
        - "msiexec.exe (remote MSI installation)"
        - "forfiles.exe (enumerate + execute)"
        - "pcalua.exe (Program Compatibility Assistant)"
        - "MSBuild.exe (inline C# tasks)"
        - "csc.exe (C# compiler)"
        - "InstallUtil.exe (.NET assembly uninstall)"
        - "RegAsm.exe (.NET assembly registration)"
        - "RegSvcs.exe (.NET Component Services)"
      detection_gap: |
        Rules monitoring only cmd.exe or powershell.exe miss dozen+ alternative 
        execution vectors through signed system binaries.
    
    Process_Injection:
      description: "Inject code into running process to avoid new process creation"
      ade_category: "ADE2-01"
      methods:
        - "VirtualAllocEx + WriteProcessMemory + CreateRemoteThread (classic)"
        - "QueueUserAPC (more subtle)"
        - "NtMapViewOfSection + ROP (process hollowing)"
        - "Thread hijacking (suspend, modify context, resume)"
        - "AtomBombing (global atom tables)"
        - "Early bird injection (APC into suspended process)"
        - "Module stomping (overwrite .text section)"
        - "Phantom DLL hollowing"
        - "Transacted hollowing (TxF rollback)"
        - "Fiber-based execution"
      detection_gap: |
        Rules monitoring only CreateRemoteThread miss alternative injection 
        methods that produce no thread creation event.
    
    Process_Proxy_Execution:
      description: "Execute through legitimate process parent"
      ade_category: "ADE2-01"
      methods:
        - "Task Scheduler API (parent: svchost.exe)"
        - "WMI Win32_Process.Create (parent: WmiPrvSE.exe)"
        - "CreateProcessAsUserW (different user token)"
        - "ShellExecute (parent: explorer.exe in some cases)"
        - "COM objects"
      detection_gap: |
        Expected parent-child relationships break, evading parent-based heuristics.
  
  Persistence:
    description: "Maintain access across reboots and logoffs"
    ade_category: "ADE2-01 (Omit Alternatives)"
    techniques:
      
      Registry_Persistence:
        description: "Registry-based persistence mechanisms"
        methods:
          - "HKLM\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Run"
          - "RunOnce (auto-deletes after execution)"
          - "RunOnceEx (extended version)"
          - "Policies\\Explorer\\Run"
          - "User Shell Folders (Startup directory)"
          - "Winlogon entries (Userinit, Shell, Notify)"
          - "AppInit_DLLs (loads into all processes)"
          - "Image File Execution Options (IFEO) Debugger entry"
          - "IFEO GlobalFlag + SilentProcessExit"
          - "Print monitors"
          - "Network share Shell"
        detection_gap: |
          Rules monitoring only Run key miss RunOnce, Winlogon, AppInit_DLLs, 
          IFEO, and other registry locations.
      
      Scheduled_Tasks_Persistence:
        description: "Scheduled task creation methods"
        ade_category: "ADE2-01"
        methods:
          - "schtasks.exe (command-line tool)"
          - "PowerShell Register-ScheduledTask"
          - "COM Task Scheduler interface"
          - "AT command (deprecated but functional)"
          - "Direct XML task file creation (bypasses process)"
        detection_gap: |
          Rules monitoring schtasks.exe miss PowerShell, COM, AT, and direct 
          XML file creation methods.
      
      Windows_Services:
        description: "Service-based persistence"
        ade_category: "ADE2-01"
        methods:
          - "sc.exe create (command-line)"
          - "PowerShell New-Service"
          - "WMI Win32_Service.Create"
          - "Direct registry manipulation of HKLM\\SYSTEM\\CurrentControlSet\\Services"
        detection_gap: |
          Rules monitoring sc.exe miss PowerShell, WMI, and direct registry 
          modification approaches.
      
      WMI_Event_Subscriptions:
        description: "Fileless persistence via WMI event triggers"
        ade_category: "ADE2-01"
        methods:
          - "__EventFilter + __EventConsumer + __FilterToConsumerBinding"
          - "CommandLineEventConsumer (executes command)"
          - "ActiveScriptEventConsumer (executes VBScript/JScript)"
          - "Triggers: process creation, timer events, user logon"
        detection_gap: |
          WMI subscriptions are fileless and require WMI-specific forensic tools. 
          Process-level detection misses these entirely.
      
      DLL_Hijacking:
        description: "Exploit DLL search order to load malicious DLLs"
        ade_category: "ADE2-01"
        methods:
          - "Plant DLL in application directory with known name"
          - "Phantom DLL loading (application seeks missing DLL)"
          - "Target applications: OneDrive, Teams, Visual Studio"
        detection_gap: |
          Rules monitoring process execution miss DLL-based persistence 
          that activates on application start.
      
      Startup_Folder:
        description: "Files in startup folder execute at logon"
        ade_category: "ADE2-01"
        methods:
          - "C:\\Users\\<user>\\AppData\\Roaming\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
          - "C:\\ProgramData\\Microsoft\\Windows\\Start Menu\\Programs\\Startup"
          - ".lnk shortcuts (can point to obfuscated commands)"
          - ".url, .scf files (alternate file types)"
          - ".bat, .vbs, .ps1 scripts"
        detection_gap: |
          Rules monitoring executable creation miss .lnk, .url, .scf, and script 
          file persistence.
      
      COM_Hijacking:
        description: "Hijack COM object CLSID registrations"
        ade_category: "ADE2-01"
        methods:
          - "HKCU\\SOFTWARE\\Classes\\CLSID\\{CLSID}\\InProcServer32"
          - "HKCU entries override HKLM (non-admin persistence)"
          - "TreatAs key for indirect hijacking"
        detection_gap: |
          Rules monitoring HKLM modifications miss HKCU CLSID hijacking 
          available to non-admin users.
      
      Linux_Persistence:
        description: "Linux persistence mechanisms"
        ade_category: "ADE2-01"
        methods:
          - "Cron jobs (/etc/crontab, /var/spool/cron, /etc/cron.d/)"
          - "systemd services (.service files)"
          - "Shell profile scripts (~/.bashrc, /etc/profile)"
          - "LD_PRELOAD (/etc/ld.so.preload)"
          - "init.d scripts (/etc/init.d/)"
          - "udev rules (/etc/udev/rules.d/)"
          - "SSH authorized_keys"
        detection_gap: "Cross-platform rules must enumerate all methods"
  
  Defense_Evasion:
    description: "Bypass or disable detection and logging mechanisms"
    ade_category: "ADE3 (Detection Bypass)"
    
    PowerShell_Evasion:
      description: "Bypass PowerShell security mechanisms"
      ade_category: "ADE3-01 (Configuration Bypass), ADE2-03 (Encoding)"
      methods:
        - "Execution Policy bypass (-ExecutionPolicy Bypass, -ep bypass)"
        - "PowerShell v2 downgrade (CLM bypass)"
        - "AMSI bypass (patch AmsiScanBuffer or set amsiInitFailed)"
        - "CLM (Constrained Language Mode) bypass"
        - "Script Block logging bypass (AMSI pre-logging)"
        - "ScriptBlock obfuscation (backticks, concatenation, character codes)"
        - "Alternate execution hosts (pwsh.exe, .NET hosting)"
      detection_gap: |
        Rules monitoring PowerShell must account for encoding, obfuscation, 
        v2 downgrade, AMSI bypass, and alternate hosts.
    
    Event_Log_Evasion:
      description: "Disable, clear, or bypass event logging"
      ade_category: "ADE3-02 (Logging Disable)"
      methods:
        - "Disable Windows Event Forwarding (Registry + Service disable)"
        - "Clear event logs (wevtutil cl Application/Security/System)"
        - "Disable auditing (auditpol /clear)"
        - "Sysmon rules disable (sysmon -c - < /dev/null)"
        - "Log tampering (direct registry modification of event log entries)"
        - "Disable Windows Defender logging"
      detection_gap: |
        Rules relying on event logs miss attacks that disable logging after 
        gaining admin access.
    
    EDR_Evasion:
      description: "Disable or bypass EDR protections"
      ade_category: "ADE3-02 (Logging Disable), ADE3-01 (Configuration Bypass)"
      methods:
        - "Unhook ntdll.dll (restore clean copy)"
        - "Direct syscalls (SysWhispers, HellsGate)"
        - "Kernel driver loading (BYOVD)"
        - "Disable EDR via WMI (Disable-NetFirewallRule, Stop-Service for EDR)"
        - "Terminate EDR processes"
        - "Spoof EDR detection (fake process tree, module hiding)"
      detection_gap: |
        Unhooking and direct syscalls bypass EDR API interception. 
        Kernel-mode access bypasses all usermode monitoring.
    
    Code_Signing_Evasion:
      description: "Use signed binaries to appear legitimate"
      ade_category: "ADE2-01 (Omit Alternatives)"
      methods:
        - "Living Off The Land binaries (LOLBins)"
        - "Signed third-party tools (ProcDump, AutoIt, VLC, 7-Zip)"
        - "Stolen or leaked signing certificates"
        - "Signing malware with certificate authority-issued cert"
      detection_gap: |
        Signature-based whitelist bypassed by signed binaries. 
        Behavioral analysis required.
  
  Lateral_Movement:
    description: "Move from one system to another within network"
    ade_category: "ADE2-01 (Omit Alternatives), ADE2-04 (Alternate Protocol)"
    
    Windows_Authentication_Abuse:
      description: "Exploit Windows authentication for lateral movement"
      ade_category: "ADE2-01, ADE2-04"
      methods:
        - "Pass-the-Hash (NTLM relay, overpass-the-hash)"
        - "Pass-the-Ticket (Kerberos TGT/TGS abuse)"
        - "DCOM lateral movement (WMI via DCOM/RPC)"
        - "WinRM lateral movement (Invoke-Command over WinRM)"
        - "PsExec / SMB-based execution"
        - "SSH lateral movement (Linux/UNIX)"
      detection_gap: |
        Each method produces different network protocols (DCOM vs WinRM vs SSH). 
        Rules must monitor all.
    
    NTLM_Relay:
      description: "Relay captured or coerced NTLM authentication"
      ade_category: "ADE2-04 (Alternate Protocol)"
      methods:
        - "Responder (LLMNR/NBT-NS poisoning)"
        - "Inveigh (PowerShell responder)"
        - "mitm6 (IPv6 DNS takeover)"
        - "ntlmrelayx.py (relay to LDAP/SMB/HTTP)"
        - "PetitPotam (coerce machine authentication)"
        - "PrinterBug / SpoolSample (RPC coercion)"
      detection_gap: |
        Relay doesn't require password cracking. Network-level detection 
        of coercion and relay is critical.
    
    Kerberos_Delegation:
      description: "Exploit Kerberos delegation for lateral movement"
      ade_category: "ADE2-01, ADE2-04"
      methods:
        - "Unconstrained delegation (TGT forwarding)"
        - "Constrained delegation (limited to specific services)"
        - "Resource-based constrained delegation (RBCD)"
      detection_gap: |
        Delegation-based attacks are subtle and require deep Kerberos 
        protocol knowledge to detect.
  
  Data_Exfiltration:
    description: "Extract sensitive data from target"
    ade_category: "ADE2-04 (Alternate Protocol/Channel)"
    
    Alternative_Channels:
      description: "Use alternate protocols for data exfiltration"
      ade_category: "ADE2-04"
      methods:
        - "DNS tunneling (dnscat2, iodine, dns2tcp)"
        - "ICMP tunneling (encapsulate data in ICMP)"
        - "SMTP exfiltration (send as email)"
        - "WebSocket upgrade (persistent encrypted channel)"
        - "SSH tunneling (-L, -R, -D flags)"
        - "Cloud storage abuse (S3, Azure Blob, Google Cloud)"
        - "Legitimate service APIs (Slack, Discord, Telegram)"
      detection_gap: |
        Rules monitoring HTTP/HTTPS miss DNS, ICMP, and cloud service 
        exfiltration channels.
    
    Protocol_Abuse:
      description: "Abuse legitimate protocols for exfiltration"
      ade_category: "ADE2-04"
      methods:
        - "DNS over HTTPS (DoH to trusted resolvers)"
        - "HTTP/HTTPS to legitimate cloud services"
        - "SMTP to legitimate mail servers"
        - "NTP or other auxiliary protocol abuse"
      detection_gap: |
        Traffic to trusted domains (googleapis.com, azurewebsites.net) bypasses 
        domain-based filtering.

evasion_by_ade_category:
  
  ADE1_Encoding_Techniques:
    category: "String/Data Encoding and Obfuscation"
    techniques:
      - "Base64 encoding (PowerShell -EncodedCommand)"
      - "Hex/Unicode escaping (bash $'\\xHH', Windows hex escaping)"
      - "Character code arrays ([char] casting)"
      - "String concatenation and substitution"
      - "Case variation (Windows paths case-insensitive)"
      - "Comment insertion in various languages"
    references:
      - "cmdline_obfuscation.md"
      - "powershell_evasion.md"
  
  ADE2_01_Omit_Alternatives:
    category: "Method/Binary/Tool Alternatives"
    techniques:
      - "Multiple tools for same objective (mimikatz vs pypykatz vs Rubeus)"
      - "Multiple APIs for same operation (CreateProcess variants)"
      - "Multiple LOLBins for execution (mshta, rundll32, regsvr32, cmstp, etc.)"
      - "Multiple persistence mechanisms (Run keys, WMI, tasks, services)"
      - "Multiple file download tools (certutil, bitsadmin, curl, esentutl)"
    references:
      - "lolbins.md"
      - "credential_access_alternatives.md"
      - "persistence_alternatives.md"
      - "windows_api_wmi.md"
  
  ADE2_03_Alternate_Data_Source:
    category: "Encoding/Obfuscation/Alternative Format"
    techniques:
      - "Command-line obfuscation (caret, comma, semicolon, variables)"
      - "PowerShell string obfuscation (backticks, concatenation, format operator)"
      - "Base64/hex encoding of commands"
      - "Path obfuscation (8.3 short names, UNC, variables)"
      - "Unicode homoglyphs and encoding tricks"
    references:
      - "cmdline_obfuscation.md"
      - "powershell_evasion.md"
  
  ADE2_04_Alternate_Protocol_Channel:
    category: "Different Protocol or Communication Channel"
    techniques:
      - "DNS tunneling instead of HTTP"
      - "ICMP instead of TCP/UDP"
      - "WinRM instead of DCOM"
      - "HTTPS with cloud providers instead of direct C2"
      - "Legitimate service APIs (Slack, Discord)"
    references:
      - "network_download_evasion.md"
  
  ADE3_01_Configuration_Bypass:
    category: "Security Configuration Bypass"
    techniques:
      - "Execution Policy bypass"
      - "UAC bypass (UACME, COM elevation)"
      - "Constrained Language Mode bypass"
      - "AppLocker/WDAC bypass (via LOLBins)"
    references:
      - "powershell_evasion.md"
  
  ADE3_02_Logging_Disable:
    category: "Logging and Detection Disable"
    techniques:
      - "Event log clearing"
      - "AMSI bypass (patch or set flag)"
      - "Windows Defender disable"
      - "EDR sensor disable"
      - "Sysmon rule disable"
  
  ADE4_Field_Semantics:
    category: "Detection Rule Field Mapping Issues"
    techniques:
      - "Case-sensitive field name mismatches"
      - "Fields unavailable in certain log sources"
      - "Field semantic differences across backends"
      - "Filter logic inversions with absent fields"
    references:
      - "sigma_field_semantics.md"
