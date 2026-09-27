# PowerShell Evasion Techniques

## String Obfuscation

PowerShell's dynamic string handling enables numerous obfuscation methods that break static pattern matching:

- **Concatenation**: `'Down'+'loadStr'+'ing'` evaluates to `DownloadString` at runtime. Rules matching the full string `DownloadString` miss this. Detection requires `|contains` on substrings or `|all` modifier with fragments.
- **Tick insertion**: PowerShell backtick is an escape character ignored in most positions. `Inv`oke-Ex`pression` is functionally identical to `Invoke-Expression`. Rules must account for backticks between any characters.
- **Variable substitution**: `$a='Invoke';$b='Expression';& "$a-$b"` constructs the cmdlet name dynamically. No static string contains the target.
- **Format operator (-f)**: `'{0}{1}' -f 'Invoke-','Expression'` builds strings from indexed placeholders.
- **[char] casting**: `[char]73+[char]69+[char]88` builds strings from ASCII codes. Completely invisible to string matching.
- **Replace operations**: `'Invoke-Expr****ion' -replace '\*{4}','ess'` reconstructs strings via replacement.
- **Reverse strings**: `'noisserp'.[-1..-100] -join ''` reverses to 'expression'. Combined with iex.
- **Caret insertion** (cmd passthrough): `p^o^w^e^r^s^h^e^l^l`
- **Environment variable splicing**: `%comspec:~0,1%%comspec:~4,1%d` → "cmd"
- **Format string**: `("{2}{0}{1}" -f 'ke-','Expression','Invo')`
- **String replace**: `'Invoke-Exzzzzion'.Replace('zzzz','press')`
- **Char array + join**: `[char[]](73,110,118) -join ''` → "Inv"

## Encoding and Alternate Representations

- **-EncodedCommand (-enc/-e/-ec)**: Base64-encoded UTF-16LE command
- **-WindowStyle Hidden (-w h)**: Parameter shortening — `-w h` equals `-WindowStyle Hidden`
- **Hex encoding**: `[char]0x49` = 'I'
- **Unicode escaping**: `` `u{0049} `` = 'I' (PowerShell 7+)

## AMSI Bypass Techniques

The Antimalware Scan Interface (AMSI) inspects PowerShell script content before execution. Bypass methods:

- **amsi.dll patching**: Overwriting the `AmsiScanBuffer` function in memory with bytes that force it to return `AMSI_RESULT_CLEAN`. Uses `VirtualProtect` to change memory permissions, then writes `0xB8, 0x57, 0x00, 0x07, 0x80, 0xC3` (mov eax, 0x80070057; ret). Detectable via ScriptBlock logging if not itself obfuscated.
- **Reflection-based bypass**: `[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)` sets `amsiInitFailed` to true, disabling all subsequent AMSI scans. Modern signatures detect the string `amsiInitFailed` but this can be obfuscated.
- **COM object hijacking**: Registering a fake AMSI COM provider that returns clean results for all scans.
- **PowerShell runspace manipulation**: Creating new runspaces with AMSI disabled.
- **CLR hooking**: Using .NET reflection to hook the AMSI methods at the CLR level.
amsiContext in memory
- **CLM bypass**: Constrained Language Mode bypass via custom runspace
- Most AMSI bypasses avoid the exact strings that AMSI itself scans for

## Alternate Execution Hosts

Detection rules focusing solely on `powershell.exe` miss alternate hosts:

- **pwsh.exe**: PowerShell 7+ (Core) uses a different binary. Rules must cover both.
- **System.Management.Automation.dll**: Any .NET application can host the PowerShell engine by loading this DLL. Custom C# executables, `msbuild.exe` inline tasks, or `installutil.exe` can execute PowerShell without spawning powershell.exe.
- **PowerShell remoting**: `Enter-PSSession` and `Invoke-Command` execute on remote hosts. The process tree shows `wsmprovhost.exe` as the parent, not powershell.exe.
- **Exchange Management Shell**, **SCCM**, and other management tools embed PowerShell engines with their own host processes.
- `powershell.exe` (v5.1), `pwsh.exe` (v7+)
- `powershell_ise.exe` — ISE host, often overlooked
- **System.Management.Automation.dll** loaded in ANY .NET host (C#, IronPython)
- **PowerShell runspace from C#**: No powershell.exe process spawned
- **WMI/CIM**: `Invoke-WmiMethod Win32_Process Create` — parent is WmiPrvSE
- **Scheduled tasks**: Parent is svchost.exe, not powershell.exe

## Encoded Commands

- **-EncodedCommand** (-enc, -e, -ec): Accepts Base64-encoded UTF-16LE command strings. Rules should match partial flag names due to PowerShell's parameter abbreviation: `-enc`, `-enco`, `-encoded`, `-EncodedCommand` all work.
- **Double encoding**: Base64-encoding the encoded command parameter itself or nesting Invoke-Expression with multiple encoding layers.
- **Compression + encoding**: `[IO.Compression.DeflateStream]` combined with Base64 produces commands invisible to Base64 signature scanning.

## Execution Policy Bypass

Execution policy is not a security boundary but rules may rely on it. Bypass methods:

- `-ExecutionPolicy Bypass` or `-ep bypass` flag
- `Set-ExecutionPolicy Unrestricted -Scope Process`
- Piping to powershell: `echo "malicious" | powershell -`
- Using `Invoke-Expression` with downloaded content (no file touches disk)
- `powershell -nop -c "IEX(content)"` -- no profile, no policy check on string input
- Registry modification of `HKLM\SOFTWARE\Microsoft\PowerShell\1\ShellIds\Microsoft.PowerShell\ExecutionPolicy`

## Constrained Language Mode (CLM) Bypass

CLM restricts PowerShell to safe operations. Bypasses:

- **PowerShell v2 downgrade**: `powershell -version 2` uses the v2 engine which has no CLM support. Requires .NET Framework 2.0 installed (commonly present on older systems).
- **Custom runspace creation**: Building a .NET application that creates an unrestricted PowerShell runspace.
- **AppLocker/WDAC policy weaknesses**: If the Device Guard policy has gaps, CLM can be escaped.
- **P/Invoke via Add-Type**: In some configurations, `Add-Type` with inline C# can bypass CLM restrictions.

## Parameter Aliases and Shortening

PowerShell uniquely resolves partial parameter names:

- `-ExecutionPolicy` → `-ep`, `-exec`, `-executionp`
- `-EncodedCommand` → `-enc`, `-e`, `-ec`
- `-NoProfile` → `-nop`, `-noprof`
- `-WindowStyle Hidden` → `-w h`, `-wi h`

## Logging Gaps

Different PowerShell logging mechanisms have distinct blind spots:

- **ScriptBlock Logging (EID 4104)**: Captures deobfuscated script content. Bypassed by AMSI bypass (pre-logging), or by using .NET methods directly that don't flow through the script block pipeline.
- **Module Logging (EID 4103)**: Captures pipeline execution details. Verbose but can be selectively disabled per-module.
- **Transcript Logging**: File-based output. Bypassed by non-interactive sessions, or by deleting/redirecting transcript files. Does not capture .NET method calls.
- **Process command line (EID 4688/Sysmon 1)**: Only captures the initial command line. Staged payloads that download and execute in-memory produce minimal initial command line artifacts.
- Rules relying solely on one logging type have inherent blind spots from these gaps.

## Detection Implications

- Rules matching on `CommandLine|contains: 'Invoke-Expression'` miss all obfuscation
- Rules matching on `Image|endswith: 'powershell.exe'` miss pwsh.exe, ISE, and .NET hosts
- Rules matching exact parameter names miss shortened forms
- The `|re` modifier with patterns like `(?i)inv.*exp` is more resilient but still bypassable