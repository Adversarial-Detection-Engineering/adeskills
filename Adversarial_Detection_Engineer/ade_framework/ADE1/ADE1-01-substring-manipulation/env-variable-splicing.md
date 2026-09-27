---
id: ADE1-002
title: Environment Variable Splicing in cmd.exe
ade_category: ADE1
ade_subcategory: ADE1-01
mitre_attack:
  - T1027 (Obfuscated Files or Information)
  - T1059.003 (Command and Scripting Interpreter: Windows Command Shell)
platform: Windows
testable: true
---

# Environment Variable Splicing in cmd.exe

## Summary

cmd.exe supports substring extraction from environment variables using `%VAR:~offset,length%` syntax. An attacker can construct any command by extracting individual characters from well-known environment variables like `COMSPEC`, `PATHEXT`, or `WINDIR`. The constructed command executes identically, but the command line contains only `%VAR%` references.

## ADE Classification

**Category:** ADE1 — Reformatting in Actions
**Subcategory:** ADE1-01 — Substring Manipulation
**Core principle:** The command string is constructed at runtime from environment variable substrings. Static pattern matching on the parent command line sees `%COMSPEC:~n,m%` references, not the resolved command name.

## The Technique

cmd.exe's `%VAR:~offset,length%` syntax extracts substrings:
- `%COMSPEC%` = `C:\WINDOWS\system32\cmd.exe`
- `%COMSPEC:~0,1%` = `C` (first character)
- `%COMSPEC:~-3%` = `exe` (last 3 characters)

An attacker can also use `set` to create custom variables, then use `call` to resolve and execute them:

```cmd
set x=whoami&& call %x%
```

This is simpler and equally effective — the parent cmd.exe command line shows `set x=whoami&& call %x%`, not `whoami`.

### Reliable environment variables

| Variable | Typical Value | Available on |
|----------|---------------|-------------|
| `COMSPEC` | `C:\WINDOWS\system32\cmd.exe` | All Windows |
| `PATHEXT` | `.COM;.EXE;.BAT;.CMD;.VBS;.VBE;.JS;.JSE;.WSF;.WSH;.MSC` | All Windows |
| `WINDIR` | `C:\WINDOWS` | All Windows |
| `SYSTEMROOT` | `C:\WINDOWS` | All Windows |

## Bypass Demonstration

### Benign test payload

```cmd
REM Simple variable construction
cmd /c "set x=whoami&& call %x%"

REM Substring extraction (construct "cmd" from COMSPEC)
cmd /c "%COMSPEC:~-7,3%"
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Raw parent command line | `set x=whoami&& call %x%` |
| cmd.exe after variable resolution | `whoami` |
| Sysmon EID 1 — parent cmd.exe | `cmd /c "set x=whoami&& call %x%"` |
| Sysmon EID 1 — child whoami.exe | `whoami` (resolved) |

## Vulnerable Rule

```yaml
title: Recon Command Execution
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentCommandLine|contains:
            - 'whoami'
            - 'ipconfig'
            - 'net user'
    condition: selection
```

### Why it misses

The parent command line contains `set x=whoami&& call %x%` — the string `whoami` IS present in the `set` command, but more sophisticated variable construction (character-by-character from env vars) would eliminate it entirely.

## Hardened Rule

```yaml
title: Recon Command Execution (Hardened)
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith:
            - '\whoami.exe'
            - '\ipconfig.exe'
            - '\net.exe'
        - OriginalFileName:
            - 'whoami.exe'
            - 'ipconfig.exe'
            - 'net.exe'
    condition: selection
```

### Why the hardened rule works

Detects the CHILD process by identity (Image or OriginalFileName), completely bypassing whatever obfuscation the parent used to invoke it.

## Sysmon Evidence

### Child Process — Event ID 1 (whoami.exe)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\whoami.exe` | Resolved path |
| CommandLine | `whoami` | Fully resolved — no variable references |
| OriginalFileName | `whoami.exe` | PE header |

cmd.exe resolves all variables before calling CreateProcess, so the child always receives the clean command.

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Parent CommandLine substring | Partial | Simple `set x=whoami` is detectable; character-by-character extraction is not |
| Parent CommandLine regex for `%.*:~` | Yes | Catches the variable extraction syntax itself as suspicious |
| Child Image field | Yes | Process identity unaffected |
| Child OriginalFileName | Yes | PE header |
| Child CommandLine | Yes | Resolved by cmd.exe |
| Behavioral | Yes | Outcome unchanged |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #2: Sysmon CommandLine is raw for parent, resolved for child
- The `call` keyword is required for delayed variable resolution in single-line commands
- Delayed expansion (`!var!`) with `cmd /v:on` provides another avenue for runtime construction

## References

- [Daniel Bohannon - DOSfuscation](https://www.fireeye.com/blog/threat-research/2018/03/dosfuscation-exploring-obfuscation-and-detection-techniques.html)
- [MITRE ATT&CK T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
