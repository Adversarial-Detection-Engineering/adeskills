---
id: ADE1-001
title: Caret Insertion in cmd.exe
ade_category: ADE1
ade_subcategory: ADE1-01
mitre_attack:
  - T1027 (Obfuscated Files or Information)
  - T1059.003 (Command and Scripting Interpreter: Windows Command Shell)
platform: Windows
testable: true
---

# Caret Insertion in cmd.exe

## Summary

The cmd.exe parser treats `^` as an escape character and strips it during command-line parsing. `w^h^o^a^m^i` resolves to `whoami` at execution time. Rules matching literal substrings in the PARENT command line will break, but the CHILD process command line shows the deobfuscated form.

## ADE Classification

**Category:** ADE1 — Reformatting in Actions
**Subcategory:** ADE1-01 — Substring Manipulation
**Core principle:** The cmd.exe parser strips carets before spawning the child process. Sysmon captures the child's command line in deobfuscated form, but the parent cmd.exe's command line retains the carets.

## The Technique

In cmd.exe, `^` is the escape character. When it precedes a non-special character, it is simply stripped. This means any command can have carets inserted between every character and still execute identically.

This works with arguments too: `ipconfig /a^l^l` resolves to `ipconfig /all`.

Double carets `^^` produce a literal caret: `echo ^^` outputs `^`.

**Does NOT work in PowerShell.** PowerShell uses the backtick (`` ` ``) as its escape character, not the caret. Carets have no special meaning in PowerShell's parser.

## Bypass Demonstration

### Benign test payload

```cmd
cmd /c "w^h^o^a^m^i"
cmd /c "ipconfig /a^l^l"
cmd /c "n^e^t u^s^e^r"
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Raw parent cmd.exe command line | `cmd /c w^h^o^a^m^i` |
| cmd.exe parser output | `whoami` |
| Sysmon EID 1 — **parent** cmd.exe | `"C:\WINDOWS\system32\cmd.exe" /c w^h^o^a^m^i` |
| Sysmon EID 1 — **child** whoami.exe | `whoami` (deobfuscated) |

## Vulnerable Rule

```yaml
title: Suspicious Whoami Execution
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        ParentCommandLine|contains: 'whoami'
    condition: selection
```

### Why it misses

The parent cmd.exe command line contains `w^h^o^a^m^i`, not the literal string `whoami`. The `|contains` modifier performs a literal substring match and fails.

## Hardened Rule

```yaml
title: Suspicious Whoami Execution (Hardened)
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_child:
        - Image|endswith: '\whoami.exe'
        - OriginalFileName: 'whoami.exe'
    condition: selection_child
```

### Why the hardened rule works

Matching on the CHILD process's Image or OriginalFileName completely bypasses caret insertion because:
1. The child process command line is already deobfuscated by cmd.exe
2. The Image field contains the resolved path regardless of how the parent specified the command
3. OriginalFileName comes from the PE header and is never affected by command-line tricks

## Sysmon Evidence

### Parent Process — Event ID 1 (cmd.exe)

| Field | Value |
|-------|-------|
| Image | `C:\Windows\System32\cmd.exe` |
| CommandLine | `"C:\WINDOWS\system32\cmd.exe" /c w^h^o^a^m^i` |
| OriginalFileName | `Cmd.Exe` |

### Child Process — Event ID 1 (whoami.exe)

| Field | Value |
|-------|-------|
| Image | `C:\Windows\System32\whoami.exe` |
| CommandLine | `whoami` |
| OriginalFileName | `whoami.exe` |

The carets appear ONLY in the parent cmd.exe command line. The child process sees the clean command.

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Parent command-line substring | No | Carets break literal match on parent's CommandLine |
| Parent command-line regex (`w\^*h\^*o\^*a\^*m\^*i`) | Yes | Pattern accounts for optional carets |
| Child Image field | Yes | Process identity unaffected |
| Child OriginalFileName | Yes | PE header, not affected |
| Child CommandLine | Yes | cmd.exe deobfuscates before spawning child |
| Script Block Logging (4104) | N/A | Not a PowerShell technique |
| AMSI | N/A | Not a PowerShell technique |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #2: Sysmon CommandLine is raw for the parent but deobfuscated for the child — this is specific to cmd.exe's parsing behavior
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #11: OriginalFileName survives any command-line manipulation

## References

- [LOLBAS Project](https://lolbas-project.github.io/)
- [Atomic Red Team - T1027](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1027/T1027.md)
- [Daniel Bohannon - DOSfuscation](https://www.fireeye.com/blog/threat-research/2018/03/dosfuscation-exploring-obfuscation-and-detection-techniques.html)
