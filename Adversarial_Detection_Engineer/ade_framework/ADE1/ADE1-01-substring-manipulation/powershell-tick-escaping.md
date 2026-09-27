---
id: ADE1-004
title: PowerShell Backtick Escaping
ade_category: ADE1
ade_subcategory: ADE1-01
mitre_attack:
  - T1027 (Obfuscated Files or Information)
  - T1059.001 (Command and Scripting Interpreter: PowerShell)
platform: Windows
testable: true
---

# PowerShell Backtick Escaping

## Summary

The backtick (`` ` ``) is PowerShell's escape character. When placed before a non-special character, it is simply stripped — `` `w `` becomes `w`. This allows obfuscation of cmdlet names and arguments. However, certain characters ARE special escape sequences (`` `a `` = BEL, `` `n `` = newline, `` `e `` = ESC), limiting where backticks can be inserted.

## ADE Classification

**Category:** ADE1 — Reformatting in Actions
**Subcategory:** ADE1-01 — Substring Manipulation
**Core principle:** The PowerShell parser strips backticks before non-special characters, resolving the obfuscated string to its original form. Script Block Logging (EID 4104) captures the script source BEFORE full deobfuscation, potentially preserving the backticks.

## The Technique

### Special escape sequences (backtick is NOT stripped)

| Sequence | Result | Character |
|----------|--------|-----------|
| `` `0 `` | Null | \0 |
| `` `a `` | Alert/BEL | \a |
| `` `b `` | Backspace | \b |
| `` `e `` | Escape (PS 6+) | \e |
| `` `f `` | Form feed | \f |
| `` `n `` | Newline | \n |
| `` `r `` | Carriage return | \r |
| `` `t `` | Tab | \t |
| `` `v `` | Vertical tab | \v |

### Non-special characters (backtick IS stripped)

Any letter NOT in the special set: c, d, g, h, i, j, k, l, m, o, p, q, s, w, x, y, z (and all uppercase).

### Practical limitation

For a word like `whoami`:
- `` `w `` → w (safe)
- `` `h `` → h (safe)
- `` `o `` → o (safe)
- `` `a `` → BEL (SPECIAL — breaks the command!)
- `` `m `` → m (safe)
- `` `i `` → i (safe)

You cannot blindly backtick-escape every character. The attacker must skip characters that produce special escapes.

For `Invoke-Expression`:
- `` `n `` → newline (breaks it!)
- `` `e `` → ESC (breaks it in PS 6+!)

This limits the technique's applicability. It works best on strings that don't contain a, b, e, f, n, r, t, v.

### Case sensitivity of escape sequences

Escape sequences are case-sensitive in PowerShell:
- `` `n `` = newline (lowercase)
- `` `N `` = just N (uppercase — NOT a special escape)

This means `` I`Nvoke-Expressio`N `` would resolve correctly (`` `N `` → N), but this changes the case of the command name. Since PowerShell is case-insensitive for cmdlet resolution, this still works.

## Bypass Demonstration

### Benign test payload

```powershell
# Inside a PowerShell session:
wh`oa`mi           # FAILS — `a is BEL
w`ho`ami            # WORKS — only safe chars ticked (but `a unticked is literal a)

# More practical: cmdlet obfuscation
I`Nv`oke-`Expressio`N 'whoami'  # Works — `N is not newline, only `n is
```

### What Sysmon sees

Sysmon EID 1 captures the command line with backticks PRESERVED in the parent process. The child process (if any is spawned) shows the resolved form.

Script Block Logging (EID 4104) captures the script block source which may or may not preserve backticks depending on the PowerShell version and how the script was invoked.

## Vulnerable Rule

```yaml
title: Invoke-Expression Usage
status: experimental
logsource:
    category: ps_script
    product: windows
detection:
    selection:
        ScriptBlockText|contains: 'Invoke-Expression'
    condition: selection
```

### Why it misses

`` I`Nv`oke-Expressio`N `` does not contain the literal substring `Invoke-Expression`.

## Hardened Rule

```yaml
title: Invoke-Expression Usage (Hardened)
status: experimental
logsource:
    category: ps_script
    product: windows
detection:
    selection:
        ScriptBlockText|re|i: 'i.?n.?v.?o.?k.?e.?-.?e.?x.?p.?r.?e.?s.?s.?i.?o.?n'
    condition: selection
```

### Why the hardened rule works

The regex `.?` between each character absorbs optional backtick characters (and any other single-character insertion). The `|i` flag makes it case-insensitive.

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Literal substring match | No | Backticks break exact match |
| Regex with `.?` tolerance | Yes | Absorbs inserted characters |
| Script Block Logging (4104) | Partial | May show backticks or resolved form depending on version |
| AMSI | Yes | Sees the resolved form after parsing |
| Image field | N/A | This is within PowerShell, not a process spawn |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #7: PowerShell parameter prefix parsing — backtick escaping compounds with parameter abbreviation
- The special escape character set is PowerShell-version-specific: `` `e `` (escape) was added in PowerShell 6.0
- In double-quoted strings, ALL backtick escapes are processed; in single-quoted strings, backtick is literal

## References

- [PowerShell Documentation - About Special Characters](https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/about/about_special_characters)
- [Daniel Bohannon - Invoke-Obfuscation](https://github.com/danielbohannon/Invoke-Obfuscation)
- [MITRE ATT&CK T1027 - Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
