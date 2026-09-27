---
id: ADE1-005
title: Boolean Replacement
ade_category: ADE1
ade_subcategory: ADE1-01
mitre_attack:
  - T1059.001 (Command and Scripting Interpreter: PowerShell)
  - T1485 (Data Destruction)
platform: Windows
testable: true
---

# Boolean Replacement

## Summary

PowerShell and other scripting runtimes accept many syntactic forms for the same boolean value: `$true`, `1`, `[bool]1`, `[bool]::Parse('true')`, `(1 -eq 1)`, and a bare switch parameter. A detection rule matching `-Force:$true` covers one spelling out of at least six. The other five sail past.

## ADE Classification

**Category:** ADE1 -- Reformatting in Actions
**Core principle:** Same semantic value (`true`), expressed in many different byte sequences. The PowerShell runtime resolves them all identically, but a static rule sees only the literal it was trained on.

## The Technique

PowerShell is permissive about boolean syntax:

| Form | Example | Evaluates to |
|------|---------|-------------|
| Canonical | `-Force:$true` | `$true` |
| Numeric | `-Force:1` | `$true` |
| Bare switch | `-Force` | `$true` (implicit) |
| Explicit cast | `-Force:([bool]1)` | `$true` |
| Method call | `-Force:([bool]::Parse('true'))` | `$true` |
| Expression | `-Force:(1 -eq 1)` | `$true` |

Rules matching the boolean value portion (`:$true`, `:1`) miss other forms. The attacker swaps the value syntax; the runtime produces identical behavior.

The same principle applies outside PowerShell. WMIC accepts both `passwordexpires=false` and `passwordexpires=0` -- same effect, different bytes.

## Bypass Demonstration

### Benign test payload

```powershell
# All of these execute Remove-Item with the force flag:
Remove-Item -Path 'C:\sensitive' -Recurse -Force:$true
Remove-Item -Path 'C:\sensitive' -Recurse -Force:1
Remove-Item -Path 'C:\sensitive' -Recurse -Force
Remove-Item -Path 'C:\sensitive' -Recurse -Force:([bool]1)
Remove-Item -Path 'C:\sensitive' -Recurse -Force:([bool]::Parse('true'))
Remove-Item -Path 'C:\sensitive' -Recurse -Force:(1 -eq 1)
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Raw command line / script | `-Force:1` or `-Force` (varies) |
| PowerShell engine | Resolves all forms to boolean `$true` |
| Sysmon EID 1 CommandLine | N/A (ps_script, not process_creation) |
| Script Block Logging (4104) | Full script text including the boolean form used |
| AMSI | Deobfuscated content |

## Vulnerable Rule

```yaml
title: Forced Recursive Removal (Naive)
id: 44444444-4444-4444-4444-000000000001
status: experimental
description: Detects PowerShell deleting items recursively with force
logsource:
  product: windows
  category: ps_script
detection:
  selection:
    ScriptBlockText|contains:
      - '-Recurse -Force:$true'
      - '-Force:$true -Recurse'
  condition: selection
level: medium
```

### Why it misses

The rule enumerates two literal orderings of `-Recurse -Force:$true`. It misses:

- `-Force` (bare switch, without explicit value)
- `-Force:1`, `-Force:([bool]1)`, `-Force:(1 -eq 1)`, etc.
- Splatting: `Remove-Item @params` where `$params = @{Recurse=$true; Force=$true}`
- Aliases of `Remove-Item`: `del`, `erase`, `rd`, `rm`, `ri`
- All orderings the rule did not enumerate

## Hardened Rule

```yaml
title: Forced Recursive Removal (Hardened)
id: 44444444-4444-4444-4444-000000000002
status: stable
description: Detects PowerShell forced-recursive removal regardless of boolean syntax
logsource:
  product: windows
  category: ps_script
detection:
  selection_cmd:
    ScriptBlockText|re|i: '\b(Remove-Item|del|erase|rd|rm|ri)\b'
  selection_force:
    ScriptBlockText|re|i: '-Force\b'
  selection_recurse:
    ScriptBlockText|re|i: '-Recurse\b'
  condition: selection_cmd and selection_force and selection_recurse
falsepositives:
  - Cleanup scripts (consider scoping by user, path, or parent process)
level: high
```

The fix: detect on the **parameter name** (which is a small, stable set), not the value. Boolean values are infinitely variable; parameter names are not. The rule matches `-Force` regardless of what follows the `\b` word boundary -- `:$true`, `:1`, bare, or any expression.

A stronger complement: detect the **resulting behavior** via Sysmon FileDelete (EID 23) events on watched paths, aggregated as "process X deleted N files in directory Y in T seconds." This fires regardless of how the deletion was invoked.

## Sysmon Evidence

### Key Fields

| Field | Value | Note |
|-------|-------|------|
| ScriptBlockText | `Remove-Item -Path 'C:\sensitive' -Recurse -Force:1` | Raw script text with boolean variant preserved |
| EventID | 4104 | Script Block Logging |
| ScriptBlockId | GUID | Correlates multi-block scripts |
| Path | Script file path or `<No file>` for interactive | Origin context |

For the behavioral complement (FileDelete):

| Field | Value | Note |
|-------|-------|------|
| EventID | 23 | Sysmon FileDelete |
| Image | `C:\...\powershell.exe` | Process performing deletion |
| TargetFilename | Deleted file path | Aggregate count for threshold |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Command-line substring | No | Only matches one boolean spelling |
| Regex on parameter name | Yes | Ignores the value; matches `-Force` itself |
| Image field | N/A | This is a script-content detection |
| OriginalFileName | N/A | Script-content detection |
| Script Block Logging | Yes | Logs full script including boolean form |
| AMSI | Yes | Sees resolved content |
| Behavioral (FileDelete) | Yes | Outcome is invariant to boolean syntax |

## Implementation Nuances

- **NUANCES #9 (Boolean values are cosmetic):** `-Force:$true`, `-Force:1`, `-Force` are all identical to the engine. Match the parameter NAME only.
- **NUANCES #2 (CommandLine is raw):** For process_creation rules, boolean values in command lines are preserved verbatim.
- **NUANCES #5 (Regex flavor):** The word-boundary `\b` and case-insensitive `|i` work across all major backends.
