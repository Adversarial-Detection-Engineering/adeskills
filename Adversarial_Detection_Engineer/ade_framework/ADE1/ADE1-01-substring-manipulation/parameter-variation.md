---
id: ADE1-008
title: Parameter Prefix Abbreviation
ade_category: ADE1
ade_subcategory: ADE1-01
mitre_attack:
  - T1059.001 (Command and Scripting Interpreter: PowerShell)
  - T1140 (Deobfuscate/Decode Files or Information)
platform: Windows
testable: true
---

# Parameter Prefix Abbreviation

## Summary

Windows command-line parsers accept any unambiguous prefix of a parameter name. PowerShell's `-EncodedCommand` can be invoked via `-e`, `-ec`, `-enc`, and over two dozen other abbreviations, with either `-` or `/` as the prefix character. A detection rule matching a single literal spelling covers one variant out of twenty-four.

## ADE Classification

**Category:** ADE2 — Omit Alternatives (primary), ADE1 — Reformatting in Actions (secondary)
**Core principle:** The PowerShell parser resolves any unique prefix of a parameter name to the full parameter. The rule checks one literal spelling; the parser accepts an entire equivalence class. Every spelling the rule omits is a free pass.

The DEaTHCon workshop classifies this as ADE2 — the rule fails to enumerate all valid prefix variants. It also has an ADE1 dimension since each variant is a reformatting of the same flag string. Filed under ADE1 in this repo for structural convenience, but the primary classification is ADE2.

## The Technique

PowerShell accepts any unambiguous prefix of a parameter name. Since no other PowerShell parameter starts with `e`, the flag `-EncodedCommand` can be shortened all the way down to `-e`. Both `-` and `/` are valid parameter prefix characters.

This creates an equivalence class of 24+ valid spellings:

| Prefix | Examples |
|--------|----------|
| Dash (`-`) | `-e`, `-ec`, `-en`, `-enc`, `-enco`, `-encod`, `-encode`, `-encoded`, `-encodedc`, `-encodedco`, `-encodedcom`, `-encodedcomm`, `-encodedcomma`, `-encodedcomman`, `-encodedcommand` |
| Slash (`/`) | `/e`, `/ec`, `/en`, `/enc`, ... `/encodedcommand` |

The behavior is not unique to PowerShell. `nslookup` accepts any unique prefix of its flags, and `netsh` exhibits a combinatorial explosion of valid abbreviations across every parameter.

## Bypass Demonstration

### Benign test payload

```cmd
:: All of these invoke EncodedCommand with a harmless Base64 payload (whoami)
powershell.exe -EncodedCommand dwBoAG8AYQBtAGkA
powershell -encodedcommand dwBoAG8AYQBtAGkA
powershell -encod dwBoAG8AYQBtAGkA
powershell -ec dwBoAG8AYQBtAGkA
powershell -e dwBoAG8AYQBtAGkA
powershell /EncodedCommand dwBoAG8AYQBtAGkA
powershell /e dwBoAG8AYQBtAGkA
pwsh -e dwBoAG8AYQBtAGkA
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Raw command line | `powershell -ec <b64>` |
| PowerShell parser | Resolves `-ec` to `-EncodedCommand` |
| Sysmon EID 1 CommandLine | `powershell -ec <b64>` (raw, unresolved) |
| Script Block Logging (4104) | Deobfuscated script block (the decoded payload) |
| AMSI | Deobfuscated payload content |

## Vulnerable Rule

```yaml
title: PowerShell Encoded Command (Naive)
id: 11111111-1111-1111-1111-000000000001
status: experimental
description: Detects PowerShell launched with -EncodedCommand
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-EncodedCommand'
  condition: selection
falsepositives:
  - Legitimate scheduled tasks
level: medium
```

### Why it misses

`CommandLine|contains: '-EncodedCommand'` matches that one spelling only. An attacker using `-ec`, `-e`, `/EncodedCommand`, or `-encod` walks straight past it. The rule also misses `pwsh.exe` (PowerShell 7+), which accepts the same flag semantics.

## Hardened Rule

```yaml
title: PowerShell Encoded Command (Hardened)
id: 11111111-1111-1111-1111-000000000002
status: stable
description: Detects PowerShell launched with any encoded-command flag variation
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith:
      - '\powershell.exe'
      - '\pwsh.exe'
  selection_ofn:
    OriginalFileName:
      - 'PowerShell.EXE'
      - 'pwsh.dll'
  selection_flag:
    CommandLine|re|i: '[-\/](e|ec|en|enc|enco|encod|encode|encoded|encodedc|encodedco|encodedcom|encodedcomm|encodedcomma|encodedcomman|encodedcommand)\b'
  condition: (selection_image or selection_ofn) and selection_flag
falsepositives:
  - Legitimate scheduled tasks (rare -- most use script files, not encoded commands)
level: high
```

The `re|i` modifier covers every valid prefix of `EncodedCommand` from `e` to the full word, with either `-` or `/` and a `\b` word boundary to avoid false positives on flags that happen to contain `e` (e.g., `-encoder`).

Note: `OriginalFileName` for `pwsh.exe` is `pwsh.dll` (PowerShell 7 is a .NET host). See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #1 and #7.

## Sysmon Evidence

### Key Fields

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe` | Resolved path -- unaffected by flag spelling |
| CommandLine | `powershell -ec dwBoAG8AYQBtAGkA` | Raw abbreviated flag preserved |
| OriginalFileName | `PowerShell.EXE` | From PE VERSION_INFO |
| ParentImage | `C:\Windows\System32\cmd.exe` | Varies by invocation context |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Command-line substring | No | Only matches one literal spelling |
| Regex with prefix enumeration | Yes | Covers all valid abbreviations with word boundary |
| Image field | Partial | Identifies PowerShell binary but not the flag |
| OriginalFileName | Partial | Survives binary rename but still needs flag check |
| Script Block Logging | Yes | Logs the decoded payload regardless of flag spelling |
| AMSI | Yes | Sees deobfuscated content at runtime |
| Behavioral | Yes | Base64 decode + execution pattern is invariant |

## Implementation Nuances

- **NUANCES #1 (OriginalFileName):** `pwsh.exe` reports `pwsh.dll` as OriginalFileName. Always OR both `Image|endswith` and `OriginalFileName` fields.
- **NUANCES #7 (Parameter prefix parsing):** PowerShell accepts `-` and `/` as prefixes and any unambiguous prefix abbreviation. The regex must cover the minimum unambiguous prefix (`-e`), not just the full name.
- **NUANCES #5 (Regex flavor):** The alternation pattern is basic enough for all backends (RE2, PCRE, Lucene). No lookahead/lookbehind needed.
