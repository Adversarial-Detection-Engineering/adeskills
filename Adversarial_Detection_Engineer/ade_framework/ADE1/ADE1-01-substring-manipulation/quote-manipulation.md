---
id: ADE1-009
title: Quote Manipulation
ade_category: ADE1
ade_subcategory: ADE1-01
mitre_attack:
  - T1059.003 (Command and Scripting Interpreter: Windows Command Shell)
  - T1490 (Inhibit System Recovery)
platform: Windows
testable: true
---

# Quote Manipulation

## Summary

Windows command-line parsers (cmd.exe, PowerShell) treat quote characters as delimiters that get stripped before the binary receives its arguments. An attacker can splice quotes anywhere inside a command token -- even mid-word -- and the execution is unchanged. The byte-level command line, however, looks completely different, breaking any literal substring detection.

## ADE Classification

**Category:** ADE1 -- Reformatting in Actions
**Core principle:** The OS parser strips quote characters before passing arguments to the target binary. Sysmon logs the raw form with quotes intact. Literal-string rules matching the clean form never see the quote-spliced variant.

## The Technique

Three families of quoting tricks defeat literal matching:

1. **Wrapping** -- `"whoami"` instead of `whoami`
2. **Mid-token quoting** -- `who"a"mi`, `wh"oa"mi`, `w"hoami"`
3. **Empty-quote splicing** -- `reagentc.exe /dis""able` (the parser strips the empty `""` and resolves to `/disable`)

The technique is especially dangerous when the threat is a specific **flag** of an otherwise-benign binary (e.g., `reagentc.exe /disable` to turn off Windows Recovery Environment). Image-only matching cannot distinguish `/disable` from benign flags like `/info` or `/enable`, so the detection must match the flag -- and that flag match is exactly what quotes defeat.

## Bypass Demonstration

### Benign test payload

```cmd
:: cmd.exe -- all execute whoami identically:
whoami
"whoami"
who"a"mi
wh""oami
w"hoam"i

:: reagentc -- the parser resolves all to /disable:
reagentc.exe /disable
reagentc.exe /dis""able
reagentc.exe /"d"i"s"a"b"l"e
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Raw command line | `reagentc.exe /dis""able` |
| cmd.exe parser | Strips `""`, resolves to `/disable` |
| Sysmon EID 1 CommandLine | `reagentc.exe /dis""able` (raw, quotes preserved) |
| Script Block Logging (4104) | N/A for cmd.exe invocations |
| AMSI | N/A for cmd.exe invocations |

## Vulnerable Rule

```yaml
title: Windows Recovery Environment Disabled (Naive)
id: 55555555-5555-5555-5555-000000000001
status: experimental
description: Detects reagentc.exe being used to disable Windows Recovery Environment
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    Image|endswith: '\reagentc.exe'
    CommandLine|contains: '/disable'
  condition: selection
level: high
```

### Why it misses

`CommandLine|contains: '/disable'` looks for the contiguous 8-byte sequence `/disable`. Splice an empty `""` anywhere inside it -- `/dis""able`, `/d""is""able`, `/"d"i"s"a"b"l"e` -- and the literal substring is no longer present. The parser still resolves to `/disable`; the rule never fires.

Image-only matching produces too many false positives because `reagentc.exe` has legitimate uses (`/info`, `/enable`, vendor maintenance).

## Hardened Rule

**Layer 1 -- Quote-tolerant flag matching:**

```yaml
title: Windows Recovery Environment Disabled - reagentc (Hardened)
id: 55555555-5555-5555-5555-000000000002
status: stable
description: Detects reagentc.exe /disable regardless of quote splicing in the flag
logsource:
  product: windows
  category: process_creation
detection:
  selection_image:
    Image|endswith: '\reagentc.exe'
  selection_ofn:
    OriginalFileName: 'reagentc.exe'
  selection_flag:
    CommandLine|re|i: "\/[\"'`]*d[\"'`]*i[\"'`]*s[\"'`]*a[\"'`]*b[\"'`]*l[\"'`]*e"
  filter_legit:
    CommandLine|re|i: '/(enable|info|boottore)\b'
  condition: (selection_image or selection_ofn) and selection_flag and not filter_legit
level: high
```

The regex allows zero-or-more quote characters (`"`, `'`, backtick) between every letter of `disable`, defeating any in-token splicing.

**Layer 2 -- Behavioral side-effect detection:**

```yaml
title: Windows Recovery Environment Disabled - Behavioral (Hardened)
id: 55555555-5555-5555-5555-000000000003
status: stable
description: |
  Detects WRE being disabled via any path -- reagentc.exe, bcdedit, DISM, or
  direct registry/BCD modification -- via the side-effect signature.
logsource:
  product: windows
detection:
  selection_registry:
    EventID: 13
    TargetObject|contains: '\Control\WinRE'
  selection_bcd_file:
    EventID: 11
    TargetFilename|contains:
      - '\Recovery\WindowsRE\Winre.wim'
      - '\Boot\BCD'
  condition: selection_registry or selection_bcd_file
level: high
```

Layer 2 catches all paths (reagentc, bcdedit, DISM, direct registry) because they all converge on the same registry/BCD artifacts.

## Sysmon Evidence

### Key Fields

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\reagentc.exe` | Resolved path -- unaffected by quoting |
| CommandLine | `reagentc.exe /dis""able` | Raw form with quotes preserved |
| OriginalFileName | `reagentc.exe` | From PE VERSION_INFO |
| ParentImage | Varies | Invocation context |

For the behavioral layer (side-effect detection):

| Field | Value | Note |
|-------|-------|------|
| EventID | 13 (RegistryEvent) | Value Set |
| TargetObject | `...\Control\WinRE` | WRE configuration key |
| EventID | 11 (FileCreate) | BCD store modification |
| TargetFilename | `...\Boot\BCD` | BCD store path |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Command-line substring | No | Quotes break contiguous literal match |
| Regex with quote tolerance | Yes | Allows optional quote chars between letters |
| Image field | Partial | Identifies binary but not the sensitive flag |
| OriginalFileName | Partial | Binary identity, still needs flag check |
| Script Block Logging | N/A | cmd.exe invocation, not PowerShell |
| AMSI | N/A | cmd.exe invocation |
| Behavioral (registry/BCD) | Yes | Side-effect is invariant to quoting |

## Implementation Nuances

- **NUANCES #1 (OriginalFileName):** Always OR `Image|endswith` and `OriginalFileName` to catch renamed binaries.
- **NUANCES #2 (CommandLine is raw):** Sysmon preserves quotes verbatim. This is the root cause of the bypass.
- **NUANCES #5 (Regex flavor):** The quote-tolerance regex uses basic character classes compatible with all backends.
