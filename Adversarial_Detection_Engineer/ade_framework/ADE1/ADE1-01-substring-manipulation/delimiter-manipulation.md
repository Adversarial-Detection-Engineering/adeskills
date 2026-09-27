---
id: ADE1-006
title: Delimiter Manipulation
ade_category: ADE1
ade_subcategory: ADE1-01
mitre_attack:
  - T1059.001 (Command and Scripting Interpreter: PowerShell)
  - T1059.003 (Command and Scripting Interpreter: Windows Command Shell)
  - T1087 (Account Discovery)
platform: Windows
testable: true
---

# Delimiter Manipulation

## Summary

Shells offer multiple operators to sequence or combine commands: `;`, `&`, `&&`, `||`, `|`. A detection rule that matches one specific delimiter misses payloads using any other valid separator. The fix is not a better substring match -- it is a behavioral correlation that detects the cluster of recon binaries spawning under a single parent, regardless of how they were chained.

## ADE Classification

**Category:** ADE1 -- Reformatting in Actions
**Core principle:** The semantic flow (run command A, then command B) is preserved across all delimiter characters. Only the syntactic separator changes. The rule checks one literal delimiter; the shell accepts many.

## The Technique

**cmd.exe sequencing operators:**

| Operator | Behavior |
|----------|----------|
| `&` | Run B regardless of A's exit code |
| `&&` | Run B only if A succeeded |
| `\|\|` | Run B only if A failed |
| `\|` | Pipe A's stdout to B's stdin |

**PowerShell sequencing operators:**

| Operator | Behavior |
|----------|----------|
| `;` | Sequential execution |
| `\|` | Pipeline |
| `&&` | Conditional on success |
| `\|\|` | Conditional on failure |

A rule matching `'whoami; hostname'` catches exactly one of these forms. Switch to `&`, `&&`, or `|` and the literal substring vanishes.

Additionally, when PowerShell invokes a process via `Start-Process -ArgumentList`, the argument string is parsed and re-joined with different whitespace and quoting than the SIEM expects, producing zero matches for obvious search patterns.

## Bypass Demonstration

### Benign test payload

```cmd
:: cmd.exe -- all execute whoami then hostname:
whoami & hostname
whoami && hostname
whoami | hostname

:: PowerShell:
whoami; hostname
whoami | Out-Null; hostname
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Raw command line | `whoami & hostname` or `whoami; hostname` |
| Shell parser | Two commands executed sequentially |
| Sysmon EID 1 CommandLine | Raw form with specific delimiter preserved |
| Sysmon EID 1 (per child) | Separate process creation for each binary |
| Script Block Logging (4104) | Full script with delimiter |
| AMSI | N/A for this technique |

## Vulnerable Rule

```yaml
title: Recon Chain via Semicolon (Naive)
id: 66666666-6666-6666-6666-000000000001
status: experimental
description: Detects whoami chained to hostname via semicolon
logsource:
  product: windows
  category: process_creation
detection:
  selection:
    CommandLine|contains: 'whoami; hostname'
  condition: selection
level: low
```

### Why it misses

The literal `'whoami; hostname'` only matches that one delimiter. Switch to `&`, `&&`, `|`, or remove the space (`whoami;hostname`), and the substring is no longer present.

## Hardened Rule

The fix moves the unit of analysis from "the command-line string" to "the behavioral cluster around a parent process." Detect 3+ recon binaries spawning under a single parent within 60 seconds:

```yaml
title: Recon Binary Chain (Hardened, Behavioral)
id: 66666666-6666-6666-6666-000000000002
status: stable
description: |
  Detects a sequence of common recon binaries spawning under a single parent process
  within a short time window -- regardless of how they were sequenced.
logsource:
  product: windows
  category: process_creation
detection:
  selection_recon_image:
    Image|endswith:
      - '\whoami.exe'
      - '\hostname.exe'
      - '\nltest.exe'
      - '\net.exe'
      - '\net1.exe'
      - '\ipconfig.exe'
      - '\systeminfo.exe'
      - '\tasklist.exe'
      - '\quser.exe'
      - '\query.exe'
  selection_recon_ofn:
    OriginalFileName:
      - 'whoami.exe'
      - 'hostname.exe'
      - 'nltestrk.exe'
      - 'net.exe'
      - 'net1.exe'
      - 'ipconfig.exe'
      - 'sysinfo.exe'
      - 'tasklist.exe'
      - 'quser.exe'
      - 'query.exe'
  condition: selection_recon_image or selection_recon_ofn
level: low
correlation:
  type: event_count
  rules:
    - selection_recon
  group-by:
    - ParentProcessGuid
  timespan: 60s
  condition:
    gte: 3
```

The correlation -- 3+ recon-family binaries from the same parent in 60 seconds -- fires regardless of which delimiter the attacker used. It also catches chains delivered via separate scripts, scheduled tasks fired in sequence, or any other mechanism.

Note: `nltest.exe` reports `nltestrk.exe` and `systeminfo.exe` reports `sysinfo.exe` as OriginalFileName. See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #1.

## Sysmon Evidence

### Key Fields (per child process)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\whoami.exe` | Each recon binary spawns as a separate process |
| CommandLine | `whoami` | Clean -- delimiter is on the parent's command line |
| OriginalFileName | `whoami.exe` | From PE VERSION_INFO |
| ParentImage | `C:\Windows\System32\cmd.exe` | Same parent for all children in a chain |
| ParentProcessGuid | `{GUID}` | Correlation key -- same GUID groups the chain |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Command-line substring | No | Only matches one specific delimiter |
| Regex with delimiter alternation | Fragile | Enumerates delimiters but misses novel separators |
| Image field | Partial | Identifies recon binaries individually |
| OriginalFileName | Partial | Binary identity, needs correlation for chain signal |
| Parent-process correlation | Yes | 3+ recon binaries from same parent defeats all delimiters |
| Script Block Logging | N/A | Primarily a cmd.exe technique |
| Behavioral | Yes | The cluster pattern is invariant to delimiter choice |

## Implementation Nuances

- **NUANCES #1 (OriginalFileName):** `nltest.exe` is `nltestrk.exe`, `systeminfo.exe` is `sysinfo.exe` in OriginalFileName. Always OR both fields.
- **NUANCES #6 (Correlation timeframes):** 60s balances fidelity against false positives. Too short (5s) misses attackers who add sleep. Too long (10m) floods with admin noise.
- **NUANCES #2 (CommandLine is raw):** Each child process has a clean command line; the delimiter only appears on the parent's command line, which is why per-child detection + correlation is the right architecture.
