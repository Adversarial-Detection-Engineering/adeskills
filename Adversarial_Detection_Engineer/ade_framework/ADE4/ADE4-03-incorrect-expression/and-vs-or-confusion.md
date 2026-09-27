---
id: ADE4-003
title: "AND vs OR Confusion in Sigma Conditions"
ade_category: ADE4
ade_subcategory: ADE4-03
mitre_attack: N/A (logic flaw, not an attack technique)
platform: Sigma / SIEM (platform-independent)
testable: logic-analysis
---

# AND vs OR Confusion in Sigma Conditions

## Summary

When a Sigma rule ANDs together alternative indicators that should be ORed, the rule becomes too narrow -- requiring ALL indicators to be present when ANY one should suffice. Conversely, when a rule ORs constraints that should be ANDed, the rule becomes too broad -- firing on any single weak signal. Both errors are endemic in detection engineering and stem from confusion about how Sigma's YAML structure maps to Boolean logic.

## ADE Classification

**Category:** ADE4 -- Logic Manipulation
**Subcategory:** ADE4-03 -- Boolean Operator Errors
**Core principle:** AND narrows (requires all conditions), OR broadens (requires any condition). Confusing the two either lets attackers through (too narrow) or drowns analysts in false positives (too broad). Sigma's YAML syntax adds a second layer of confusion: lists within a mapping key are OR, keys within a mapping are AND.

## The Technique

### The two failure modes

**Too narrow (AND where OR intended):**
```
"Alert if the attacker uses curl AND wget"
→ Attacker using only curl bypasses the rule
→ The rule requires an unrealistic combination of indicators
```

**Too broad (OR where AND intended):**
```
"Alert if the process is PowerShell OR the arguments contain -enc"
→ Every legitimate PowerShell execution fires the rule
→ Analysts drown in false positives, eventually disable the rule
```

### Sigma YAML semantics

This is where the confusion originates. Sigma's YAML structure has implicit Boolean semantics that differ from how many engineers read YAML:

```yaml
# YAML list under a key = OR (any value matches)
selection:
    Image|endswith:
        - '\curl.exe'       # Image ends with \curl.exe
        - '\wget.exe'       # OR Image ends with \wget.exe

# Multiple keys in a mapping = AND (all must match)
selection:
    Image|endswith: '\powershell.exe'    # Image matches
    CommandLine|contains: '-enc'          # AND CommandLine matches

# Multiple named selections in condition = depends on operator
condition: selection_process and selection_args    # AND
condition: selection_process or selection_args      # OR
condition: 1 of selection_*                         # OR across all matching
```

**The rule:** Within a single Sigma detection mapping, values in a list are OR; keys across a mapping are AND. Between named selections, the `condition` field explicitly states the operator.

## Logic Analysis

### Case 1: Too-narrow rule (AND on alternatives)

**Vulnerable rule:** Alert when both curl and wget appear in the same process creation event.

```yaml
detection:
    selection_curl:
        Image|endswith: '\curl.exe'
    selection_wget:
        Image|endswith: '\wget.exe'
    condition: selection_curl and selection_wget
```

**Truth table:**

| Process Image | selection_curl? | selection_wget? | AND result | Alert? |
|--------------|----------------|----------------|-----------|--------|
| `curl.exe` | Yes | No | False | **No** -- missed |
| `wget.exe` | No | Yes | False | **No** -- missed |
| Neither | No | No | False | No -- correct |
| Both (impossible*) | Yes | Yes | True | Yes -- but unreachable |

*A single process creation event has exactly one Image value. The AND condition is logically impossible to satisfy -- this rule can never fire.

**Fixed version:**

```yaml
detection:
    selection:
        Image|endswith:
            - '\curl.exe'
            - '\wget.exe'
    condition: selection
```

The list creates an OR: alert if the image is curl OR wget.

### Case 2: Too-broad rule (OR on constraints)

**Vulnerable rule:** Alert on any PowerShell execution or any command line containing encoded content.

```yaml
detection:
    selection_process:
        Image|endswith: '\powershell.exe'
    selection_args:
        CommandLine|contains|base64offset|contains:
            - 'Invoke-Expression'
            - 'IEX'
    condition: selection_process or selection_args
```

**Truth table:**

| Image | CommandLine | selection_process? | selection_args? | OR result | Alert? |
|-------|-------------|-------------------|----------------|----------|--------|
| `powershell.exe` | `Get-Help` | Yes | No | True | **Yes** -- false positive |
| `cmd.exe` | `cmd /c IEX(...)` | No | Yes | True | Yes -- but is cmd.exe with IEX suspicious enough? |
| `powershell.exe` | `IEX(New-Object...)` | Yes | Yes | True | Yes -- correct |
| `notepad.exe` | `file.txt` | No | No | False | No -- correct |

The OR makes every PowerShell execution an alert, regardless of what it does. Analysts see thousands of legitimate PowerShell events, develop alert fatigue, and eventually disable the rule -- leaving the actual malicious usage undetected.

**Fixed version:**

```yaml
detection:
    selection_process:
        Image|endswith: '\powershell.exe'
    selection_args:
        CommandLine|contains:
            - 'Invoke-Expression'
            - 'IEX('
            - 'IEX ('
    condition: selection_process and selection_args
```

The AND requires both PowerShell as the process AND suspicious arguments -- much more precise.

### Case 3: Sigma YAML mapping vs. list confusion

A subtler error occurs when the rule author puts alternatives as separate keys in a mapping, thinking they are ORed:

```yaml
# WRONG — this is an AND (both keys must match the same event)
selection:
    CommandLine|contains: 'curl'
    CommandLine|contains: 'wget'
# This means: CommandLine contains 'curl' AND CommandLine contains 'wget'
# Almost never fires because a single command line rarely contains both strings

# CORRECT — this is an OR (either value matches)
selection:
    CommandLine|contains:
        - 'curl'
        - 'wget'
# This means: CommandLine contains 'curl' OR CommandLine contains 'wget'
```

**Boolean expansion:**

```
Wrong:   CommandLine CONTAINS 'curl' AND CommandLine CONTAINS 'wget'
         → requires both substrings in the same command line

Correct: CommandLine CONTAINS 'curl' OR CommandLine CONTAINS 'wget'
         → either substring triggers the rule
```

## Vulnerable Rule

```yaml
title: Download Tool Execution
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_curl:
        Image|endswith: '\curl.exe'
        CommandLine|contains: 'http'
    selection_wget:
        Image|endswith: '\wget.exe'
        CommandLine|contains: 'http'
    selection_certutil:
        Image|endswith: '\certutil.exe'
        CommandLine|contains: '-urlcache'
    condition: selection_curl and selection_wget and selection_certutil
```

### Why it misses

The condition requires ALL THREE tools to appear in the same process creation event, which is impossible -- each event has exactly one Image value. The rule author intended to catch ANY of these download tools, not all of them simultaneously.

Even if interpreted as a correlation rule across multiple events, the AND requires the attacker to use all three tools, which no real attacker does.

## Hardened Rule

```yaml
title: Download Tool Execution (Hardened)
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection_curl:
        Image|endswith: '\curl.exe'
        CommandLine|contains: 'http'
    selection_wget:
        Image|endswith: '\wget.exe'
        CommandLine|contains: 'http'
    selection_certutil:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_certutil_args:
        CommandLine|contains:
            - '-urlcache'
            - '/urlcache'
    condition: selection_curl or selection_wget or (selection_certutil and selection_certutil_args)
falsepositives:
    - Legitimate download activity by system administrators
    - Automated update scripts using curl
level: medium
```

### Why the hardened rule works

1. **OR between tool selections:** Each download tool is detected independently
2. **AND within each tool:** Each tool requires both the process identity AND suspicious arguments (prevents matching curl without network arguments)
3. **OriginalFileName for certutil:** Catches renamed copies

## Research: lolcads Findings (January 2025)

The [lolcads](https://lolcads.io/) research project analyzed the real-world effectiveness of Sigma rules against evasion and found:

| Finding | Detail |
|---------|--------|
| Alerts evadable | 99.99% of tested alerts could be evaded |
| Simple file renaming | 90% of evasions required nothing more than renaming the binary |
| Logic errors | AND/OR confusion was a contributing factor in many rule failures |
| Root cause | Rules anchored on attacker-controllable fields with brittle logic |

These findings underscore that Boolean logic errors compound with other ADE categories: a rule that ANDs indicators incorrectly AND matches on controllable fields (ADE4-002) AND uses literal substrings (ADE1) has multiple independent evasion paths.

### SigmaHQ quality pipeline

The SigmaHQ project includes automated checks that catch some Boolean errors:

| Check | Catches |
|-------|---------|
| Overly broad rules (too many false positives) | Rules with `condition: selection` on weak selections |
| Impossible conditions | AND across mutually exclusive field values |
| Redundant selections | Selections that are subsets of other selections |

However, the pipeline struggles with **too-narrow** rules because determining whether a rule should be broader requires understanding the author's intent, which is not encoded in the YAML.

## Detection Layers

This is a meta-technique targeting detection rule quality.

| Audit Method | Catches? | How |
|--------------|----------|-----|
| Truth table enumeration | Yes | Test all combinations of selection matches |
| Sigma rule linting | Partial | Automated checks catch impossible conditions |
| Peer review with Boolean focus | Yes | Reviewer asks "should these be ANDed or ORed?" |
| False positive rate monitoring | Partial | Too-broad rules show high FP rates; too-narrow may show zero hits |
| Coverage testing with atomic tests | Yes | Run known-bad commands; verify rule fires |
| lolcads-style automated evasion testing | Yes | Systematic evasion attempts against each rule |

## Common Patterns and Quick Reference

| Pattern | Correct Operator | Why |
|---------|-----------------|-----|
| Multiple tool alternatives (curl, wget, certutil) | **OR** | Attacker uses one, not all |
| Process identity + suspicious arguments | **AND** | Both needed for confidence |
| Multiple suspicious argument variations | **OR** | Any variant is suspicious |
| Multiple evidence sources (file + registry + network) | **AND** for high confidence, **OR** for broad coverage | Tradeoff: precision vs. recall |
| Exclusion filters (filter1, filter2) | **AND NOT** each | Each filter is independent |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) -- Boolean operator confusion is the most common logic error in detection engineering
- Sigma's YAML-to-Boolean mapping is the primary source of confusion: engineers who think in SQL or SPL may not realize that YAML list = OR and YAML mapping keys = AND
- The `1 of selection_*` syntax is a safer way to express OR across multiple named selections -- it makes the intent explicit
- Too-narrow rules are harder to detect than too-broad rules because they produce no output (zero alerts) rather than excessive output (thousands of alerts)
- Testing both positive cases (known-bad that should fire) and negative cases (known-good that should not fire) is essential for catching both failure modes
- The lolcads finding that 99.99% of alerts are evadable suggests that logic errors are not edge cases but the default state of most detection rule sets

## References

- [lolcads - Detection Evasion Research (Jan 2025)](https://lolcads.io/)
- [SigmaHQ - Sigma Specification](https://sigmahq.io/docs/basics/conditions.html)
- [SigmaHQ - Rule Repository](https://github.com/SigmaHQ/sigma)
- [Sigma Condition Documentation](https://sigmahq.io/docs/basics/conditions.html)
- [Karneades - SigmaFilterCheck](https://github.com/Karneades/SigmaFilterCheck)
- [Florian Roth - Writing Good Sigma Rules](https://blog.sigmahq.io/)
