---
id: ADE4-001
title: "Gate Inversion — De Morgan's Laws in Detection Logic"
ade_category: ADE4
ade_subcategory: ADE4-01
mitre_attack: N/A (logic flaw, not an attack technique)
platform: Sigma / SIEM (platform-independent)
testable: logic-analysis
---

# Gate Inversion

## Summary

When a detection rule uses chained NOT filters -- `NOT(A) AND NOT(B)` -- the combined exclusion covers only A and B, not the entire space of values. Attackers who use a value outside the exclusion set (C, D, ...) bypass the rule entirely. This is a direct consequence of De Morgan's Laws: `NOT(A) AND NOT(B) = NOT(A OR B)`, meaning the exclusions are additive but finite, and any value not explicitly excluded passes through.

## ADE Classification

**Category:** ADE4 -- Logic Manipulation
**Subcategory:** ADE4-01 -- Filter Incompleteness
**Core principle:** Exclusion-based filters define what is *allowed through* by specifying what is *blocked*. The unblocked space is implicitly trusted and often far larger than the rule author realized.

## The Technique

### The logical structure

Many detection rules follow this pattern:

```
condition: selection AND NOT filter1 AND NOT filter2
```

The author intends: "Alert on the selection, EXCEPT when the event matches filter1 or filter2." But each filter only covers a specific case. The universe of possible values is much larger than the exclusion list.

### De Morgan's expansion

```
NOT(filter1) AND NOT(filter2)
= NOT(filter1 OR filter2)           # De Morgan's Law
```

This means: "Allow through anything that is NOT in {filter1, filter2}." Every value outside that set passes. If the filters exclude `SYSTEM` and `LOCAL SERVICE`, then `NETWORK SERVICE`, domain accounts, machine accounts, gMSA accounts, and all other identities pass through unfiltered.

### The attacker's insight

The attacker does not need to defeat the detection logic -- they just need to operate outside the exclusion set. The rule has a finite list of "known good" exclusions; the attacker picks any identity, path, or value that is not on that list.

## Logic Analysis

### Truth table: Two-filter exclusion

Consider a rule that alerts on process creation but excludes SYSTEM and LOCAL SERVICE accounts:

| User Account | Matches filter1 (SYSTEM)? | Matches filter2 (LOCAL SERVICE)? | NOT(f1) AND NOT(f2) | Alert fires? |
|-------------|--------------------------|----------------------------------|---------------------|-------------|
| NT AUTHORITY\SYSTEM | Yes | No | False | No (excluded) |
| NT AUTHORITY\LOCAL SERVICE | No | Yes | False | No (excluded) |
| NT AUTHORITY\NETWORK SERVICE | No | No | **True** | **Yes** -- but attacker wanted this to be excluded too |
| DOMAIN\attacker | No | No | **True** | **Yes** -- attacker bypasses |
| DOMAIN\machine$ | No | No | **True** | **Yes** -- machine account bypasses |

The rule author likely intended to exclude all service accounts, but the filter only covers two of many possible service identities.

### Boolean expansion

```
Original:    selection AND NOT(User='SYSTEM') AND NOT(User='LOCAL SERVICE')
Equivalent:  selection AND NOT(User IN {'SYSTEM', 'LOCAL SERVICE'})
Gap:         User IN {'NETWORK SERVICE', 'DOMAIN\svc_*', 'gMSA$', ...}  <-- all bypass
```

## Vulnerable Rule

```yaml
title: Suspicious Process Execution by Non-Service Account
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\whoami.exe'
            - '\nltest.exe'
            - '\net.exe'
    filter_system:
        User: 'NT AUTHORITY\SYSTEM'
    filter_local_service:
        User: 'NT AUTHORITY\LOCAL SERVICE'
    condition: selection and not filter_system and not filter_local_service
```

### Why it misses

The rule excludes exactly two accounts. An attacker operating as `NT AUTHORITY\NETWORK SERVICE`, any domain user, any machine account (`DOMAIN\HOST$`), or any managed service account (`gMSA$`) is not excluded and would trigger the rule -- which seems correct. But the *intent* was to exclude all service accounts, and the filter missed several.

More critically: if the rule were *inverted* (trying to alert ONLY on service accounts doing something suspicious), the incomplete filter list would miss service accounts not enumerated.

### Real-world SigmaHQ example

```yaml
# From SigmaHQ: win_system_exe_anomaly (simplified)
title: System Binary Executed from Unusual Path
detection:
    selection:
        OriginalFileName:
            - 'cmd.exe'
            - 'powershell.exe'
    filter_legit_paths:
        Image|startswith:
            - 'C:\Windows\System32\'
            - 'C:\Windows\SysWOW64\'
            - 'C:\Windows\WinSxS\'
    condition: selection and not filter_legit_paths
```

The `|startswith` wildcard on `C:\Windows\WinSxS\` will match ANY subdirectory under WinSxS. An attacker who creates `C:\Windows\WinSxS\malicious\cmd.exe` passes the filter because the path starts with the whitelisted prefix. The wildcard-based exclusion is broader than intended.

## Hardened Rule

```yaml
title: Suspicious Process Execution by Non-Service Account (Hardened)
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith:
            - '\whoami.exe'
            - '\nltest.exe'
            - '\net.exe'
    filter_service_accounts:
        User|startswith: 'NT AUTHORITY\'
    filter_machine_accounts:
        User|endswith: '$'
    condition: selection and not filter_service_accounts and not filter_machine_accounts
falsepositives:
    - Legitimate administrative tools run by domain users
level: medium
```

### Why the hardened rule is better

Instead of enumerating specific service account names (which will always be incomplete), the hardened rule uses pattern matching to cover entire *categories*:
- `NT AUTHORITY\*` covers SYSTEM, LOCAL SERVICE, NETWORK SERVICE, and any future NT AUTHORITY accounts
- `*$` covers all machine accounts and managed service accounts

This reduces the gap from "every non-enumerated service account" to "accounts that don't match either pattern" -- a much smaller set.

### The fundamental tradeoff

Exclusion-based filters can never be proven complete unless the universe of values is known and finite. Allowlist-based approaches (match on known-bad rather than exclude known-good) are structurally more resilient.

## Automated Detection of Gate Inversion

### SigmaFilterCheck

The [SigmaFilterCheck](https://github.com/Karneades/SigmaFilterCheck) tool by Karneades automates detection of vulnerable filter conditions in Sigma rules. It analyzes filter fields and identifies:
- Filters on attacker-controllable fields
- Incomplete exclusion sets
- Wildcard-based exclusions that cover more than intended

```bash
# Check a single rule
python sigma_filter_check.py -r rules/windows/process_creation/suspicious_execution.yml

# Check all rules in a directory
python sigma_filter_check.py -d rules/windows/
```

## Detection Layers

This is a meta-technique -- it applies to the detection rules themselves, not to attacker actions. The "detection" here is auditing your own rule logic.

| Audit Method | Catches? | How |
|--------------|----------|-----|
| Truth table enumeration | Yes | Systematically test all input combinations |
| De Morgan's simplification | Yes | Simplify NOT chains to reveal the actual exclusion set |
| SigmaFilterCheck tool | Yes | Automated analysis of filter fields |
| Adversarial rule testing | Yes | Try values outside the filter set |
| Peer review of filter conditions | Partial | Depends on reviewer recognizing completeness gaps |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) -- filter completeness is a recurring vulnerability across all ADE4 techniques
- Every NOT filter implicitly trusts the entire complement of its exclusion set
- The risk scales with the cardinality of the field: a field with 3 possible values is easy to enumerate; a field with millions (like User or CommandLine) is practically impossible to fully exclude
- Sigma's `|contains`, `|startswith`, and `|endswith` modifiers create partial matches that may cover more or fewer values than intended
- Rule authors should document the *intent* of each filter (what category of events it excludes) alongside the *implementation* (the specific values listed)

## References

- [Karneades - SigmaFilterCheck](https://github.com/Karneades/SigmaFilterCheck)
- [De Morgan's Laws - Wikipedia](https://en.wikipedia.org/wiki/De_Morgan%27s_laws)
- [SigmaHQ - Rule Repository](https://github.com/SigmaHQ/sigma)
- [Florian Roth - Sigma Rule Best Practices](https://blog.sigmahq.io/)
