---
id: ADE4-005
title: "Unavailable Field — Silent Match Failure"
ade_category: ADE4
ade_subcategory: ADE4-04
mitre_attack: N/A (telemetry-availability flaw, not an attack technique)
platform: Sigma / SIEM (log-source-dependent)
testable: logic-analysis
---

# Unavailable Field — Silent Match Failure

## Summary

A rule references a field that is spelled correctly and *exists in the schema*, but is **not populated** in the log source that actually reaches the rule. The field is present in the author's reference source (usually Sysmon EID 1) and absent — or empty — everywhere else the rule runs. The compiled query is valid; it simply evaluates against `null` and never matches. This is distinct from a field-name typo ([field-name-mismatch.md](field-name-mismatch.md)): here the name is right and the data is missing.

## ADE Classification

**Category:** ADE4 — Logic Manipulation
**Subcategory:** ADE4-04 — Field Mismapping & Semantics
**Core principle:** Coverage is a property of the *deployed telemetry*, not of the rule text. A field that is only emitted under a specific configuration, event ID, or product creates a blind spot that the rule cannot see and the author did not intend. The attacker's "technique" is often just landing on a host where the depended-upon field is not being collected.

## The Technique

### Where fields go missing

| Field the rule depends on | Present in | Absent / empty in | Root cause |
|---|---|---|---|
| `OriginalFileName` | Sysmon EID 1 | Security 4688, many EDR tables, cross-platform | Sourced from the PE header; only Sysmon exposes it |
| `CommandLine` | Sysmon EID 1 (subject to config) | Security 4688 **unless** command-line auditing is enabled; ≤ Win7/2008R2 has no field at all | GPO/registry `ProcessCreationIncludeCmdLine_Enabled` off by default — **#14** |
| `ParentImage` / `ParentCommandLine` | Sysmon EID 1 | PowerShell Script Block logs (EID 4104), many file/registry events | Parent-process context is a process-creation concept, not carried by other event IDs |
| `Hashes`, network EID 3, ADS EID 15 | Sysmon *if config emits them* | Minimal/filtered Sysmon configs | Config `<Exclude>`/omission — **#23** |
| Deep substrings in `CommandLine` | Untruncated pipelines | Truncated EDR/forwarding paths | Telemetry length ceiling — **#18** |

### Two ways it bites

1. **Positive selection against an absent field → false negative.** `OriginalFileName: 'Cmd.Exe'` on a 4688-only host resolves to `null`; the rule never fires even when `cmd.exe` was renamed and executed.
2. **Truncation moves the indicator out of view.** The field exists and is populated, but the meaningful substring sits past the collection pipeline's length ceiling. An attacker pads the front of the command line with whitespace/comments so a `|contains` match on a deep token never sees it (**#18**). Anchor on early structural tokens (image, first switch) instead.

The [absent-field-inverts-filter.md](absent-field-inverts-filter.md) technique covers the third, nastier case: an absent field inside a `not filter` clause, which inverts the rule outcome rather than merely zeroing it.

## Logic Analysis

**Vulnerable rule** — depends on a Sysmon-only field but is not pinned to Sysmon:

```yaml
title: Renamed LOLBin Execution
status: experimental
logsource:
    category: process_creation
    product: windows          # NOT pinned to service: sysmon
detection:
    selection:
        OriginalFileName: 'CertUtil.exe'
        CommandLine|contains: '-urlcache'
    condition: selection
```

**Coverage matrix:**

| Host telemetry | `OriginalFileName` | `CommandLine` | Fires on renamed `certutil.exe -urlcache`? |
|---|---|---|---|
| Sysmon EID 1 (full config) | populated | populated | Yes |
| Security 4688, cmdline auditing ON | `null` | populated | **No — false negative** |
| Security 4688, cmdline auditing OFF (**#14**) | `null` | `null` | **No — doubly blind** |
| EDR table without PE metadata | `null` | populated | **No — false negative** |

The rule looks complete and even prefers the rename-resistant field — but on three of four telemetry profiles it silently contributes zero coverage.

**Hardened rule** — pin the source that has the field, and provide an OR fallback for sources that don't:

```yaml
title: Renamed LOLBin Execution (Hardened)
status: test
logsource:
    category: process_creation
    product: windows
detection:
    # Preferred, high-fidelity path — requires the Sysmon-only field
    selection_sysmon:
        OriginalFileName: 'CertUtil.exe'
    # Fallback for sources without OriginalFileName: anchor on image name + behavior
    selection_image:
        Image|endswith: '\certutil.exe'
    selection_behavior:
        CommandLine|windash|contains:
            - '-urlcache'
            - '-verifyctl'
            - '-decode'
    condition: (selection_sysmon or selection_image) and selection_behavior
falsepositives:
    - Legitimate certificate-management and update workflows
level: medium
```

Two structural fixes: (1) the behavior anchor uses an early, hard-to-pad token set rather than a single deep substring (**#18**); (2) the identity check ORs the Sysmon-only field with an image-name fallback so at least one branch is populated on every source. Where the org standardizes on Sysmon, the cleaner fix is simply `service: sysmon` plus a documented collection requirement.

## Detection Layers (auditing the rule, not an attack)

| Audit method | Catches? | How |
|---|---|---|
| Telemetry inventory per host class | Yes | Map which event IDs / fields each fleet segment actually emits |
| Field-population probe | Yes | Query the field over a known window; if it is always `null` on a segment, the rule is blind there |
| Verify command-line auditing (**#14**) | Yes | Confirm `ProcessCreationIncludeCmdLine_Enabled` and Audit Process Creation are on where 4688 is the source |
| Sysmon config coverage review (**#23**) | Yes | Confirm the config emits the EIDs/fields the rule depends on and does not `<Exclude>` the abused binaries |
| Truncation test (**#18**) | Yes | Emit a padded command line; confirm the deep-substring rule still matches |
| Pin `service:` + collection requirement | Prevents | Makes the dependency explicit and reviewable |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) **#14** (4688 command-line auditing off by default; no field at all on ≤ Win7/2008R2), **#18** (execution vs telemetry length ceilings; pad-past-truncation), and **#23** (the deployed Sysmon config decides which fields and event IDs exist).
- Related availability boundaries: **#8** (WSL2 telemetry boundary), **#15** (PowerShell v2 downgrade removes 4104), **#16** (Script Block Logging chunking splits a script across events).
- Full field catalog and controllability notes: [`bug_patterns/sigma_field_semantics.md`](../../../bug_patterns/sigma_field_semantics.md).
- A rule's coverage claim is only valid for the telemetry profile it was validated against. "Works in the lab (full Sysmon)" does not imply "works in production (4688, cmdline auditing off)."
- Prefer `OriginalFileName`/hash for identity where the source provides them (**#11**, **#12**), but always OR in an image-name fallback for sources that don't — otherwise the high-fidelity field becomes a single point of blindness.

## References

- [Microsoft — Event 4688 and command-line auditing](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
- [Microsoft — Command line process auditing](https://learn.microsoft.com/en-us/windows-server/identity/ad-ds/manage/component-updates/command-line-process-auditing)
- [Sysmon — configuration reference](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [SwiftOnSecurity / Olaf Hartong — Sysmon config coverage](https://github.com/olafhartong/sysmon-modular)
