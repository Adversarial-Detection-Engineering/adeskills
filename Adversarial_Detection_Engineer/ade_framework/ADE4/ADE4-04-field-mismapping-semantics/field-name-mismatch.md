---
id: ADE4-004
title: "Field-Name Mismatch Across Backends"
ade_category: ADE4
ade_subcategory: ADE4-04
mitre_attack: N/A (logic/mapping flaw, not an attack technique)
platform: Sigma / SIEM (backend-dependent)
testable: logic-analysis
---

# Field-Name Mismatch Across Backends

## Summary

A single Sigma rule transpiles to many SIEM backends, each with its own field-naming scheme and case-handling. When the rule author uses a field name that the target backend spells differently — `CommandLine` vs `commandline` vs `command_line`, `TargetFilename` vs `TargetFileName` — the compiled query references a field that does not exist in that backend's schema. The query does not error; it simply matches nothing. This is a **silent zero-coverage gap**: the rule appears deployed and green, but never fires.

## ADE Classification

**Category:** ADE4 — Logic Manipulation
**Subcategory:** ADE4-04 — Field Mismapping & Semantics
**Core principle:** A field reference that does not resolve in the target schema is not a syntax error — it is a match against nothing. The rule is "wrong by construction" (an ADE4-03 sibling), but the error lives in the field-mapping layer rather than the Boolean layer, and it is invisible until you inspect the *transpiled* query rather than the Sigma source.

Unlike most ADE techniques, no attacker action is required. The rule is born broken the moment it targets a backend whose field mapping the author did not verify. An attacker who knows a given backend uses `command_line` simply relies on the org's rule being written against `CommandLine`.

## The Technique

### Where the names diverge

Sigma field names are case-insensitive *in the specification*, but the pySigma backends and the underlying data schemas are not uniformly so. The mapping from a Sigma taxonomy field to a concrete column is done by each backend's pipeline, and gaps there produce a field that silently resolves to nothing.

| Sigma field (as written) | Sysmon EID 1 | Windows Security 4688 | Elastic ECS | Splunk (typical) | Sentinel (KQL) |
|---|---|---|---|---|---|
| `CommandLine` | `CommandLine` | `Process Command Line` (field literally named with spaces) | `process.command_line` | `Process_Command_Line` / `CommandLine` | `CommandLine` / `ProcessCommandLine` |
| `Image` | `Image` | `New Process Name` | `process.executable` | `Image` / `NewProcessName` | `NewProcessName` / `FolderPath` |
| `OriginalFileName` | `OriginalFileName` | *(absent)* | `process.pe.original_file_name` | varies | *(absent in 4688 tables)* |
| `ParentImage` | `ParentImage` | `Creator Process Name` | `process.parent.executable` | `ParentImage` | `InitiatingProcessFolderPath` |

A rule authored against Sysmon field names and shipped to a 4688-only or ECS-normalized backend without a mapping pipeline references columns that do not exist there.

### The two silent-failure surfaces

1. **Case / spelling drift.** `Commandline`, `commandLine`, `command_line`, `TargetFileName` (Sysmon actually emits `TargetFilename`, lowercase `n`). On a case-sensitive backend these resolve to no column.
2. **Log-source binding drift.** The rule matches Sysmon field names but the deployed pipeline feeds it Security-log (4688) events, where the command line — if present at all — lives in a field named `Process Command Line`, not `CommandLine` (see [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) **#14**), and only when command-line auditing is switched on. See the companion technique [Unavailable / Absent Field](unavailable-field.md) for the availability half of this problem.

## Logic Analysis

**Vulnerable rule** — authored against a field the target backend renames:

```yaml
title: Encoded PowerShell Execution
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        Image|endswith: '\powershell.exe'
        Commandline|contains: '-enc'      # NOTE: 'Commandline', not 'CommandLine'
    condition: selection
```

**What happens per backend:**

| Backend | `Commandline` resolves to | Result |
|---|---|---|
| Sysmon via a case-normalizing pipeline | `CommandLine` | Fires (got lucky) |
| Case-sensitive field mapping | no column | **Silent — matches nothing** |
| 4688-only host | no `Commandline`; data is in `Process Command Line` | **Silent — matches nothing** |

The rule passes YAML linting, transpiles without error on most backends, and shows zero hits. Zero hits is indistinguishable from "no attacks happened," so the gap is never noticed until an incident review.

**Hardened rule** — pin the log source, use the canonical field spelling, and let a verified pipeline own the mapping:

```yaml
title: Encoded PowerShell Execution (Hardened)
status: test
logsource:
    category: process_creation
    product: windows
    service: sysmon           # pin the source so field names are known
detection:
    selection_img:
        - Image|endswith: '\powershell.exe'
        - OriginalFileName: 'PowerShell.EXE'   # survives rename; Sysmon-only, hence the service pin
    selection_enc:
        CommandLine|windash|contains: '-enc'   # canonical spelling; windash covers -/ 
    condition: selection_img and selection_enc
falsepositives:
    - Administrative scripts that legitimately pass -EncodedCommand
level: medium
```

If you must target multiple sources, do not paper over the difference with one guessed field name — define the field mapping explicitly in the backend pipeline (pySigma processing pipeline / field-mapping transformation) and **test the transpiled query**, not the Sigma source.

## Detection Layers (auditing the rule, not an attack)

| Audit method | Catches? | How |
|---|---|---|
| Inspect the **transpiled** query | Yes | Read the actual SPL/KQL/Lucene the rule compiles to; confirm the field exists in that schema |
| Field-existence probe | Yes | Query the target index for the field over a known window; a field that never appears is unmapped |
| Zero-hit monitoring | Partial | A rule that has *never* fired since deploy is suspect — but zero hits can also be genuine |
| Atomic test replay | Yes | Run a known-bad command; confirm the rule fires on that backend specifically |
| Pin `service:` in `logsource` | Prevents | Removes the cross-source ambiguity at authoring time |
| pySigma pipeline field-mapping validation | Yes | The pipeline declares the mapping; unmapped fields can be made to error instead of resolving to null |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) **#5** (Sigma `|re` regex flavor varies by backend — the same transpile-time divergence applies to field names), **#14** (4688 command-line auditing off by default; the field is named `Process Command Line`), and **#23** (your Sysmon config decides which fields exist at all).
- Full field-mapping catalog: [`bug_patterns/sigma_field_semantics.md`](../../../bug_patterns/sigma_field_semantics.md).
- Case-insensitivity in the Sigma spec does **not** guarantee case-insensitivity in the compiled query — the backend's data store decides.
- A field typo and an absent field fail identically at runtime (no match), but have different fixes: a typo is corrected at authoring; an absent field requires either a different source or an OR across sources (see [unavailable-field.md](unavailable-field.md)).
- Prefer pinning `service:` over writing "portable" rules against a lowest-common-denominator field name — portability that resolves to null on half your fleet is worse than an explicit single-source rule.

## References

- [SigmaHQ — Sigma Taxonomy & field mapping](https://sigmahq.io/docs/basics/rules.html)
- [pySigma — Processing Pipelines](https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html)
- [Microsoft — Audit Process Creation / command line in 4688](https://learn.microsoft.com/en-us/windows/security/threat-protection/auditing/event-4688)
