# ADE4-04 · Field Mismapping & Semantics

Parent category: [ADE4 — Logic Manipulation](../overview.md)

The rule references fields incorrectly — wrong name, unavailable field, or misunderstood semantics — across log sources and Sigma backends, so it silently fails to match.

**Common cases:**
- `CommandLine` vs `commandline`/`command_line`/`cmdline` across backends.
- `OriginalFileName` present only in Sysmon EID 1; absent from Security 4688, EDR, and cross-platform sources.
- `ParentImage` absent in PowerShell ScriptBlock logs (EID 4104).
- `SubjectUserName` vs `TargetUserName` semantics in Windows Security logs.
- A `selection and not filter` rule where `filter` references an absent field can invert to a false positive or false negative.

**Why it's a bug:** the same Sigma rule transpiles to many backends with different field names, availability, and semantics; an unmapped or absent field fails silently rather than loudly.

## Techniques

- [Field-Name Mismatch Across Backends](field-name-mismatch.md) — right field, wrong spelling/case for the target backend; transpiles clean, matches nothing.
- [Unavailable Field — Silent Match Failure](unavailable-field.md) — right name, but the field isn't populated in the source that reaches the rule (Sysmon-only fields, 4688 command-line auditing off, truncation).
- [Absent Field Inverts a Filter Clause](absent-field-inverts-filter.md) — a missing field inside a `not filter` flips the rule outcome via backend null-handling; the ADE4-04 ∩ ADE4-01 case.

Full field catalog: [`bug_patterns/sigma_field_semantics.md`](../../../bug_patterns/sigma_field_semantics.md). Related: Implementation Nuances #5, #14, #18, #23 — [logging_assumption_errors.md](../../../bug_patterns/logging_assumption_errors.md).
