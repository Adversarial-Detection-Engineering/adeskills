# Bug Patterns

Cross-cutting reference material that the ADE technique files draw on: platform-specific detection-logic-bug catalogs, telemetry/logging nuances, and alternative-technique catalogs. Where a worked technique file is one bug in one place, these are the reusable, many-to-many references.

## Platform bug catalogs

Detection-logic bugs specific to a SIEM/EDR query language and rule model — rule types, query-language quirks, transpilation and field pitfalls — each mapped back to the ADE categories.

| File | Covers |
|---|---|
| [elasticsecurity.md](elasticsecurity.md) | Elastic Security (TOML / KQL / EQL / ES\|QL): rule-type exposures, `new_terms`/`threshold` keys, `maxspan`, `DATE_TRUNC` buckets, `process.name` vs `.executable`, extension lists, ML drift |
| [microsoftsentinel.md](microsoftsentinel.md) | Microsoft Sentinel (KQL): `queryPeriod`/`bin()` windows, `parse` on message strings, IOC/enum lists, per-entity & Top-N thresholds, ASIM semantics, KQL case/regex quirks, `join` null-handling |
| [sigma.md](sigma.md) | Sigma (generic YAML): detection-block Boolean semantics, `logsource` binding, modifier blind spots, and the transpilation bug class (regex flavor, field mapping, null-handling) |

## Telemetry & field semantics

| File | Covers |
|---|---|
| [logging_assumption_errors.md](logging_assumption_errors.md) | **Implementation Nuances #1–#23** — the numbered telemetry/parsing/backend gotchas referenced throughout the framework as *NUANCES #N* |
| [sigma_field_semantics.md](sigma_field_semantics.md) | Sigma field naming, modifiers, field controllability by log source, condition-logic traps |

## Alternative-technique catalogs (ADE2 "omit alternatives")

| File | Covers |
|---|---|
| [LOLBAS-gap-analysis.md](LOLBAS-gap-analysis.md) | Variants the LOLBAS project does not capture; a contribution backlog with ADE mappings |
| [cmdline_obfuscation.md](cmdline_obfuscation.md) | Command-line reformatting / obfuscation equivalence classes (ADE1) |
| [credential_access_alternatives.md](credential_access_alternatives.md) | Alternative credential-access methods |
| [network_download_evasion.md](network_download_evasion.md) | Alternative ingress/download mechanisms |
| [persistence_alternatives.md](persistence_alternatives.md) | Alternative persistence locations/mechanisms |
| [powershell_evasion.md](powershell_evasion.md) | PowerShell-specific evasion techniques |
| [windows_api_wmi.md](windows_api_wmi.md) | Windows API / WMI alternatives to CLI tooling |
| [evasion_techniques_reference.md](evasion_techniques_reference.md) | General evasion-technique reference |

## See also

- Framework overviews: [ADE1](../ade_framework/ADE1/overview.md) · [ADE2](../ade_framework/ADE2/overview.md) · [ADE3](../ade_framework/ADE3/overview.md) · [ADE4](../ade_framework/ADE4/overview.md)
- [Mitigations](../ade_framework/mitigations.md) (incl. per-platform sections) · [Rulesets](../rulesets.md) · [ADE checklist](../ade-checklist.md)
