# SIGMA Field Semantics & Pitfalls

## Field Naming Issues

Sigma field names are case-insensitive in the specification but backend implementations vary. Common mismatches:

- **CommandLine** vs **commandline** vs **command_line**: Sysmon uses `CommandLine` (PascalCase), but some backends normalize to lowercase. Rules targeting `Commandline` may silently fail on case-sensitive backends.
- **OriginalFileName** vs **Image**: `OriginalFileName` resists process renaming evasion (sourced from PE header), while `Image` reflects the on-disk path. A rule matching only `Image: '*\cmd.exe'` is trivially bypassed by renaming the binary. Rules should prefer `OriginalFileName` where available, but note it is only populated by Sysmon EventID 1 and not all EDR telemetry sources.
- **ParentImage** vs **ParentCommandLine**: Parent process fields are not available in all log sources. PowerShell ScriptBlock logging (EventID 4104) does not contain `ParentImage` or `CommandLine` fields from process creation events.
- **TargetFilename** vs **TargetFileName**: Sysmon uses `TargetFilename` (lowercase 'n'). Typos here cause silent match failures.
- **User** vs **SubjectUserName** vs **TargetUserName**: Windows Security logs distinguish Subject and Target users. Using the wrong field misattributes activity.

## Sigma Modifiers

Modifiers transform field matching behavior. Critical modifiers and their semantics:

- **|contains**: Substring match. `CommandLine|contains: '-enc'` matches anywhere in the string. Beware: this also matches `-encounter`, `-encoding`, etc.
- **|startswith / |endswith**: Anchored matches. `Image|endswith: '\cmd.exe'` prevents matching `notcmd.exe` but misses `cmd.exe.bak` or `cmd.exe ` (trailing space).
- **|all**: Requires ALL values in a list to match (AND logic). Without `|all`, a list of values uses OR logic. `CommandLine|contains|all: ['-nop', '-w hidden', '-enc']` requires all three substrings.
- **|base64 / |base64offset**: Matches Base64-encoded versions of a string. `|base64offset` handles all three Base64 alignment offsets (offset 0, 1, 2). Critical for detecting encoded PowerShell commands.
- **|re**: Full regex matching. Expensive and not supported by all backends. Use sparingly.
- **|windash**: Matches both `-` and `/` argument prefixes on Windows. `CommandLine|windash|contains: '-exec'` matches both `-exec` and `/exec`.
- **|cidr**: Network CIDR matching for IP fields. `DestinationIp|cidr: '10.0.0.0/8'` matches the entire private range.

## Field Controllability by Log Source

These fields are ATTACKER-CONTROLLABLE (values set by the attacker's actions):

**process_creation:**
- CommandLine, Image, ParentImage, ParentCommandLine, CurrentDirectory, User
- OriginalFileName is embedded in PE but can be set at compile time

**file_event:**
- TargetFilename (attacker chooses file path/name), Image (which process writes)

**registry_set/add:**
- TargetObject (registry path — partially controllable), Details (value data)

**network_connection:**
- DestinationHostname, DestinationIp, DestinationPort (attacker controls their infra)

**dns_query:**
- QueryName (attacker controls their domains)

## Fields that are NOT directly controllable

- EventID (system-generated), Provider_Name, LogonType (system-determined)
- Hashes (SHA256/MD5/IMPHASH — attacker can change by recompilation)
- IntegrityLevel (system-enforced, but attacker with admin can elevate)

## Modifier Pitfalls

- **|contains without |all**: OR-matching — ANY value matches (usually intended)
- **|contains|all**: AND-matching — ALL values must appear (easy to fragment)
- **|endswith on paths**: `|endswith: '\cmd.exe'` catches renames but misses copies to different names
- **Exact match (no modifier)**: Extremely fragile — case-sensitive, full-string match
- **|re**: Powerful but expensive; patterns can still be bypassed if not anchored
- **Missing |base64/|utf16**: Rules matching plaintext miss encoded variants
- **|windash**: Normalizes -/ for arguments but doesn't help with other obfuscation

## Common Condition Logic Traps

### AND vs OR in Selections

Multiple values under a single field use **OR** logic by default:
```yaml
selection:
    CommandLine|contains:
        - 'mimikatz'
        - 'sekurlsa'
```
This matches if EITHER substring appears. To require BOTH, use `|all` modifier or separate selections with `condition: selection1 and selection2`.

Multiple fields within one selection use **AND** logic:
```yaml
selection:
    Image|endswith: '\powershell.exe'
    CommandLine|contains: '-enc'
```
This requires BOTH conditions. A common bug is placing unrelated OR conditions under one selection, inadvertently requiring all to match.

### Filter Misuse

- `condition: selection and not filter` -- correct single filter exclusion.
- `condition: selection and not 1 of filter*` -- correctly excludes if ANY filter matches (OR exclusion).
- `condition: selection and not all of filter*` -- dangerous: only excludes when ALL filters match simultaneously. Rarely intended.
- Filters referencing fields absent from certain log sources silently pass through (no match = no filter = alert fires unexpectedly, or never fires depending on logic).

### 1-of-them vs all-of-them

- `1 of them` triggers if any named selection matches (broad, higher recall).
- `all of them` triggers only when every selection matches (narrow, higher precision). Including filters in `them` when using `all of them` is a logic bug since filters are meant to exclude.
- **selection and not filter**: If filter uses attacker-controllable fields, attacker can inject filter values to bypass (ADE4-02 Conjunction Inversion)
- **1 of selection_***: OR across multiple selections — adding new evasion variant means finding ANY alternative
- **all of selection_***: AND across multiple selections — attacker must satisfy ALL (harder to bypass, but each individual selection may have ADE1/ADE2 bugs)
- **Nested NOT**: Multiple NOT clauses can interact unexpectedly (De Morgan's Laws)
- **filter before selection**: The condition order matters — `selection and not filter` vs `not filter and selection` are logically equivalent but some engines may short-circuit differently

## Field Scope Issues

Fields available differ by log source. Common mismatches:
- **Process creation** (Sysmon EID 1, Security 4688): `CommandLine`, `Image`, `ParentImage`, `User`, `Hashes`, `OriginalFileName`.
- **PowerShell ScriptBlock** (EID 4104): `ScriptBlockText`, `ScriptBlockId`, `Path`. No `CommandLine` or `Image`.
- **Network connection** (Sysmon EID 3): `DestinationIp`, `DestinationPort`, `Image`. No `CommandLine`.
- A rule using `CommandLine` in a PowerShell ScriptBlock log source silently matches nothing.

## Common Rule Authoring Mistakes

- Using exact match when `|contains` is needed (misses substrings)
- Using `|contains` when `|endswith` is needed (matches too broadly)
- Forgetting case sensitivity (SIGMA is case-insensitive by spec, but backends vary)
- AND-joining CommandLine substrings (fragmented across events)
- Filtering on User field without considering service accounts