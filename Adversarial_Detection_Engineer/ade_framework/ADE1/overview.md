# ADE1: Reformatting in Actions

Reformatting in Actions occurs when a detection rule relies on **string-match conditions**, and an attacker manipulates the collected value — through obfuscation, encoding, concatenation, or character insertion — to produce a semantically identical command that no longer matches the rule's pattern. This has been exploited by threat actors for years and still appears in modern SIEM rules.

## Core Insight

Any rule that pattern-matches an attacker-controllable string field (`CommandLine`, `ScriptBlockText`, `TargetFilename`, registry keys/values, URLs, process names) is vulnerable to reformatting unless it accounts for *all* parser-accepted variations. Detection logic assumes attackers use exact, unmodified strings; in reality most string indicators are trivially altered while the OS/interpreter still executes the same thing.

## Why It's a Bug

The rule author assumes a canonical spelling of the indicator. The parser accepts many spellings. Common transforms that break a literal match while preserving execution:

- String concatenation and variable substitution
- Encoding / escaping (Base64, hex, URL, char codes)
- Case manipulation
- Whitespace insertion and token splitting
- Escape-character insertion (carets, backticks, quotes)

## Vulnerable Rule Patterns

String-matching operators that create risk when applied to attacker-controlled fields:

- `contains: 'exact_string'`
- `startswith: 'prefix'` / `endswith: 'suffix'`
- Exact equality: `field: 'value'`

## Subcategories

### ADE1-01: Substring Manipulation
Detection logic relies on substring matches; the attacker alters or obfuscates the input so the hypothesis conditions are not met, producing a false negative. Applies to command-line arguments, method/function names, filenames/paths, registry keys/values, and any attacker-controlled string field.

### ADE1-02: Normalization Asymmetry
A mismatch between how the logging/normalization pipeline records a value and how the OS or interpreter actually parses it. The rule matches the normalized form while the parser executes a different-looking-but-equivalent form (e.g., short names, forward slashes, non-breaking whitespace, Unicode homoglyphs). This also covers **correlation joins keyed on an attacker-mutable value**: when a rule joins two records on a key the attacker can perturb (or that the two sources normalize differently), the join key fails to line up and the correlated alert never fires even though both events were logged. See `../../bug_patterns/cmdline_obfuscation.md` for the fuller catalog.

## Techniques in This Category

Grouped by subcategory — see each subcategory's README for its definition and detection guidance.

### [ADE1-01 Substring Manipulation](ADE1-01-substring-manipulation/)

| Technique | Shell | Mechanism | From |
|-----------|-------|-----------|------|
| [Parameter Variation](ADE1-01-substring-manipulation/parameter-variation.md) | PowerShell | 24+ flag prefix abbreviations for -EncodedCommand | DEaTHCon Demo 01 |
| [Whitespace Manipulation](ADE1-01-substring-manipulation/whitespace-manipulation.md) | cmd.exe | Extra spaces between tokens break literal substring matches | DEaTHCon Demo 03 |
| [Boolean Replacement](ADE1-01-substring-manipulation/boolean-replacement.md) | PowerShell | Infinite boolean syntax variations for switch parameters | DEaTHCon Demo 04 |
| [Quote Manipulation](ADE1-01-substring-manipulation/quote-manipulation.md) | cmd.exe | Mid-token quote splicing stripped by parser | DEaTHCon Demo 05 |
| [Delimiter Manipulation](ADE1-01-substring-manipulation/delimiter-manipulation.md) | cmd/PS | Multiple command-sequencing operators | DEaTHCon Demo 06 |
| [Obfuscation](ADE1-01-substring-manipulation/obfuscation.md) | PowerShell | String concat, char codes, format strings, base64, encryption | DEaTHCon Demo 08 |
| [Caret Insertion](ADE1-01-substring-manipulation/caret-insertion.md) | cmd.exe | Carets stripped at parse time | New |
| [Environment Variable Splicing](ADE1-01-substring-manipulation/env-variable-splicing.md) | cmd.exe | Substring extraction from env vars constructs commands | New |
| [PowerShell Tick Escaping](ADE1-01-substring-manipulation/powershell-tick-escaping.md) | PowerShell | Backtick escape char stripped for non-special chars | New |

### [ADE1-02 Normalization Asymmetry](ADE1-02-normalization-asymmetry/)

| Technique | Shell | Mechanism | From |
|-----------|-------|-----------|------|
| [NTFS Short Names](ADE1-02-normalization-asymmetry/ntfs-short-names.md) | Windows | 8.3 short names bypass path-based rules | New |

## Detection Strategy

1. **Regex tolerance** — patterns that absorb optional junk characters between meaningful tokens
2. **Behavioral detection** — detect the outcome (network connection, file write, registry change), not the command string
3. **Script Block Logging (EID 4104)** — PowerShell deobfuscates before logging (catches ticks, concatenation, format strings)
4. **AMSI** — sees the deobfuscated form after runtime resolution
5. **Image/OriginalFileName anchoring** — binary identity is unaffected by command-line reformatting
6. **Sigma encoding modifiers** — `|base64`, `|base64offset`, `|windash`, `|re` to match encoded/prefixed variants

## Testing Your Rules

- Does the rule rely on exact string matches in attacker-controlled fields?
- Can the matched string be split across variables or concatenated?
- Are there encoding schemes (Base64, hex, URL) that bypass the match?
- Would case changes or whitespace insertion break detection?

If "yes" to any, the rule likely has an ADE1 vulnerability.

## Related Categories

- **ADE2 (Omit Alternatives)** — alternative methods/binaries also use different strings
- **ADE4 (Logic Manipulation)** — string manipulation used to flip negation conditions

## Reference Catalogs

- `../../bug_patterns/cmdline_obfuscation.md` — cmd.exe / bash obfuscation catalog
- `../../bug_patterns/powershell_evasion.md` — PowerShell string-construction and encoding evasion
