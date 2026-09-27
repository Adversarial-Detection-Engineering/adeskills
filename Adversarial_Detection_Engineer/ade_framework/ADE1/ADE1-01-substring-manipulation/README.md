# ADE1-01 · Substring Manipulation

Parent category: [ADE1 — Reformatting in Actions](../overview.md)

Detection logic relies on substring matches against an attacker-controllable string field, and the attacker alters or obfuscates the input so the match fails — a false negative.

**Why it's a bug:** the author assumes a canonical spelling of the indicator; the parser accepts many. Concatenation, encoding (Base64/hex/char codes), case changes, whitespace insertion, escape characters, and token splitting all preserve execution while breaking a literal match.

**Applies to:** `CommandLine`, `ScriptBlockText`, process/method names, filenames/paths, registry keys/values, URLs — any attacker-controlled string field.

## Techniques

- [Parameter Variation](parameter-variation.md)
- [Whitespace Manipulation](whitespace-manipulation.md)
- [Boolean Replacement](boolean-replacement.md)
- [Quote Manipulation](quote-manipulation.md)
- [Delimiter Manipulation](delimiter-manipulation.md)
- [Obfuscation](obfuscation.md)
- [Caret Insertion](caret-insertion.md)
- [Environment Variable Splicing](env-variable-splicing.md)
- [PowerShell Tick Escaping](powershell-tick-escaping.md)

## See also

- Implementation Nuances #2, #7, #9 — [logging_assumption_errors.md](../../../bug_patterns/logging_assumption_errors.md)
- [cmdline_obfuscation.md](../../../bug_patterns/cmdline_obfuscation.md) · [powershell_evasion.md](../../../bug_patterns/powershell_evasion.md)
