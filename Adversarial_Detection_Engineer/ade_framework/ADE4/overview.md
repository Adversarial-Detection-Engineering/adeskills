# ADE4: Logic Manipulation

Logic Manipulation occurs when an attacker analyzes detection logic as **Boolean algebra** and manipulates inputs or filters to invert, bypass, or neutralize the rule outcome — or when the rule's own logic is simply wrong. Every logic-manipulation bypass requires another bug to invert or skip the logic, so ADE4 commonly appears alongside a bug from another category.

## Core Insight

Complex filter conditions (multiple NOTs, ANDs across controllable fields, exclusion lists) are where logic bugs hide. The author intended one thing; the Boolean expression implements another.

## Subcategories

### ADE4-01: Gate Inversion
A NOT clause (negation) checks values the attacker can make appear through **poisoned data** inserted before the record is generated. Often in rule exceptions/filters. Frequently the author didn't consider that chained negations simplify via [De Morgan's Laws](https://en.wikipedia.org/wiki/De_Morgan%27s_laws):

```
NOT A AND NOT B  ⟺  NOT (A OR B)
NOT A OR  NOT B  ⟺  NOT (A AND B)
```

If the attacker can insert `value1` OR `value2` into a `not (filter1 or filter2)` condition, the whole rule goes False.

### ADE4-02: Conjunction Inversion
An AND condition checks a value the attacker can manipulate through poisoned data before record generation. Example: filling an array so a non-empty check evaluates as benign, or adding a "safe" sentinel string to a payload to satisfy `... AND not (field contains "safe_string")`.

### ADE4-03: Incorrect Expression
The interpreted query rarely produces hits by construction — incorrect choices between negations, conjunctions, or disjunctions. Ineffective *by design*, not by attacker action. Classic mistakes: AND where OR is required (e.g., requiring `curl` AND `wget` in one command line), mutually exclusive conditions, or negating privileged accounts in non-privesc rules. Root cause is usually lack of adversarial emulation / no test data before deployment.

### ADE4-04: Field Mismapping & Semantics
The rule references fields incorrectly (wrong name, unavailable field, or misunderstood semantics) across log sources and Sigma backends, so it silently fails to match. Examples: `CommandLine` vs `commandline`/`command_line` across backends; `OriginalFileName` present only in Sysmon EID 1; `ParentImage` absent in PowerShell ScriptBlock logs (EID 4104); `SubjectUserName` vs `TargetUserName` semantics in Windows Security logs. A `selection and not filter` rule where `filter` references an absent field can invert to a false positive/negative. Full catalog: `../../bug_patterns/sigma_field_semantics.md`.

## Techniques in This Category

Grouped by subcategory — see each subcategory's README for its definition and detection guidance.

### [ADE4-01 Gate Inversion](ADE4-01-gate-inversion/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Gate Inversion](ADE4-01-gate-inversion/gate-inversion.md) | De Morgan's law reveals gaps in NOT chains | Logic analysis | ADE taxonomy |

### [ADE4-02 Conjunction Inversion](ADE4-02-conjunction-inversion/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Conjunction Inversion](ADE4-02-conjunction-inversion/conjunction-inversion.md) | Attacker injects sentinel values to trigger exclusion filters | Logic analysis | ADE taxonomy |

### [ADE4-03 Incorrect Expression](ADE4-03-incorrect-expression/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [AND vs OR Confusion](ADE4-03-incorrect-expression/and-vs-or-confusion.md) | Rule ANDs alternatives that should be ORed | Logic analysis | ADE taxonomy |

### [ADE4-04 Field Mismapping & Semantics](ADE4-04-field-mismapping-semantics/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Field-Name Mismatch Across Backends](ADE4-04-field-mismapping-semantics/field-name-mismatch.md) | Correct field, wrong spelling/case for the target backend — transpiles clean, matches nothing | Logic analysis | ADE taxonomy + Nuances #5/#14/#23 |
| [Unavailable Field — Silent Match Failure](ADE4-04-field-mismapping-semantics/unavailable-field.md) | Field not populated in the source that reaches the rule (Sysmon-only fields, 4688 auditing off, truncation) | Logic analysis | ADE taxonomy + Nuances #14/#18/#23 |
| [Absent Field Inverts a Filter Clause](ADE4-04-field-mismapping-semantics/absent-field-inverts-filter.md) | Missing field inside `not filter` flips the outcome via backend null-handling | Logic analysis | ADE taxonomy + Nuances #14/#23 |

Full field catalog: `../../bug_patterns/sigma_field_semantics.md`.

## Detection Strategy

1. **Truth table review** — enumerate all input combinations for the detection condition
2. **Filter field audit** — check whether any filter field is attacker-controllable
3. **De Morgan's simplification** — simplify complex NOT chains to reveal logical equivalence
4. **Adversarial filter injection** — test whether an attacker can deliberately trigger exclusion conditions
5. **Rule linting** — automated checks for common mistakes (AND on alternatives, NOT on controllable fields)
6. **Field-availability validation** — verify each referenced field exists, with the intended semantics, in every targeted log source

## Risk: Negating Privileged Accounts

Many rules negate privileged accounts (`root`, `SYSTEM`, `Administrator`) to cut noise. This only makes sense for **privilege-escalation** detections. For initial access, persistence, lateral movement, defense evasion, credential access, and collection/exfiltration, privileged-account activity **must** be monitored — unauthenticated RCE routinely lands directly as root/SYSTEM:

- [CVE-2025-20337 — Cisco ISE](https://nvd.nist.gov/vuln/detail/CVE-2025-20337): unauth RCE as root, exploited by APTs
- [CVE-2025-59287 — Microsoft WSUS](https://nvd.nist.gov/vuln/detail/CVE-2025-59287): unauth RCE with SYSTEM-equivalent privileges
- [CVE-2024-6387 — OpenSSH "regreSSHion"](https://nvd.nist.gov/vuln/detail/cve-2024-6387): unauth RCE to root shell

Excluding root/SYSTEM only makes sense when the logic itself expresses escalation, e.g. `user.previous != "root" and user.current == "root"`.

## Testing Your Rules

- **Gate Inversion:** Multiple `not` conditions chained with AND that simplify via De Morgan's? Negations on attacker-controlled fields?
- **Conjunction Inversion:** AND conditions on mutable fields the attacker could satisfy to flip to False?
- **Incorrect Expression:** Tested with real attack samples? AND used where OR is needed? Privileged accounts excluded in non-privesc rules?
- **Field Semantics:** Does each field exist — with the intended meaning — in every targeted source and backend?

## Related Categories

- **ADE1 (Substring Manipulation)** — string manipulation used to flip negations
- **ADE3 (Aggregation Hijacking)** — manipulated aggregations flip Boolean gates
- **ADE2 (Omit Alternatives)** — logic errors compound with missing alternatives
