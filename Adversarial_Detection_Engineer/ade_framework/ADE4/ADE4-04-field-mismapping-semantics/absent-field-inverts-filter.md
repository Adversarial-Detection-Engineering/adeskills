---
id: ADE4-006
title: "Absent Field Inverts a Filter Clause"
ade_category: ADE4
ade_subcategory: ADE4-04
mitre_attack: N/A (logic/telemetry flaw, not an attack technique)
platform: Sigma / SIEM (backend- and source-dependent)
testable: logic-analysis
---

# Absent Field Inverts a Filter Clause

## Summary

The dangerous cousin of the plain absent-field bug ([unavailable-field.md](unavailable-field.md)). When an absent field appears inside a **negated filter** — the `not filter` half of a `selection and not filter` rule — its `null` value doesn't merely zero the rule, it can *flip the rule's outcome*. Depending on how the backend evaluates `field != value` against a missing field, the exclusion either swallows every true positive (false negatives) or disables itself and floods the analyst (false positives). Either way the author's intent is inverted, and which way it breaks depends on the backend's null semantics — so the same Sigma source behaves differently across SIEMs.

## ADE Classification

**Category:** ADE4 — Logic Manipulation
**Subcategory:** ADE4-04 — Field Mismapping & Semantics
**Core principle:** `NOT (null == value)` is not the same across backends. Some evaluate a comparison against a missing field as `false` (so `not false → true`, exclusion never applies), some as `null`/unknown (three-valued logic drops the row), and some treat the absent field as a match. The rule author reasoned in two-valued Boolean logic; the backend runs three-valued logic over possibly-missing fields. This is where ADE4-04 (field semantics) meets ADE4-01 (gate inversion): the negation the author trusted is decided by null-handling, not by data.

## The Technique

### The pattern that breaks

```yaml
detection:
    selection:
        Image|endswith: '\rundll32.exe'
    filter:
        ParentImage|endswith: '\explorer.exe'   # "ignore rundll32 launched by Explorer"
    condition: selection and not filter
```

Intent: alert on `rundll32.exe` *unless* its parent is `explorer.exe` (assumed benign). Now run it where `ParentImage` is **absent** — e.g. the event arrives without parent context, or a source/config that doesn't populate it (**#23**), or a backend that renamed it so the mapping resolves to `null`.

### Two inversion modes, by backend null-handling

| Backend evaluates `ParentImage|endswith '\explorer.exe'` on a missing field as… | `filter` | `not filter` | `selection and not filter` | Effect |
|---|---|---|---|---|
| `false` (no match on null) | false | **true** | fires whenever `selection` matches | Exclusion silently disabled → **false positives / noise**, analysts mute the rule |
| `null` → row dropped (three-valued) | null | null | **null → excluded** | Exclusion swallows everything → **false negatives**, rule never fires |
| absent treated as empty string that "matches" a broad pattern | true | false | never fires | **false negatives** |

The author validated the rule on Sysmon (parent populated, behaves as intended) and shipped it. On a segment where the field is absent, the *same YAML* inverts — and the direction differs per backend, so a multi-SIEM org gets both failure modes from one rule.

### Why an attacker cares

Where the flip yields false negatives, the attacker's job is done for them by the telemetry gap. Where the flip merely disables the exclusion, the resulting noise gets the rule tuned down or off — a slower path to the same blind spot. And an attacker who *can* influence the filtered field (poisoning `ParentImage`-adjacent context, or ensuring the event lacks parent context) is doing ADE4-01 gate inversion through the ADE4-04 door.

## Logic Analysis

**Vulnerable rule** (as above) — the exclusion depends on a field that may be absent.

**Hardened rule** — make the filter robust to a missing field so absence can never satisfy or void the exclusion:

```yaml
title: Suspicious rundll32 (Hardened)
status: test
logsource:
    category: process_creation
    product: windows
    service: sysmon                     # pin a source that populates ParentImage
detection:
    selection:
        Image|endswith: '\rundll32.exe'
    # Only exclude when the parent field is BOTH present AND the benign value.
    filter_benign_parent:
        ParentImage|endswith: '\explorer.exe'
    filter_parent_present:
        ParentImage|exists: true        # pySigma |exists guards the negation
    condition: selection and not (filter_benign_parent and filter_parent_present)
falsepositives:
    - rundll32 genuinely launched by explorer.exe (user double-click)
level: medium
```

Now the exclusion applies only when `ParentImage` is present *and* equals the benign value; a missing field can neither trigger nor void it. Backends without an `|exists` equivalent should express the same guard explicitly (e.g. `ParentImage != "" and ParentImage endswith ...`) in the transpiled query, or pin `service:` to a source that always populates the field.

**General rules for negated filters:**

1. Never negate a field that can be absent without also asserting its presence.
2. Pin `logsource.service` so the field's availability is known, not assumed.
3. Inspect the **transpiled** query's null-handling on each target backend — do not trust that `not filter` means what it reads.
4. Prefer excluding on stable, always-present fields (event ID, product-guaranteed fields) over optional ones.

## Detection Layers (auditing the rule, not an attack)

| Audit method | Catches? | How |
|---|---|---|
| Truth-table over `{field present, field absent} × backend null-semantics` | Yes | Enumerate all four rows above for each target SIEM |
| Field-population probe on the filtered field | Yes | If `ParentImage` is ever `null` on a target segment, the negation is at risk |
| Transpiled-query null-handling review | Yes | Read how the backend compiles `not (field endswith …)` for a missing field |
| `|exists` / presence guard on every negated optional field | Prevents | Absence can no longer flip the outcome |
| Pin `service:` + collection requirement | Prevents | Removes the availability ambiguity |
| A/B replay: benign-parent event AND parent-absent event | Yes | Confirms the rule fires on the malicious case and suppresses only the intended benign one |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) **#23** (Sysmon config decides whether `ParentImage` and friends are emitted) and **#14** (source-dependent field availability for command-line/parent context).
- This technique is the intersection of [ADE4-01 Gate Inversion](../ADE4-01-gate-inversion/gate-inversion.md) (negation on manipulable/absent input) and ADE4-04 (field semantics); cross-reference both when auditing exclusion-heavy rules.
- Full field catalog: [`bug_patterns/sigma_field_semantics.md`](../../../bug_patterns/sigma_field_semantics.md).
- Three-valued logic (`true`/`false`/`null`) is the root cause: authors reason in two-valued Boolean, backends run SQL-style three-valued logic where `null` propagates. `NOT null = null`, not `true`.
- The failure is backend-divergent: a rule can be correct on Splunk (PCRE, null→false) and inverted on an Elastic/RE2 pipeline that drops null rows. Validate per backend, not once.

## References

- [SigmaHQ — Conditions and the `exists` modifier](https://sigmahq.io/docs/basics/modifiers.html)
- [SigmaHQ — Writing rules & filters](https://sigmahq.io/docs/basics/rules.html)
- [Three-valued logic and NULL comparison (SQL semantics)](https://en.wikipedia.org/wiki/Three-valued_logic)
