# ADE3-06 · Limit Saturation

Parent category: [ADE3 — Context Development](../overview.md)

Detection relies on a query operator that holds a **bounded working set** — a join or subsearch, a group table, a sort, or a per-key match count — while assuming the operator evaluates every record in scope. When the volume reaching that operator exceeds its limit, the engine truncates the set, and the in-scope record is discarded before the rule's conditions ever evaluate it.

**Why it's a bug:** truncation is not an error. The search completes, at most a warning banner records it, and a scheduled rule reports "no results." The limit is spent on everything that reaches the operator, not on the records the rule cares about, so a bounded side filtered only by event type spends its budget on noise. Volume grows on its own, so a rule validated on a small tenant degrades silently as the estate grows — and an attacker who can generate records on the bounded side can push it past the limit on purpose.

## Techniques

- [Join, Subsearch, and Group-Limit Saturation](join-and-group-limit-saturation.md)

## See also

- Both ADE3-06 and [ADE1-02 Normalization Asymmetry](../../ADE1/ADE1-02-normalization-asymmetry/README.md) produce empty joins: ADE1-02 because the keys differ, ADE3-06 because the matching row was truncated. Constrain the bounded side to one host and re-run to tell them apart.
- [ADE3-02 Aggregation Hijacking](../ADE3-02-aggregation-hijacking/README.md) manipulates the *value* an aggregation computes; ADE3-06 decides whether the record is *in* the aggregation at all.
- [ADE4-04 Unavailable Field](../../ADE4/ADE4-04-field-mismapping-semantics/unavailable-field.md) covers telemetry ceilings (a command line truncated at collection); ADE3-06 is a query-engine ceiling on rows, groups, or keys.
- Canonical definition: [ADE Framework — ADE3-06](https://github.com/Adversarial-Detection-Engineering/Adversarial-Detection-Engineering-Framework/blob/main/docs/taxonomy/ade3-context-development.md#ade3-06-context-development---limit-saturation).
