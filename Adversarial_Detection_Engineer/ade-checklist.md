# The ADE False-Negative Checklist

This reference expands **step 3 of the scoping process** — the four question categories you apply to every public rule you find. Their job is to surface *why a reasonable-looking rule might not fire* against an in-scope technique, so you can turn each gap into a client question and a validation objective.

> **Scope reminder.** Every question here is answered at the level of *"would this detection catch the technique, and what must be true for it to fire?"* — never *"how do we get past it?"* Describe **categories** of gap, not a specific bypass recipe, encoding, timing pattern, or tool flag chosen to defeat a named rule. If a line of reasoning starts to produce an execution step, stop and route it to the human red-team lead (SKILL.md → Guardrails).

Each rule you evaluate should get a pass through all four lenses. They are ordered from "does the rule even receive the data" outward to "is the rule tuned for this environment."

---

## 1. Data-source dependency

**Question:** What log source / sensor must be enabled and correctly configured for this rule to fire *at all*?

A detection rule is only as real as the telemetry feeding it. A rule can be perfectly written and still contribute **zero** coverage on a host where its data source isn't collected — and that failure is silent (no error, no alert, just no match).

**What to look for in the rule:**
- Its `logsource` / `data_source` / index binding — does it assume Sysmon EID 1, Security 4688, PowerShell Script Block Logging (4104), an EDR process table, a cloud audit log?
- Fields that only exist on one source — e.g. `OriginalFileName` (Sysmon only), a command line on 4688 (off by default), `ParentImage` (absent in 4104).
- Any assumption that a given event ID or field is emitted, which the deployed sensor config actually decides.

**Why it produces false negatives:** the sensor isn't deployed on that host class; the event ID is filtered out by config; the field isn't populated on the source that reaches the rule; the activity happens in a telemetry blind spot (e.g. inside WSL2, or after a PowerShell v2 downgrade removes 4104).

**Goes deeper in:** [`bug_patterns/logging_assumption_errors.md`](bug_patterns/logging_assumption_errors.md) — especially #8 (WSL2 boundary), #14 (4688 command-line auditing off by default), #15 (PS v2 downgrade), #23 (Sysmon config decides what exists); and [`ade_framework/ADE4/ADE4-04-field-mismapping-semantics/`](ade_framework/ADE4/ADE4-04-field-mismapping-semantics/README.md) for field-availability failures.

**Validation objective (phrasing):** *"Confirm whether [data source / EID / field] is actually ingested and this rule is enabled in the client's SIEM before assuming coverage for [technique]."*

**Open question for the client (phrasing):** *"Is [Sysmon EID X / command-line auditing / script block logging] enabled on the in-scope hosts?"*

---

## 2. Threshold assumptions

**Question:** Does the rule key on a count, rate, or time window that a slower or lower-volume version of the same technique would fall under?

Many rules fire only above a threshold (`> N events`), within a time window (`maxspan` / `queryPeriod`), or on a "newly seen" / baseline-relative condition. Those parameters are visible to — and shapeable by — anyone who knows the technique.

**What to look for in the rule:**
- Aggregations: `| stats count by`, `| bin`, `threshold`-type rules, `count() > N`.
- Correlation windows: `timeframe`, `maxspan`, `queryFrequency` / `queryPeriod`.
- "New terms" / "first seen" / UEBA baseline logic.

**Why it produces false negatives:** the same action performed below the count, spread past the window, or matched to an existing baseline stays under the trigger. Correlation windows that are too tight also drop legitimately-related events under clock skew.

**Goes deeper in:** [`ade_framework/ADE3/overview.md`](ade_framework/ADE3/overview.md) — Context Development, especially [`ADE3-02` aggregation hijacking](ade_framework/ADE3/ADE3-02-aggregation-hijacking/README.md) and [`ADE3-03` timing and scheduling](ade_framework/ADE3/ADE3-03-timing-and-scheduling/README.md); and [`bug_patterns/logging_assumption_errors.md`](bug_patterns/logging_assumption_errors.md) #6 (correlation timeframes) and #22 (time zones / clock skew).

**Validation objective (phrasing):** *"Validate detection coverage for [technique] under the identified threshold/window assumption — confirm whether a low-and-slow variant is still detected."*

**Open question for the client (phrasing):** *"What are the tuned thresholds and correlation windows on this rule in your environment?"* (public defaults are often re-tuned).

---

## 3. Scope assumptions

**Question:** Does the rule cover only one protocol, OS, binary, auth method, or version — leaving adjacent variants uncovered?

Rules are usually written against the one canonical form of a technique. The same objective is often reachable through an alternative that the rule never enumerated: a different LOLBin, a renamed binary, a different execution method, a different path, an equivalent-but-reformatted command line.

**What to look for in the rule:**
- Anchoring on a single `Image|endswith: '\tool.exe'` or one literal command string.
- One protocol / port / auth type where several are equivalent.
- One OS or one product version, when the environment has others in scope.
- Literal-substring matches (`|contains: 'canonical string'`) with no allowance for reformatting.

**Why it produces false negatives:** the attacker uses an in-scope alternative the rule doesn't list (ADE2), or the same command reformatted so the literal match breaks (ADE1). Both are "the rule enumerated a subset of the equivalence class."

**Goes deeper in:** [`ade_framework/ADE2/overview.md`](ade_framework/ADE2/overview.md) — Omit Alternatives (alternative binaries, methods, versions, locations, file types), with [`bug_patterns/LOLBAS-gap-analysis.md`](bug_patterns/LOLBAS-gap-analysis.md) as the worked catalog; and [`ade_framework/ADE1/overview.md`](ade_framework/ADE1/overview.md) — Reformatting in Actions.

**Validation objective (phrasing):** *"Confirm coverage extends across [the in-scope alternatives / OS versions / protocols], not just the canonical form the public rule matches."*

**Open question for the client (phrasing):** *"Which OS versions, shells, and tool variants are in scope, and does the deployed rule set cover each?"*

---

## 4. Environment drift

**Question:** Is the rule likely tuned against a baseline that doesn't match *this* client's environment?

A rule that works in the vendor's reference environment can misbehave in a specific customer's. Exclusion filters written to cut noise in one org can become blind spots in another; filters that reference fields which aren't populated here can even invert the rule.

**What to look for in the rule:**
- Exclusion filters: `and not filter`, allow-lists of "known good" paths/users/parents.
- Assumptions about what is "normal" (which admin tools, which service accounts, which parent processes are benign).
- Negations on attacker-influenceable or possibly-absent fields.

**Why it produces false negatives:** an exclusion the customer inherited swallows the true positive; a filter field is absent on the customer's telemetry and flips the rule's outcome via null-handling; the "normal" baseline the rule assumes doesn't hold here.

**Goes deeper in:** [`ade_framework/ADE4/overview.md`](ade_framework/ADE4/overview.md) — Logic Manipulation, especially [`ADE4-01` gate inversion](ade_framework/ADE4/ADE4-01-gate-inversion/README.md) and [`ADE4-04` field mismapping / absent-field filter inversion](ade_framework/ADE4/ADE4-04-field-mismapping-semantics/absent-field-inverts-filter.md); and [`bug_patterns/logging_assumption_errors.md`](bug_patterns/logging_assumption_errors.md) #23 (config-driven coverage).

**Validation objective (phrasing):** *"Review the rule's exclusion filters against this environment's baseline; confirm no in-scope activity is inadvertently allow-listed."*

**Open question for the client (phrasing):** *"What local tuning / exclusions have been applied to this rule, and against what baseline?"*

---

## Applying the checklist

For each in-scope technique + public rule, produce one worksheet row (per SKILL.md → Output format) capturing, at minimum, the **data-source dependency** and the single most material gap among lenses 2–4, phrased as an **open question for the client** and a **suggested test-plan objective**. If a rule looks solid on all four lenses, say so — "no obvious category gap; recommend confirming the rule is enabled" is a valid, useful finding.

Keep every entry at the reasoning level. The worksheet feeds a human-authored test plan and RoE; it is not itself an execution plan.
