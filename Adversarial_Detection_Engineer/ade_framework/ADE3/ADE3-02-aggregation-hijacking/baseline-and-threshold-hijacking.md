---
id: ADE3-004
title: Baseline and Threshold Hijacking
ade_category: ADE3
ade_subcategory: ADE3-02
mitre_attack:
  - T1219 (Remote Access Software)
  - T1105 (Ingress Tool Transfer)
platform: Cross-platform
testable: logic-analysis
---

# Baseline and Threshold Hijacking

## Summary

A detection rule keys on an **aggregate the attacker can observe or influence** — a "new terms"/first-seen baseline, a count/rate threshold, or a UEBA entity grouping. Because the aggregation is shaped by prior activity, the attacker either matches an existing baseline, seeds a benign first occurrence, or stays under the threshold, so in-scope activity never trips the rule.

Grounded in real findings (DLE-2026-00006/00007/00013): several Elastic "New Terms" rules aggregate on `host.id` alone — "AWS CLI Command with Custom Endpoint URL" and "First Time Seen Commonly Abused Remote Access Tool Execution." If the same behaviour already occurred on the host inside the history window, later executions merge into the baseline and never alert.

## ADE Classification

**Category:** ADE3 — Context Development
**Subcategory:** ADE3-02 — Aggregation Hijacking
**Core principle:** the aggregation baseline is visible to, and shapeable by, the attacker. Recon the current baseline → precondition the buckets (or stay under the count) → execute within the established baseline. The primary action is unchanged; the surrounding *context* is manipulated.

## The Technique

Three flavours, all seen in the corpus:

1. **New-terms / first-seen keyed too narrowly.** A rule fires only the *first* time a term (e.g. AWS CLI `--endpoint-url`, or a RAT binary name) is seen per `host.id` within an N-day window. Bypass:
   - **Baseline match** — if the behaviour already happened on that host in-window (recon confirms), subsequent runs are "not new" and are suppressed.
   - **Baseline seeding** — deliberately generate one benign first occurrence so the malicious repeat is aggregated into the existing term.
2. **Threshold / count evasion.** A rule fires at `count >= N`; the attacker performs `N-1` and stops, or spreads events so no bucket reaches `N` (overlaps with [ADE3-03 Timing](../ADE3-03-timing-and-scheduling/window-evasion.md)).
3. **Exclusion-baseline abuse.** A rule *excludes* a "known-noise" bucket (e.g. filenames > 30 chars as legitimate third-party software); the attacker adopts that bucket (a long filename) to land inside the excluded baseline — this is also a [gate inversion, ADE4-01](../../ADE4/ADE4-01-gate-inversion/README.md).

The unifying weakness: the aggregation key is too coarse (`host.id` only, no `user.name`/args/hash) or the threshold/exclusion is a static proxy the attacker can satisfy on purpose.

## Vulnerable Rule

```toml
# Paraphrased Elastic "New Terms" rule
type = "new_terms"
query = '''
event.category:process and process.name:"aws" and process.args:"--endpoint-url"
'''
[rule.new_terms]
field = "new_terms_fields"
value = ["host.id"]           # aggregation keyed on host.id ALONE
history_window_start = "now-10d"
```

### Why it misses

Alerting only on the first `host.id`-scoped occurrence means: prior in-window usage suppresses the alert, and a single benign seed run poisons the baseline so the malicious repeat is never "new." No aggregation field distinguishes *who* or *how*.

## Hardened Rule

```toml
type = "new_terms"
query = '''
event.category:process and process.name:"aws" and process.args:"--endpoint-url"
'''
[rule.new_terms]
field = "new_terms_fields"
# Widen the aggregation so "newness" is meaningful and harder to pre-seed
value = ["host.id", "user.name", "process.args"]
history_window_start = "now-10d"
```

Plus, for count-based rules, evaluate the threshold over a **sliding** window and add a companion low-and-slow rule; for exclusion baselines, guard the negation so an attacker can't opt into the excluded bucket (see the ADE4-01 hardening).

### Why the hardened rule works

Adding `user.name` and `process.args` (or an executable hash) to the aggregation makes a single benign seed insufficient to cover a different identity/argument set, and makes the "first seen" genuinely represent new behaviour rather than a coarse host-level bucket the attacker can pre-fill.

## Detection Layers

| Audit method | Catches baseline/threshold hijack? | How |
|---|---|---|
| Widen aggregation keys | Yes | user + args + hash, not host alone |
| Sliding-window thresholds + low-and-slow companion | Yes | Removes the "stay under N in a fixed bucket" gap |
| Guard exclusion baselines | Yes | Attacker can't opt into the excluded bucket |
| Baseline-poisoning review | Partial | Ask "can a benign first run seed this?" for every new-terms rule |
| Emulate: seed then repeat | Yes | Reproduce a benign first occurrence, then the malicious repeat; confirm it still alerts |

## Implementation Nuances

- New-terms/UEBA "first seen" logic is only as good as its key granularity; `host.id`-only keys are the recurring anti-pattern in the corpus. See [Implementation Nuances #6](../../../bug_patterns/logging_assumption_errors.md) (correlation timeframes) and #22 (clock skew across the aggregation window).
- ADE3-02 frequently co-occurs with [ADE3-01 Process Cloning](../ADE3-01-process-cloning/) (the aggregated term is `process.name`, which a rename defeats regardless of baseline) and [ADE3-03 Timing](../ADE3-03-timing-and-scheduling/window-evasion.md).
- Exclusion-baseline abuse is the bridge to [ADE4-01 Gate Inversion](../../ADE4/ADE4-01-gate-inversion/README.md): the same long-filename move both matches an aggregation exclusion and inverts a `not` gate.

## References

- [MITRE ATT&CK T1219 — Remote Access Software](https://attack.mitre.org/techniques/T1219/)
- [MITRE ATT&CK T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Elastic detection-rules — AWS CLI Command with Custom Endpoint URL](https://github.com/elastic/detection-rules/blob/main/rules/linux/command_and_control_aws_cli_endpoint_url_used.toml)
- [Elastic detection-rules — First Time Seen Commonly Abused Remote Access Tool Execution](https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_new_terms_commonly_abused_rat_execution.toml)
