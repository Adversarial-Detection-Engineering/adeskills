---
id: ADE3-005
title: Correlation Window Evasion
ade_category: ADE3
ade_subcategory: ADE3-03
mitre_attack:
  - T1110 (Brute Force)
  - T1114 (Email Collection)
platform: Cross-platform
testable: logic-analysis
---

# Correlation Window Evasion

## Summary

A detection rule aggregates or correlates events within a **fixed time window** — a `queryPeriod`, a sequence `maxspan`, a rate threshold per interval. Because the window is a static, knowable parameter, the attacker spaces actions to fall outside it ("low and slow"), or delays a correlated step past `maxspan`, so the events are logged individually but never satisfy the time-bounded condition together.

Grounded in real findings: the Sentinel analytic **"Brute force attack against user credentials"** (ADE3-03) requires ≥10 failures within a 20-minute `queryPeriod` — 9 failures, wait 21 minutes, repeat never trips it. The Elastic **"Collection Email Outlook Mailbox via COM"** rule (DLE-2026-00009) couples a short sequence `maxspan` with file-age and immediate process-to-process timing, all of which a `sleep` defeats.

## ADE Classification

**Category:** ADE3 — Context Development
**Subcategory:** ADE3-03 — Timing and Scheduling
**Core principle:** the time window is visible to the attacker and cheap to wait out. Spacing actions beyond the aggregation/correlation window keeps every individual event in-scope while ensuring no window ever accumulates enough to alert.

## The Technique

Three concrete patterns from the corpus:

1. **Threshold-per-window (slow brute force).** Rule: `FailureCount >= 10` within a 20-minute window. Bypass: 9 failures, sleep 21 minutes, 9 more — no rolling 20-minute window ever reaches 10, and the eventual success plus distributed failures never coincide.
2. **Sequence `maxspan` delay.** Rule: EQL sequence requiring step B within N seconds of step A. Bypass: insert a `sleep` longer than `maxspan` between the parent action and the COM/child action; the sequence expires and no correlated alert is produced.
3. **Freshness/age assumptions.** Rule: only correlate if a file was created within a short window before use, or if a *new* process is spawned. Bypass: wait out the file-age check, or reuse an existing (single-instance) COM server so no new process-creation event anchors the sequence (this last part also overlaps [ADE3-02 Aggregation Hijacking](../ADE3-02-aggregation-hijacking/baseline-and-threshold-hijacking.md)).

The unifying weakness: correctness of the rule depends on the attacker *cooperating* with the timing assumption.

## Vulnerable Rule

```yaml
# Paraphrased Sentinel brute-force analytic
queryPeriod: 20m
queryFrequency: 20m
query: |
    imAuthentication
    | where EventResult == "Failure"
    | summarize FailureCount = count(), SuccessCount = countif(EventResult == "Success")
        by TargetUserId, bin(TimeGenerated, 20m)
    | where FailureCount >= 10 and SuccessCount >= 1
```

### Why it misses

The fixed 20-minute `bin`/`queryPeriod` means an attacker who keeps each 20-minute window under 10 failures never satisfies `FailureCount >= 10`. A slow brute force spread over hours is fully in-scope yet invisible.

## Hardened Rule

```yaml
# Longer look-back + sliding evaluation + corroborating signal
queryPeriod: 24h
queryFrequency: 1h
query: |
    imAuthentication
    | where EventResult == "Failure"
    | summarize FailureCount = count(), SuccessCount = countif(EventResult == "Success"),
        window = make_set(bin(TimeGenerated, 1h))
        by TargetUserId
    | where FailureCount >= 10 and SuccessCount >= 1
    // corroborate with distinct source IPs / impossible travel to catch low-and-slow
```

For sequence rules: widen `maxspan` to the realistic dwell time, or decouple the steps into separate stateful detections joined on a stable key so a `sleep` between them does not expire the correlation.

### Why the hardened rule works

A longer look-back with a sliding evaluation removes the "reset every 20 minutes" gap, and a corroborating signal (source-IP spread, impossible travel) catches distributed attempts that any single time bucket would miss. Widening or decoupling `maxspan` removes the trivial `sleep` bypass.

## Detection Layers

| Audit method | Catches window evasion? | How |
|---|---|---|
| Longer look-back / sliding window | Yes | No fixed bucket to stay under |
| Corroborating orthogonal signal | Yes | Source-IP spread, impossible travel, volume across users |
| Realistic `maxspan` or decoupled stateful steps | Yes | A `sleep` no longer expires the sequence |
| Avoid freshness/"new process" anchors | Partial | Reused COM/long-lived processes still correlate |
| Emulate low-and-slow | Yes | Reproduce N-1-per-window / sleep-past-maxspan; confirm coverage |
| Document the window as a known limit | Prevents surprise | If a tight window is intentional (FP control), record the accepted risk |

## Implementation Nuances

- See [Implementation Nuances #6](../../../bug_patterns/logging_assumption_errors.md) (correlation timeframes — too short misses `sleep`-spaced steps, too long inflates FPs) and #22 (time zones / clock skew — normalize to UTC and leave slack, or windows drop legitimately-related events).
- ADE3-03 stacks with [ADE3-02](../ADE3-02-aggregation-hijacking/baseline-and-threshold-hijacking.md) (threshold-per-window is both a timing and an aggregation bug) and [ADE3-01 Process Cloning](../ADE3-01-process-cloning/) (a sequence anchored on `process.name` fails on rename regardless of timing) — the Outlook COM rule exhibited all three, a stacked guaranteed-false-negative.
- Tightening a window to reduce false positives directly widens the low-and-slow gap; this is a genuine trade-off to document, not always a defect.

## References

- [MITRE ATT&CK T1110 — Brute Force](https://attack.mitre.org/techniques/T1110/)
- [MITRE ATT&CK T1114 — Email Collection](https://attack.mitre.org/techniques/T1114/)
- [Elastic detection-rules — Collection Email Outlook Mailbox via COM](https://github.com/elastic/detection-rules/blob/main/rules/windows/collection_email_outlook_mailbox_via_com.toml)
- [Microsoft Sentinel — Brute force attack against user credentials (ASIM)](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Microsoft%20Entra%20ID/Analytic%20Rules/imAuthBruteForce.yaml)
