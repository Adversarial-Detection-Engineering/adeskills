# ADE3-03 · Timing and Scheduling

Parent category: [ADE3 — Context Development](../overview.md)

Detection relies on **time-based assumptions** — execution frequency, duration, inter-event timing. By spacing, batching, or scheduling actions outside rule windows (`maxspan`, file-age checks, lookback periods, rate limits) the attacker bypasses detection without changing behavior.

**Why it's a bug:** hard-coded time windows are a fixed target an attacker can simply wait out. Clock skew across hosts compounds the problem for correlation rules.

## Techniques

- [Correlation Window Evasion](window-evasion.md) — the attacker spaces actions outside a fixed `queryPeriod`/rate window, slow-and-low (worked examples: slow brute force under a 20-minute window; threshold-per-window resets).
- [Maxspan Delay, Boundary Straddling, and Beacon Jitter](maxspan-delay-and-beacon-jitter.md) — exploit *how* time is binned/sequenced: `sleep` past a sequence `maxspan`, straddle a `date_trunc` bucket edge, or jitter a beacon (documented instances: `awk`+`sleep` LoLBin egress, minute-boundary straddling, C2 jitter).

See also Implementation Nuances #6, #22 — [logging_assumption_errors.md](../../../bug_patterns/logging_assumption_errors.md).
