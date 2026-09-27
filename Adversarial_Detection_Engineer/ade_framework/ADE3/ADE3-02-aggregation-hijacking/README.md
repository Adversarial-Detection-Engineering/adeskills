# ADE3-02 · Aggregation Hijacking

Parent category: [ADE3 — Context Development](../overview.md)

Detection relies on **aggregated values** the attacker can influence or precondition: threshold rules ("alert if >10" → stay at 9), "newly seen"/new-terms logic (run a benign version first), UEBA entity grouping (match an existing baseline), or file size/name-length aggregations.

**Why it's a bug:** the aggregation baseline is visible to and shapeable by the attacker. Pattern: recon current baselines → precondition the buckets → execute within the established baseline.

## Techniques

- [Baseline and Threshold Hijacking](baseline-and-threshold-hijacking.md) — the attacker matches, seeds, or stays under an aggregation the rule keys on (worked examples: `host.id`-only new-terms rules, threshold-per-window counts, exclusion-baseline abuse).
- [Distribution Across Entities](distribute-across-entities.md) — spread the campaign across many users/accounts/IPs/senders so no single entity crosses a per-entity threshold or Top-N cut (documented instances: Bedrock abuse across accounts, password spraying, Top-N email-sender rules).
