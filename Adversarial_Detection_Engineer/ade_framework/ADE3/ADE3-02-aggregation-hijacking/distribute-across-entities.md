---
id: ADE3-006
title: Distribution Across Entities
ade_category: ADE3
ade_subcategory: ADE3-02
mitre_attack:
  - T1110.003 (Brute Force: Password Spraying)
  - T1078 (Valid Accounts)
platform: Cloud / Identity
testable: logic-analysis
---

# Distribution Across Entities

## Summary

A rule aggregates a count **per entity** — per user, per account, per IP, per sender, per resource — and fires when one entity crosses a threshold, or ranks entities into a "Top-N" list. The attacker spreads the same total activity across **many entities** so no single entity reaches the threshold or the Top-N cut, while the aggregate campaign proceeds unchanged.

This was the single largest ADE3-02 cluster in the corpus (240+ findings): AI/Bedrock abuse spread across compromised user accounts, password spraying spread across users, and phishing/email rules spread across senders, domains, or policies to stay off "Top-N" lists.

## ADE Classification

**Category:** ADE3 — Context Development
**Subcategory:** ADE3-02 — Aggregation Hijacking
**Core principle:** a per-entity aggregation assumes one entity carries the whole campaign. The attacker controls how many entities they use, so any per-entity threshold or Top-N ranking can be diluted below the alerting line by adding entities.

## The Pattern

1. **Per-user/account dilution** — a rule fires at `> N` events *per `user.id`*; the attacker uses `M` accounts at `N-1` each. Total = `M×(N-1)`, well above `N`, but no single user bucket alerts.
2. **Top-N ranking evasion** — a rule surfaces the "Top 10/100 senders / users / domains." The attacker uses more senders/domains than the list depth, or keeps each below the typical volume, so their traffic never ranks.
3. **Policy/administrative fan-out** — instead of one broad "Allow Phishing" policy (which would stand out), create ten narrowly-named policies so no single policy looks anomalous.
4. **Shared-secret / entity-key gaps** — a rule keyed on one entity field (`dt_hash`, a single account) inherently can't see cross-entity abuse and may be *broken by construction*.

## Documented instances (from the analysis corpus)

| Rule (platform) | Aggregation key | Distribution bypass |
|---|---|---|
| AWS Bedrock Invocations without Guardrails by a Single User (Elastic) | per `user.id`, >5/min | 4 invocations each across `user_A`, `user_B` |
| Unusual High Confidence Content Filter Blocks (Elastic) | per `user.id` count | distribute prompts across `user_A/B/C` |
| Unusual High Denied Sensitive Information Policy Blocks (Elastic) | per `user.id`, 60 min | 3 requests each across 3 AWS accounts |
| Potential Abuse of Resources by High Token Count (Elastic) | per `user.id` | exfil spread across `user-A/B/C` |
| AWS Bedrock Multiple Denied Models by a Single User (Elastic) | per `user.id` | probe denied models one per account |
| NRT Multiple users email forwarded to same destination (Sentinel/KQL) | per `ClientIP`/`UserId` | rotate VPN so each forward is a different ClientIP |
| Top 100 malicious email senders (Sentinel/KQL) | Top-N `SenderMailFromAddress` | 150 sender addresses, one mail each |
| Top 100 senders (Sentinel/KQL) | Top-N by count | 500 emails across 10 accounts |
| Email Top Domains sending Phish (Sentinel/KQL) | Top-N `SenderFromDomain` | 20 registered domains, moderate volume each |
| Total Emails with Admin Overrides (Allow) (Sentinel/KQL) | per `OrgLevelPolicy` | ten narrowly-named allow policies instead of one |
| Multiple Okta Auth Events with Same Device Token Hash (Elastic) | per `dt_hash` | rule inherently can't see cross-entity spray |

## Vulnerable Rule

```sql
-- Paraphrased Bedrock abuse rule: threshold per user per minute
FROM logs-aws.bedrock*
| STATS invocations = COUNT(*) BY user.id, minute = DATE_TRUNC(1 minute, @timestamp)
| WHERE invocations > 5
```

### Why it misses

`> 5` is evaluated **per `user.id`**. An attacker holding two compromised accounts runs 4 invocations on each per minute — 8 total, but every `user.id` bucket stays at 4. The abuse scales with the number of accounts while the rule only ever sees per-user counts.

## Hardened Rule

```sql
FROM logs-aws.bedrock*
| STATS invocations = COUNT(*), users = COUNT_DISTINCT(user.id)
    BY account = cloud.account.id, minute = DATE_TRUNC(1 minute, @timestamp)
| WHERE invocations > 5 OR (users >= 3 AND invocations >= 9)
```

Add an **account-level (or tenant-level) aggregation and a distinct-entity cardinality clause**, so a campaign spread thinly across many users still trips a coarser bucket; for Top-N rules, alert on absolute volume/behaviour thresholds rather than relative ranking.

## Detection Layers

| Audit method | Catches distribution? | How |
|---|---|---|
| Add a coarser bucket (account/tenant) | Yes | Per-user dilution still sums at the account level |
| Distinct-entity cardinality clause | Yes | "Many users each just under threshold" becomes the signal |
| Absolute thresholds over Top-N ranking | Yes | Ranking is relative and diluteable; absolute volume is not |
| Correlate entities by shared indicator | Partial | Same destination/ASN/campaign ties diluted entities together |
| Emulate multi-entity spread | Yes | Reproduce `M×(N-1)`; confirm the coarser rule fires |

## Implementation Nuances

- Distribution-across-entities is the *spatial* sibling of the *temporal* [ADE3-03 window evasion](../ADE3-03-timing-and-scheduling/window-evasion.md); attackers routinely combine both (many entities **and** slow).
- Per-origin thresholds are the identity/network form documented in [ADE2-03 Source Location and Origin Distribution](../../ADE2/ADE2-03-locations/identity-source-distribution.md).
- A rule keyed on a single entity field (`dt_hash`) can be *inherently broken* — no attacker action needed; flag these as design defects, not just bypasses. See [Implementation Nuances #6](../../../bug_patterns/logging_assumption_errors.md).

## References

- [MITRE ATT&CK T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [MITRE ATT&CK T1078 — Valid Accounts](https://attack.mitre.org/techniques/T1078/)
- [Elastic detection-rules](https://github.com/elastic/detection-rules) · [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel)
