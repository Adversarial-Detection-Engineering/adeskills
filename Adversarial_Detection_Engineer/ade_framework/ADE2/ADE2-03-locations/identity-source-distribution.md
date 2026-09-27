---
id: ADE2-012
title: Source Location and Origin Distribution
ade_category: ADE2
ade_subcategory: ADE2-03
mitre_attack:
  - T1090 (Proxy)
  - T1110.003 (Brute Force: Password Spraying)
platform: Cloud / Identity
testable: logic-analysis
---

# Source Location and Origin Distribution

## Summary

The "location" in ADE2-03 is not only a filesystem path — it is also **where an action originates**: the source IP, ASN, geo-region, or device. A rule that keys on a single origin (per-IP counting, "atypical travel" from a known-good region, "unusual country") is defeated when the attacker distributes or relocates the origin so no single source crosses the rule's boundary.

Grounded in the corpus: multiple Elastic and Sentinel identity rules count failures per `source.ip`, or gate on `source.geo.region_iso_code` / country, and were flagged ADE2-03 because a proxy/botnet/VPN moves the origin into an in-scope-but-unmonitored location.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-03 — Locations
**Core principle:** the origin of an action is attacker-choosable. Per-origin thresholds and "known-good location" baselines assume the attacker stays at one observable source; commodity proxies, botnets, VPNs, and cloud egress make the source a free variable.

## The Pattern

1. **Per-source thresholding** — a rule counts events per `source.ip`; the attacker spreads the same campaign across many IPs so no single IP reaches the threshold (a location-flavoured [aggregation hijack, ADE3-02](../../ADE3/ADE3-02-aggregation-hijacking/baseline-and-threshold-hijacking.md)).
2. **Known-good region seeding / relocation** — an "impossible travel" or "new country" rule trusts the set of regions the user normally logs in from; the attacker first identifies (or seeds) a common region and originates from there, or picks an obscure in-country data center that reads as domestic.
3. **Trusted-origin masquerade** — originate from a commercial VPN / cloud IP range that the org already sees frequently, so the "unusual source" gate never trips.

## Documented instances (from the analysis corpus)

| Rule (platform) | Origin field | How the origin is moved |
|---|---|---|
| Okta Brute Force or Password Spraying Attack (Elastic) | `source.ip` | proxy network / botnet — 10 failures each from many IPs instead of 25 from one |
| Unusual Source IP for Okta Privileged Operations (Elastic) | `source.ip` | commercial VPN / cloud-hosted proxy in a frequently-seen range |
| M365 Identity Login from Atypical Travel Location (Elastic) | `source.geo.region_iso_code` | pre-identify a region the victim commonly uses; originate from there |
| Unusual Country For an AWS Command (Elastic) | geolocation (country) | VPN/proxy in an obscure data center inside a trusted country |
| Authentication Attempt from New Country (Sentinel/KQL) | `IPAddress` / `Location` | compromise a cloud VM in a region that reads as a plausible location |

## Vulnerable Rule

```toml
# Paraphrased Okta password-spray rule: per-source-IP threshold
type = "threshold"
query = 'event.dataset:okta.system and event.action:user.session.start and event.outcome:failure'
[rule.threshold]
field = ["source.ip"]      # counts failures per single IP
value = 25
```

### Why it misses

The threshold is evaluated **per `source.ip`**. An attacker driving the spray through a rotating proxy pool keeps each IP under 25 while attempting hundreds of logins overall — the aggregate attack is fully in-scope but no single source bucket alerts.

## Hardened Rule

```toml
type = "threshold"
query = 'event.dataset:okta.system and event.action:user.session.start and event.outcome:failure'
[rule.threshold]
# Count the campaign by its target/cardinality, not by the attacker-controlled origin
field = ["user.name"]
value = 5
[rule.threshold.cardinality]
field = "source.ip"
value = 10                 # many distinct source IPs against one/few users = spray
```

Key on the **invariant the attacker can't cheaply move** (the targeted account, or the distinct-source cardinality) rather than the origin IP; corroborate geo rules with an orthogonal signal (new device + new region + off-hours) instead of trusting the region set alone.

## Detection Layers

| Audit method | Catches origin distribution? | How |
|---|---|---|
| Count by target + source cardinality | Yes | Spraying many IPs at few users raises cardinality |
| Corroborate geo with device/token signals | Yes | Region alone is cheap to spoof; combine signals |
| ASN/hosting-provider enrichment | Partial | VPN/cloud egress ranges are a weak but useful signal |
| Impossible-travel with velocity, not region set | Partial | Harder to seed than a static known-good region list |
| Emulate distributed origin | Yes | Reproduce a proxy-spread spray; confirm coverage |

## Implementation Nuances

- This is the identity/network sibling of the filesystem-path technique [Alternate Paths and Directories](alternate-paths-and-directories.md): both move an attacker-choosable "location" out of the rule's scope.
- Per-origin thresholds double as an [ADE3-02 aggregation hijack](../../ADE3/ADE3-02-aggregation-hijacking/baseline-and-threshold-hijacking.md) and often an [ADE3-03 timing](../../ADE3/ADE3-03-timing-and-scheduling/window-evasion.md) issue — distributed *and* slow.
- "Known-good region" baselines are seedable exactly like new-terms baselines (ADE3-02): a benign login from the chosen region poisons the trusted set.

## References

- [MITRE ATT&CK T1090 — Proxy](https://attack.mitre.org/techniques/T1090/)
- [MITRE ATT&CK T1110.003 — Password Spraying](https://attack.mitre.org/techniques/T1110/003/)
- [Elastic detection-rules — Okta/identity rules](https://github.com/elastic/detection-rules)
