---
id: ADE3-008
title: Join, Subsearch, and Group-Limit Saturation
ade_category: ADE3
ade_subcategory: ADE3-06
mitre_attack:
  - T1218.011 (System Binary Proxy Execution: Rundll32)
  - T1542.003 (Pre-OS Boot: Bootkit)
  - T1190 (Exploit Public-Facing Application)
platform: Cross-platform
testable: logic-analysis
---

# Join, Subsearch, and Group-Limit Saturation

## Summary

A correlation or rarity rule routes part of its evaluation through an operator with a **fixed working-set limit** — a Splunk `join` subsearch, a LogScale `join()` subquery, a LogScale `groupBy()` table, or a `sort`. When the bounded side is filtered only by event type, it fills with estate-wide data, and past the limit the engine truncates the set without raising an error. The rule then evaluates an incomplete set and reports no match.

This is a **query-engineering defect**, not an evasion technique: it produces False Negatives on its own, in an environment where nothing adversarial is happening, as soon as data volume exceeds the operator's default. It is grounded in production rules — three Splunk ESCU detections place near-estate-wide `Network_Traffic` data in a `join` subsearch, and two CrowdStrike community queries show the LogScale forms.

## ADE Classification

**Category:** ADE3 — Context Development
**Subcategory:** ADE3-06 — Limit Saturation
**Core principle:** the rule's outcome depends on whether a record fits inside an operator's row, group, or key budget, while that budget is consumed by surrounding data volume the rule does not control. The in-scope action is unchanged and fully logged; the *volume of context around it* decides whether the rule sees it.

## The Defect

Three shapes, all present in public rulesets.

**1. The high-volume side is placed in the bounded operator.** The subsearch returns the common event type (every network flow, every listening socket) while the streamed main search holds the rare one (the specific suspicious process). The row budget is spent on the common set, so the rare process's matching row competes with estate-wide noise for a fixed number of slots. The correct arrangement is the inverse: the bounded operator holds the selective set.

**2. A group table runs at its default limit ahead of a rarity filter.** A hunting query groups by a high-cardinality key pair, then filters for groups seen on few hosts. LogScale's `groupBy()` defaults to 20,000 groups and, when it exceeds that, retains the **top-N groups by value** — so the low-count groups are evicted first. The rarity filter then runs against a set from which the rare groups have already been removed.

**3. An operator is already at its ceiling.** Where a subquery limit has been raised to the engine's hard maximum (LogScale `join()` caps at 200,000), there is no remaining headroom. The only remedy is to reduce what reaches the operator.

**Why it goes unnoticed:** truncation completes successfully. Splunk returns partial results with a warning banner; LogScale shows a banner on the group limit. Neither surfaces on a scheduled rule, and neither distinguishes "no results because nothing matched" from "no results because the matching row was outside the budget." A rule validated against a lab or a small tenant passes, then degrades as the estate grows — which makes this, like [ADE3-04 Event Fragmentation](../ADE3-04-event-fragmentation/), **unintentional evasion**.

**Adversarial relevance:** because the budget is consumed by all traffic reaching the operator rather than the records the rule cares about, ordinary unrelated volume inside the search window competes with the malicious record for the same slots. Anything that raises that volume — a scan, a backup window, a burst of benign connections — raises the probability that the needed row is the one dropped.

## Vulnerable Rule

```spl
# Paraphrased from Splunk ESCU "Rundll32 with no Command Line Arguments with Network"
| tstats count FROM datamodel=Endpoint.Processes
  WHERE `process_rundll32` Processes.process IN ("*rundll32", "*rundll32.exe")
  BY host Processes.process_id ...
| rename dest as src
| join host process_id
  [
    | tstats count FROM datamodel=Network_Traffic.All_Traffic
      WHERE All_Traffic.dest_port != 0
      BY host All_Traffic.bytes All_Traffic.src_port All_Traffic.dest_port
         All_Traffic.process_id ...        # 20 grouping fields total
  ]
```

### Why it misses

The subsearch's only filter is `dest_port != 0`, which matches nearly every flow, and it groups by 20 fields including `bytes` and `src_port` — values close to unique per connection. So it materialises roughly one row per network flow across the estate, all competing for the documented `join` budget: *"A maximum of 50,000 rows in the right-side dataset can be joined with the left-side dataset over a maximum runtime of 60 seconds."* The rule needs exactly one of those rows. Nothing about the rundll32 process on the left constrains what the subsearch retains.

The same shape appears in two sibling ESCU detections: *Windows WinLogon with Public Network Connection* (subsearch returns every public connection in the estate, where the rule needs only winlogon's) and *Log4Shell JNDI Payload Injection with Outbound Connection* (subsearch returns every destination in `Network_Traffic`, where the rule needs only hosts named in JNDI payloads).

## Hardened Rule

Invert the correlation so the bounded operator holds the **rare** set, and the high-volume data model is streamed and filtered by the subsearch's output:

```spl
| tstats count min(_time) as firstTime max(_time) as lastTime
  FROM datamodel=Network_Traffic.All_Traffic
  WHERE All_Traffic.dest_port != 0
    [ | tstats count FROM datamodel=Endpoint.Processes
        WHERE `process_rundll32` Processes.process IN ("*rundll32", "*rundll32.exe")
        BY host Processes.process_id
      | rename Processes.process_id AS All_Traffic.process_id
      | fields host All_Traffic.process_id ]
  BY host All_Traffic.process_id All_Traffic.dest All_Traffic.dest_port
| `drop_dm_object_name(All_Traffic)`
```

### Why the hardened rule works

The subsearch is still bounded — 10,000 results by default — but it now holds the records the rule is *about*. An estate with more than 10,000 argument-less rundll32 processes in one window has a false-positive problem to solve before a truncation problem. This subsearch-in-`WHERE` form is used by production ESCU detections including *Attacker Tools On Endpoint* and *Prohibited Network Traffic Allowed*, with the same `rename` to data-model-prefixed field names.

Trade-off: the output carries network fields only, so process context (parent, user, path) is pulled during triage or in a follow-up enrichment stage rather than in the alert row.

For the LogScale forms: pass `limit=max` to `groupBy()` when a rarity filter follows it, so the rare groups are not evicted before the filter runs; prefer `selfJoinFilter()` over `join()` for same-stream correlation, gating the result on both sides being present, since it admits false-positive keys but no false negatives.

## Detection Layers

| Audit method | Catches limit saturation? | How |
|---|---|---|
| Count the bounded side alone over the rule's window | Yes | If it approaches the operator's default, the rule is truncating now |
| Re-run constrained to one host | Yes | A match that appears only when constrained confirms truncation, and distinguishes it from a key mismatch (ADE1-02) |
| Invert rare/common sides | Yes | Structural fix — the budget is spent on the selective set |
| Explicit limits (`limit=max`, `sort 0`) | Partial | Raises the ceiling where the engine allows; no help where already at maximum |
| Rarity-filter ordering review | Yes | Ask whether any threshold or rarity filter runs *after* a top-N eviction |
| Never-fired review | Partial | A correlation rule with zero hits since deployment is a truncation candidate |

## Implementation Nuances

- The two Splunk limits are `subsearch_maxout` (50,000 rows for `join`; 10,000 for other subsearches) and `subsearch_maxtime` (60 seconds), both in `limits.conf`. The `max` argument is unrelated to the row cap — it sets how many subsearch rows each main result may join with, and **defaults to 1**.
- LogScale's `join()` row cap is `limit` (default 100,000, maximum 200,000); its `max` parameter, like Splunk's, controls rows retained per join key and defaults to 1. Raising `max` does not raise the row cap.
- LogScale `groupBy()` defaults to 20,000 groups (`GroupDefaultLimit`), with `limit=max` resolving to `GroupMaxLimit`, 1,000,000 by default. Its documentation notes that on reaching the limit, `count` becomes a lower-bound estimate.
- Sort defaults truncate independently of anything upstream: Splunk `sort` returns 10,000 results unless given `0`; LogScale `sort()` returns 200 unless given a `limit`. A `limit=max` on a preceding `groupBy()` does nothing for the `sort` after it.
- Keying a streaming `groupBy()` per process to avoid a join cap is not a general escape hatch — at estate scale it reaches the group limit instead, trading one bounded operator for another.
- ADE3-06 co-occurs with [ADE1-02 Normalization Asymmetry](../../ADE1/ADE1-02-normalization-asymmetry/README.md) (both yield empty joins, for different reasons) and with [ADE3-02 Aggregation Hijacking](../ADE3-02-aggregation-hijacking/) where a rarity threshold sits behind a group limit.

## References

- [Splunk — `join` command reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Join) (50,000-row / 60-second subsearch cap; `max` default 1)
- [Splunk — `tstats` command reference](https://docs.splunk.com/Documentation/Splunk/latest/SearchReference/Tstats) (WHERE-clause filtering)
- [CrowdStrike LogScale — `join()` function](https://library.humio.com/crowdstrike-query-language/functions-join.html) (`limit` default 100,000, maximum 200,000)
- [CrowdStrike LogScale — `groupBy()` function](https://library.humio.com/crowdstrike-query-language/functions-groupby.html) (`GroupDefaultLimit` 20,000; `GroupMaxLimit` 1,000,000; top-N retention, count becomes a lower-bound estimate)
- [Splunk ESCU — Rundll32 with no Command Line Arguments with Network](https://github.com/splunk/security_content/blob/develop/detections/endpoint/rundll32_with_no_command_line_arguments_with_network.yml)
- [Splunk ESCU — Windows WinLogon with Public Network Connection](https://github.com/splunk/security_content/blob/develop/detections/endpoint/windows_winlogon_with_public_network_connection.yml)
- [Splunk ESCU — Log4Shell JNDI Payload Injection with Outbound Connection](https://github.com/splunk/security_content/blob/develop/detections/web/log4shell_jndi_payload_injection_with_outbound_connection.yml)
- [CrowdStrike — Hunt PDB File Paths in Reflective .NET Module Loads](https://github.com/CrowdStrike/logscale-community-content/blob/main/Queries-Only/Helpful-CQL-Queries/Hunt%20PBD%20File%20Paths%20in%20Reflective%20.net%20Module%20Loads.md)
- [CrowdStrike — Process Events: Identify Low Port Bindings](https://github.com/CrowdStrike/logscale-community-content/blob/main/Log-Sources/CrowdStrike/FLTR/crowdstrike-fltrcore/src/queries/ProcessEvents-IdentifyLowPortBindings.yaml)
