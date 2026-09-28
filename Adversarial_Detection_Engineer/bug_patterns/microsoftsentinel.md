# Microsoft Sentinel — Detection-Logic Bug Patterns

Platform-specific pitfalls for Microsoft Sentinel analytic rules (KQL, `Azure/Azure-Sentinel`). Each entry is a recurring false-negative source observed while mapping the Sentinel ruleset to the ADE taxonomy. Pair with [`logging_assumption_errors.md`](logging_assumption_errors.md) and [`sigma_field_semantics.md`](sigma_field_semantics.md).

## Rule scheduling fields and where they break

| Field | Meaning | ADE exposure |
|---|---|---|
| `queryPeriod` | look-back the query runs over | ADE3-03 (slow-and-low outside the window) |
| `queryFrequency` | how often it runs | gaps / straddling between runs |
| `triggerThreshold` + `triggerOperator` | result count to alert | ADE3-02 (stay under) |
| `eventGroupingSettings` | alert per-row vs per-group | over/under-grouping |
| NRT (near-real-time) rules | single-event, no scheduling | narrower context (no aggregation) |

## 1. Fixed `queryPeriod` / `bin()` windows (ADE3-03)

The dominant Sentinel timing bug: aggregation over a fixed window, usually `summarize ... by bin(TimeGenerated, 20m)` combined with `queryPeriod`. An attacker keeps each window under threshold ("slow brute force": 9 failures, wait 21 min, repeat). Seen in *imAuthBruteForce* (ASIM), account-lockout, and SSO-error rules.

**Mitigation:** longer look-back with a sliding evaluation, and corroborate with an orthogonal signal (distinct source IPs, impossible travel). See [ADE3-03 window evasion](../ade_framework/ADE3/ADE3-03-timing-and-scheduling/window-evasion.md).

## 2. `parse` / `extract` on human-readable message strings (ADE2-02)

Many Sentinel rules `parse Message with ...` against a specific log-message template (WAF scores, appliance CVE strings, IIS fields). A vendor update that reformats the message yields empty parsed fields and the rule silently returns nothing. Seen in *Application Gateway WAF – SQLi/XSS Detection*, *PulseConnectSecure CVE-2021-22893*.

**Mitigation:** prefer structured/dynamic fields; when parsing prose, use tolerant `extract()` regex and validate against the current message format. See [ADE2-02 schema drift](../ade_framework/ADE2/ADE2-02-versioning/log-schema-and-signature-drift.md).

## 3. Static value / enum / hash lists (ADE2-02)

Rules matching fixed `sha256Hashes`, `signames`, IOC lists, role names, or internal enum integers (`SubmissionType == "3"`) break when the attacker recompiles (new hash), a new variant appears, or Microsoft renames/renumbers a value. Prefer behavior over IOC lists; treat hash/IOC rules as short-lived. Seen in *Prestige ransomware IOCs*, *Probable AdFind Recon* (`TargetProcessSHA256`), *Admin Submissions by DetectionMethod*.

## 4. Per-source / per-entity thresholds and Top-N (ADE3-02)

- Counting per `IPAddress`/`source.ip` is defeated by proxy/botnet distribution (see [ADE2-03 origin distribution](../ade_framework/ADE2/ADE2-03-locations/identity-source-distribution.md)).
- "Top 10/100 senders/users/domains" rules are diluted by using more entities than the list depth (*Top 100 malicious email senders*, *Top policies performing user overrides*). Use absolute thresholds/behavior, not relative ranking. See [ADE3-02 distribution](../ade_framework/ADE3/ADE3-02-aggregation-hijacking/distribute-across-entities.md).

## 5. Destination allow-lists and folder/location checks (ADE2-03)

Rules keyed on specific mail folders (`Deleted Items`, `Junk`), a curated `DataverseSharePointSites` list, `DeliveryLocation`, or a single spooler/startup path miss equivalent destinations (custom folder, unlisted site, sibling subfolder). Alert on the risky *behavior shape* and suppress known-good. Seen in *Malicious Inbox Rule* (moves to `RSS Feeds`), *Malware Detections by delivery location*, *Dev-0530 File Extension Rename*. See [ADE2-03 destination locations](../ade_framework/ADE2/ADE2-03-locations/cloud-destination-locations.md).

## 6. ASIM normalization semantics

Sentinel's Advanced SIEM Information Model (ASIM) parsers (`imAuthentication`, `imProcessCreate`, `imDns`, `imFileEvent`, `imWebSession`) normalize disparate sources. Pitfalls:
- A rule written against a *native* table misses events that only arrive normalized, and vice versa (ADE4-04 field availability).
- ASIM field values (`EventResult`, `TargetUserType`, `DvcAction`) are parser-defined; excluding a value (`where TargetUserType != "NonInteractive"`) creates a blind spot for that class (gate inversion, ADE4-01) — seen in *imAuthBruteForce* excluding non-interactive accounts.
- Normalized `TargetProcessSHA256`/`Process` depend on the source populating them; a source that doesn't emit the field silently drops the match.

## 7. KQL matching quirks

- **Case sensitivity:** `==` is **case-sensitive** by default; use `=~`, deliberately. `AdFind.exe` vs `adfind.exe` silently diverge.
- **`has` vs `contains`:** `has` is token-based (whole-term, indexed, faster); `contains` is substring. A `has` rule misses a substring embedded in a larger token; a `contains` rule over-matches. Choose intentionally.
- **`matches regex`** uses RE2 (no backreferences, no lookbehind/lookahead) — patterns ported from PCRE may not compile or behave the same.
- **`in` vs `in~`:** `in` is case-sensitive set membership; enumerated LOLBin/extension lists silently miss case variants without `in~`.
- **`arg_max`/`arg_min` and `make_set`:** collapsing to one row per key can hide the very events a correlation needs; verify the summarize preserves what the condition tests.

## 8. Watchlists, exclusions, and `join` (ADE4-01/4-04)

- Watchlist/allow-list `join`s that exclude "known-good" entities can be poisoned or can invert when the joined field is absent (three-valued logic — see [ADE4-04 absent-field inversion](../ade_framework/ADE4/ADE4-04-field-mismapping-semantics/absent-field-inverts-filter.md)).
- `join kind=inner` silently drops rows with null keys; `leftouter` then `where isempty(...)` behaves differently — a null key can flip a "not in allow-list" exclusion.

## Quick audit checklist for a Sentinel rule

- Fixed `bin()`/`queryPeriod` window? Add sliding look-back + corroboration.
- `parse` on a message string, or a static hash/IOC/enum list? Expect version drift.
- Per-`IPAddress`/entity threshold or Top-N? Add cardinality / absolute thresholds.
- Destination-folder/site allow-list? Match behavior shape instead.
- Case-sensitive `==`/`has`/`in` on attacker strings? Use `=~`/`in~` deliberately.
- ASIM `where field != value` exclusion? Confirm it isn't a scoped blind spot.

## References
- [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) · [KQL reference](https://learn.microsoft.com/en-us/azure/data-explorer/kusto/query/) · [ASIM](https://learn.microsoft.com/en-us/azure/sentinel/normalization) · [Scheduled analytics rules](https://learn.microsoft.com/en-us/azure/sentinel/detect-threats-custom)
