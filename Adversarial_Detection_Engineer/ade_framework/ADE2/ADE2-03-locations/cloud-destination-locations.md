---
id: ADE2-013
title: Cloud and Application Destination Locations
ade_category: ADE2
ade_subcategory: ADE2-03
mitre_attack:
  - T1564.008 (Hide Artifacts: Email Hiding Rules)
  - T1114 (Email Collection)
platform: Cloud (M365 / SharePoint / Windows)
testable: logic-analysis
---

# Cloud and Application Destination Locations

## Summary

A rule enumerates a fixed set of **destination locations** an action can target — a mail folder, a delivery location, a SharePoint site/library, a startup or spool subfolder — while an in-scope alternative destination achieves the same outcome. The action (move email, deliver malware, drop a file, upload a document) is unchanged; only the *target location* moves outside the enumerated set.

Grounded in the corpus: many M365/Sentinel rules were flagged ADE2-03 because they check specific folders (`Deleted Items`, `Junk Email`), specific delivery locations, a curated list of SharePoint sites, or a single spooler/startup path.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-03 — Locations
**Core principle:** a destination is a parameter. When a rule lists "the suspicious folders/sites/paths," any equivalent destination not on the list is an omitted alternative and a silent false negative.

## The Pattern

1. **Mail-rule / delivery folder swap** — an inbox-rule or phishing-evasion rule keys on moves to `Deleted Items`/`Junk`; the attacker moves matching mail to a benign custom folder (`Archive Alerts`, `RSS Feeds`) or lets it land in the primary Inbox.
2. **Curated site/library allow-list** — a rule references a maintained list of SharePoint sites (`DataverseSharePointSites`); the attacker uses a newly-created, misconfigured, or unlisted site/library, or uploads to a Teams channel's backing library instead of a chat.
3. **Alternate system subfolder** — a drop-path rule checks one directory (a spooler driver folder, the Startup folder, a fixed ransom-note path); the attacker uses a sibling subfolder or redirects the Startup location via `User Shell Folders`.

## Documented instances (from the analysis corpus)

| Rule (platform) | Location field | Alternative destination used |
|---|---|---|
| M365 Exchange Inbox Phishing Evasion Rule Created (Elastic) | `MoveToFolder` | move to a custom `Archive Alerts` folder instead of Deleted/Junk |
| Malicious Inbox Rule (Sentinel/KQL) | `Parameters` | move matching mail to `RSS Feeds` rather than Deleted/Junk |
| Malware Detections by delivery location (Sentinel/KQL) | `DeliveryLocation` | malware delivered to Inbox rather than Quarantine/Failed |
| Potentially malicious SVG delivered to Inbox (Sentinel/KQL) | `LatestDeliveryLocation` | final delivery location differs from the checked value |
| Dataverse – Mass download from SharePoint (Sentinel/KQL) | `DataverseSharePointSites` | access a site not in the curated site list |
| Accessed files shared by temporary external user (Sentinel/KQL) | `SourceRelativeUrl` | upload to a general document library, not the watched path |
| Files uploaded to Teams and access summary (Sentinel/KQL) | `SourceRelativeUrl` | upload to a channel's `Files` tab (backing library) vs direct chat |
| Shortcut File Written on Startup Folder (Elastic) | `file.path` | redirect Startup via `User Shell Folders` to another directory |
| Windows Print Spooler Suspicious File Creation (Sentinel/KQL) | `FolderPath` | drop the DLL in a sibling spooler `drivers` subfolder |
| Dev-0530 File Extension Rename (Sentinel/KQL) | `FolderPath` | drop the ransom note under `Public\Desktop` / another drive |

## Vulnerable Rule

```kql
// Paraphrased: inbox-rule evasion keyed to specific destination folders
OfficeActivity
| where Operation in ("New-InboxRule","Set-InboxRule")
| where Parameters has_any ("Deleted Items","Junk Email")
```

### Why it misses

Only moves to `Deleted Items`/`Junk Email` match. A rule that quietly moves security-related mail to a benign custom folder (`Archive Alerts`) or `RSS Feeds` hides it from the user just as effectively while the destination check evaluates false.

## Hardened Rule

```kql
OfficeActivity
| where Operation in ("New-InboxRule","Set-InboxRule")
// Alert on the risky rule SHAPE (delete / mark-read / move + a security keyword),
// not on a fixed destination-folder allow-list
| extend p = tostring(Parameters)
| where p has_any ("DeleteMessage","MarkAsRead","MoveToFolder")
| where p has_any ("phish","security","microsoft","invoice","password","alert")
```

Alert on the **behaviour shape** (auto-delete/mark-read/move combined with sensitive keywords) rather than an enumerated destination; for site/library rules, alert broadly and suppress known-good sites instead of matching a curated allow-list.

## Detection Layers

| Audit method | Catches destination swap? | How |
|---|---|---|
| Match rule/behavior shape, not destination list | Yes | Any target folder with the risky action pattern is caught |
| Alert broadly + suppress known-good site/path | Yes | Unlisted sites/folders don't fall through |
| Check the *final* delivery/location field | Partial | Use `LatestDeliveryLocation`, not the initial value |
| Emulate with an alternate destination | Yes | Reproduce with a custom folder / unlisted site; confirm coverage |

## Implementation Nuances

- Filesystem-path version of this is [Alternate Paths and Directories](alternate-paths-and-directories.md); origin-location version is [Source Location and Origin Distribution](identity-source-distribution.md). All three are ADE2-03 "the location is a parameter."
- Destination allow-lists (curated SharePoint sites, "known" folders) are maintenance-fragile and attacker-observable — the same weakness as new-terms baselines ([ADE3-02](../../ADE3/ADE3-02-aggregation-hijacking/baseline-and-threshold-hijacking.md)).

## References

- [MITRE ATT&CK T1564.008 — Email Hiding Rules](https://attack.mitre.org/techniques/T1564/008/)
- [MITRE ATT&CK T1114 — Email Collection](https://attack.mitre.org/techniques/T1114/)
- [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) · [Elastic detection-rules](https://github.com/elastic/detection-rules)
