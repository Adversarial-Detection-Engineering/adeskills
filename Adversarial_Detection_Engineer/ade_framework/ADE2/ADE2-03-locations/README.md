# ADE2-03 · Locations

Parent category: [ADE2 — Omit Alternatives](../overview.md)

Detection logic only searches specific locations (file paths, registry keys, URLs) while other valid in-scope locations are ignored — `Program Files` vs `Program Files (x86)`, `HKLM` vs `HKCU`, distro cron-path differences, region-specific endpoints.

**Why it's a bug:** the same outcome is reachable from many locations; hardcoding one leaves the rest uncovered.

## Techniques

- [Alternate Paths and Directories](alternate-paths-and-directories.md) — a rule pinned to one filesystem path/directory misses equivalent locations (worked examples: `/etc/profile.d/` MOTD persistence, `/tmp` staging).
- [Source Location and Origin Distribution](identity-source-distribution.md) — the "location" is the origin IP/geo/region; per-source thresholds and known-good-region baselines fall to proxies/VPNs/distribution (documented instances: Okta spray, atypical-travel, unusual-country rules).
- [Cloud and Application Destination Locations](cloud-destination-locations.md) — a rule's fixed set of destination folders/sites/paths misses equivalent targets (documented instances: inbox-rule folders, SharePoint site allow-lists, spooler/startup subfolders).

See also [`bug_patterns/persistence_alternatives.md`](../../../bug_patterns/persistence_alternatives.md).
