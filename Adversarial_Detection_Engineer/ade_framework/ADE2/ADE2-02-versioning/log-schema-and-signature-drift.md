---
id: ADE2-011
title: Log-Schema, Value, and Signature Drift
ade_category: ADE2
ade_subcategory: ADE2-02
mitre_attack:
  - T1036 (Masquerading)
  - T1027 (Obfuscated Files or Information)
platform: Cross-platform
testable: logic-analysis
---

# Log-Schema, Value, and Signature Drift

## Summary

A rule matches a **specific string value, field name, message format, or file hash/signature** that a vendor update, a new software version, or a trivially-recompiled tool changes — so the same in-scope activity is logged under a value the rule never lists. Unlike an API/operation swap ([Deprecated and Alternate API Versions](deprecated-and-alternate-api-versions.md)), the *event still occurs and is still logged*; only its representation drifts, and the rule silently stops matching.

This is one of the most common ADE2-02 patterns in the analysis corpus — dozens of Elastic and Sentinel rules break when a provider renames a field/value, changes a log message format, or when an attacker recompiles a tool to change its hash.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-02 — Versioning
**Core principle:** rules pinned to a literal value, a message template, or a static hash are pinned to a *point-in-time* representation. Vendors rename policy codes, bump schema versions, and reword log messages; attackers recompile binaries. Each is an omitted "version" of the same event.

## The Pattern

Three drift surfaces, all evidenced in the corpus:

1. **Value / enum rename** — the rule matches a fixed set of codes or names that the provider later renames or extends (a new `violation_code`, a renamed policy, a new built-in role, a changed submission-type integer).
2. **Message-format / schema drift** — the rule parses a specific log-message template or field layout that a product update reformats (WAF score strings, appliance CVE log wording, audit-schema key renames).
3. **Hash / signature drift** — the rule matches a static SHA256, IMPHASH, or signer that a recompiled tool variant or a new malware build changes.

## Documented instances (from the analysis corpus)

| Rule (platform) | Drift surface | What changes and breaks the match |
|---|---|---|
| Unusual High Confidence Content Filter Blocks (Elastic) | value/enum | a new `gen_ai.compliance.violation_code` (e.g. `SELF_HARM_INDUCEMENT`) not in the rule's list |
| Unusual High Denied Sensitive Information Policy Blocks (Elastic) | value rename | Bedrock `sensitive_information_policy` renamed to `data_privacy_policy`; `BLOCKED` action renamed |
| Azure RBAC Built-In Administrator Roles Assigned (Elastic) | new enum | a newly introduced built-in admin role name not in the enumerated `roleDefinition` set |
| Google Workspace Marketplace Restrictions Modified (Elastic) | setting rename | Admin API renames "Allowlist access" setting → rule's `setting.name` no longer matches |
| M365 Teams External Access Enabled (Elastic) | new method | a new Graph API endpoint/`event.action` for the same setting change |
| Application Gateway WAF – SQLi/XSS Detection (Sentinel/KQL) | message format | WAF `Message` string reformatted (score-field layout changes) → parse fails |
| PulseConnectSecure CVE-2021-22893 (Sentinel/KQL) | message wording | appliance version logs the exploit attempt with slightly different `Messages` text |
| Probable AdFind Recon Tool Usage (Sentinel/KQL) | hash drift | recompiled/alternate `AdFind.exe` → different `TargetProcessSHA256` |
| Prestige ransomware IOCs Oct 2022 (Sentinel/KQL) | hash + signame | new variant → SHA256 not in `sha256Hashes`, different Defender `signames` |
| Silk Typhoon Suspicious Exchange Request (Sentinel/KQL) | value drift | customized IIS backend `sSiteName` or newer/older Exchange build |
| Admin Submissions by DetectionMethod (Sentinel/KQL) | enum integer | Defender changes internal `SubmissionType` value (`3`→`4`) |

## Vulnerable Rule

```kql
// Paraphrased: WAF detection keyed to a parsed message template
AzureDiagnostics
| where Category == "ApplicationGatewayFirewall"
| parse Message with "Total Inbound Score: " TotalInboundScore " - SQLI=" SQLI_Score ",XSS=" XSS_Score
| where toint(SQLI_Score) > 0
```

### Why it misses

The `parse` pattern hard-codes the exact message layout. A WAF/OWASP-CRS update that reorders or reworks the `Message` string yields empty `SQLI_Score` for every event, and the rule silently returns nothing — coverage looks intact but is zero.

## Hardened Rule

```kql
AzureDiagnostics
| where Category == "ApplicationGatewayFirewall"
// Prefer structured fields over parsing a human-readable string
| extend score = coalesce(toint(column_ifexists("SQLI_Score_d", int(null))),
                          extract(@"SQLI[=:]\s*(\d+)", 1, Message))
| where isnotempty(score) and toint(score) > 0
```

Where structured fields exist, use them instead of parsing prose; where a value list is unavoidable, alert broadly on the event and suppress known-good, and prefer `OriginalFileName`/behavior over a static hash (hashes are recompile-fragile — see [Implementation Nuances #12](../../../bug_patterns/logging_assumption_errors.md)).

## Detection Layers

| Audit method | Catches drift? | How |
|---|---|---|
| Use structured fields, not message parsing | Yes | Immune to message-template rewording |
| Alert broadly + suppress known-good | Yes | New/renamed values don't fall through a positive list |
| Behavior/`OriginalFileName` over static hash | Yes | Survives recompilation |
| Provider-changelog review cadence | Partial | Periodically re-verify enums/schema against the current API |
| Emulate on the current product version | Yes | Reproduce the event on today's build; confirm the field/value still matches |

## Implementation Nuances

- See [Implementation Nuances #12](../../../bug_patterns/logging_assumption_errors.md) (hashes are computed per-build; a recompile defeats a static hash) and #23 (config/schema decides what fields exist).
- This pattern is often a *design fragility* rather than an active attacker move — but it is still a false-negative source and belongs in ADE2-02: the "version" that drifts is the log/tool representation.
- Related: field *availability/naming* across backends is [ADE4-04](../../ADE4/ADE4-04-field-mismapping-semantics/README.md); this technique is value/message/hash drift *within* a field.

## References

- [MITRE ATT&CK T1036 — Masquerading](https://attack.mitre.org/techniques/T1036/)
- [MITRE ATT&CK T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [Elastic detection-rules](https://github.com/elastic/detection-rules) · [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel)
