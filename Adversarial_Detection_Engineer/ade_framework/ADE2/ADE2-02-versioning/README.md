# ADE2-02 · Versioning

Parent category: [ADE2 — Omit Alternatives](../overview.md)

Detection logic assumes a fixed software, OS, or API version while other in-scope versions bypass it — OS/distro path differences, deprecated → replacement APIs, protocol version changes, version-specific behaviors.

**Why it's a bug:** rules age. APIs are deprecated and replaced, new OS versions add or rename fields, and a rule tuned to one version silently misses the others.

## Techniques

- [Deprecated and Alternate API Versions](deprecated-and-alternate-api-versions.md) — a rule pinned to one API/service/OS generation misses the same effect via a deprecated or replacement version (worked example: AWS RDS EC2-Classic vs VPC).
- [Log-Schema, Value, and Signature Drift](log-schema-and-signature-drift.md) — a rule keyed to a literal value, message format, or static hash breaks when a vendor update renames it or the tool is recompiled (documented instances: WAF message parsing, renamed policy codes, AdFind/ransomware hash drift).

See also the alternative catalogs under [`bug_patterns/`](../../../bug_patterns/).
