# ADE3-05 · Lineage Spoofing

Parent category: [ADE3 — Context Development](../overview.md)

Detection relies on the **parent-process relationship** (e.g., "PowerShell spawned by Word = suspicious") while assuming the logged parent is truthful. Using a legitimate API (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), the attacker assigns an arbitrary parent, so the event still fires but the `ParentImage`/`ParentProcessId` the rule trusts is poisoned.

**Why it's a bug:** parent lineage is a mutable, attacker-controllable field, yet many rules treat it as ground truth for both alerting and exclusion. This is a subcategory beyond the original four ADE3 classes: the telemetry exists, a contextual field has been falsified.

## Techniques

- [Parent PID Spoofing](parent-pid-spoofing.md)

## See also

- Filter exclusions on `ParentImage` (ADE4-02 Conjunction Inversion) are directly exploitable via lineage spoofing.
