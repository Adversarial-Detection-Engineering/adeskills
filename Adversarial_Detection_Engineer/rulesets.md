# Detection Rulesets — Where to Find Them and How to Search

This reference supports **step 2 of the scoping process** ("Find the public rule"). It lists the major open-source and vendor detection-rule repositories, tells you how each one encodes MITRE ATT&CK technique IDs, and shows how to search them and read the *actual rule logic* rather than a title. It also covers **adding a custom or client-specific ruleset** (see the last section) when the engagement uses a rule source not in the default list.

> **Scope reminder.** You are looking up what is publicly known about how a technique is *typically detected*, to reason about false negatives at the category level. You are **not** assembling a bypass. Cite the repo + rule name you found so the human operator can verify it (see SKILL.md → Guardrails).

## Cross-vendor default: Sigma

If the client's stack is unknown, default to **SigmaHQ**. Sigma is a generic, backend-agnostic YAML detection format that transpiles to most SIEM query languages, so a Sigma rule is the closest thing to a portable statement of "how this technique is usually caught."

- **Repo:** [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma)
- **Layout:** `rules/` organized by product and log source — e.g. `rules/windows/process_creation/`, `rules/linux/`, `rules/cloud/`. Emerging/experimental rules live under `rules-emerging-threats/` and `rules-threat-hunting/`.
- **ATT&CK mapping:** each rule carries `tags:` like `attack.t1059.001`, `attack.execution`, `attack.defense_evasion`.
- **Caveat:** transpilation is not lossless — a Sigma rule's real-world behavior depends on the backend it was compiled to (regex flavor, field mapping, null-handling). See [`bug_patterns/sigma_field_semantics.md`](bug_patterns/sigma_field_semantics.md) and [`bug_patterns/logging_assumption_errors.md`](bug_patterns/logging_assumption_errors.md) (#5, #14, #23).

## The major rulesets

| Ruleset | Repo | Format / query language | Target SIEM/EDR | ATT&CK is encoded as |
|---|---|---|---|---|
| **Sigma** | [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) | YAML (generic) | Any (via pySigma) | `tags: attack.tXXXX` |
| **Elastic** | [elastic/detection-rules](https://github.com/elastic/detection-rules) | TOML + KQL / EQL / Lucene | Elastic Security | `[[rule.threat]]` → `technique.id` |
| **Splunk** | [splunk/security_content](https://github.com/splunk/security_content) | YAML + SPL | Splunk (ESCU) | `tags.mitre_attack_id` |
| **Microsoft Sentinel** | [Azure/Azure-Sentinel](https://github.com/Azure/Azure-Sentinel) | YAML + KQL | Sentinel / Defender XDR | `relevantTechniques:` |
| **CrowdStrike** | [CrowdStrike/logscale-community-content](https://github.com/CrowdStrike/logscale-community-content) | LogScale (LQL) | Falcon LogScale / NG-SIEM | prose / tags per query |
| **Query Hub** | [ByteRay-Labs/Query-Hub](https://github.com/ByteRay-Labs/Query-Hub) | mixed community queries | mixed | verify per query on the repo |

### Per-ruleset notes

- **Sigma** — start here for any Windows/process-creation technique. The log-source directory tells you the sensor assumption at a glance (`process_creation`, `registry_set`, `network_connection`, `ps_script`).
- **Elastic detection-rules** — TOML files under `rules/<platform>/`. The `query` field holds the KQL/EQL; `[rule]` `type` distinguishes `query` / `eql` / `threshold` / `machine_learning`. A `threshold` rule is a red flag for the *threshold-assumption* lens (see [`ade-checklist.md`](ade-checklist.md)).
- **Splunk security_content** — human-readable detections at [research.splunk.com](https://research.splunk.com); source YAML under `detections/`. The `search` field is the SPL. Note `data_source` and any `| stats ... by` / `| bin` aggregation.
- **Azure-Sentinel** — analytics-rule YAML under `Detections/` and inside `Solutions/`. `query` is KQL; watch `queryFrequency` / `queryPeriod` / `triggerThreshold` for windowing assumptions.
- **CrowdStrike logscale-community-content** — community LogScale queries; coverage is uneven and less ATT&CK-tagged, so search by technique keyword and read the query.
- **ByteRay-Labs/Query-Hub** — community-contributed queries aggregated across formats; structure and coverage change, so confirm the current layout on the repo before relying on it, and cite the specific query file.

## Adding a custom or client-specific ruleset

The default list above is a starting point, not a fixed set. Add a custom ruleset whenever the engagement's rule source isn't covered — the client's **own** detection repo, an internal/commercial tool's export, a managed-SOC provider's content pack, or a niche open-source project. Record it so this worksheet (and the next engagement's) can search it the same way as the built-in ones.

**To add one, capture the same five things the table above records:**

| Field | What to note |
|---|---|
| **Name** | Short label you'll cite in worksheet rows |
| **Location** | Repo URL, internal path, or "provided by client (not public)" |
| **Format / query language** | Sigma YAML, KQL, SPL, LQL, vendor DSL, etc. |
| **Target SIEM/EDR** | Where these rules run |
| **ATT&CK encoding** | The field/tag that carries the technique ID (or "untagged — search by keyword") |

Append it as a new row in **The major rulesets** table above, then add a short bullet under **Per-ruleset notes** describing how to search it and which fields decide false-negative behavior in that format.

**Guidance for custom sources:**
- **Client-provided (non-public) rules** — if the client shares their actual rule logic, evaluate it with the same four lenses ([`ade-checklist.md`](ade-checklist.md)) but do **not** commit the rule content to this repo; reference it as "client-provided" and keep the specifics in the engagement's own (access-controlled) notes. If they only *claim* coverage without sharing logic, that stays an **open question**, not an assumption (SKILL.md → Guardrails).
- **A custom/internal tool's ruleset** — if it exports to a known format (e.g. Sigma), convert and search it like the corresponding built-in entry. If it uses a proprietary DSL, note the format and read rules directly; the four lenses are format-independent.
- **Provenance** — always cite the source (repo + rule name, or "client-provided, <date>") so the human operator can verify it, exactly as for the public rulesets.
- **Sigma-compatibility shortcut** — many tools import/export Sigma. If a custom source speaks Sigma, you get the cross-vendor tooling and the [`sigma_field_semantics.md`](bug_patterns/sigma_field_semantics.md) caveats for free.

## How to search (with `web_search` / `web_fetch`)

These are public GitHub repos. Two reliable paths:

1. **GitHub code search by ATT&CK ID** — the most precise. Search within a repo for the tag/field:
   - Sigma: `attack.t1218.011 repo:SigmaHQ/sigma`
   - Elastic: `T1218.011 repo:elastic/detection-rules`
   - Splunk: `T1218.011 repo:splunk/security_content`
   - Sentinel: `T1218.011 repo:Azure/Azure-Sentinel`
2. **`web_search` for the technique + ruleset name** when you don't have the exact ID yet — e.g. `rundll32 evasion sigma rule process_creation`, then follow the GitHub result.

**Always read the rule body, not the title.** Fetch the *raw* file so you see the real logic:

```
https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/<rule>.yml
```

For a Sigma rule, the fields that decide false-negative behavior are `logsource` (the sensor dependency), `detection.selection*` (what strings/fields it keys on), `condition` (the Boolean, including any `not filter`), and modifiers (`|contains`, `|endswith`, `|re`, `|windash`, `|all`). Map those directly onto the four lenses in [`ade-checklist.md`](ade-checklist.md).

## From a found rule to the ADE reasoning

Once you have the actual rule logic, the local framework tells you *where the false negatives tend to live*:

- **ADE1 — Reformatting in Actions** → [`ade_framework/ADE1/overview.md`](ade_framework/ADE1/overview.md): literal-substring and flag-format assumptions.
- **ADE2 — Omit Alternatives** → [`ade_framework/ADE2/overview.md`](ade_framework/ADE2/overview.md): alternative binaries/methods/versions/locations the rule doesn't enumerate. See also [`bug_patterns/LOLBAS-gap-analysis.md`](bug_patterns/LOLBAS-gap-analysis.md).
- **ADE3 — Context Development** → [`ade_framework/ADE3/overview.md`](ade_framework/ADE3/overview.md): threshold / aggregation / timing / correlation assumptions.
- **ADE4 — Logic Manipulation** → [`ade_framework/ADE4/overview.md`](ade_framework/ADE4/overview.md): Boolean, filter, and field-mapping errors, including backend-specific field availability ([`ADE4-04`](ade_framework/ADE4/ADE4-04-field-mismapping-semantics/README.md)).

## Caveats to record as open questions

- A **public** rule is not necessarily the client's **deployed** rule. Vendors and customers tune, disable, and replace rules. Treat the public rule as "the typical shape of coverage," and flag "confirm this rule is enabled and untuned in the client's SIEM" as an open question, not an assumption.
- Coverage tags can be aspirational. A rule tagged for a technique may only catch one narrow variant of it.
- Rulesets move. Directory paths and default branches change; if a raw fetch 404s, re-search the repo rather than guessing the path.
