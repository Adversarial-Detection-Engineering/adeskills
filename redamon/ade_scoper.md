---
title: "PURPLE TEAM SKILL: ADE Detection-Aware Emulation Scoper"
description: >
  Replans adversary emulation around a target's SPECIFIED SIEM/EDR stack: maps in-scope ATT&CK
  techniques to that stack's public detection rules, uses the Adversarial Detection Engineering (ADE)
  detection-logic-bug taxonomy to derive emulation variants that probe the rules' likely false
  negatives, and produces rule-hardening mitigation recommendations after testing.
  Trigger when scoping or replanning a purple-team engagement against named SIEM tools (Splunk,
  Elastic, Sentinel, CrowdStrike, Sigma), building detection-validation emulation plans, or turning
  detection-rule gaps into test cases and post-test fixes.
tools:
  - kali_shell
  - execute_curl
  - execute_code
tags:
  - purple-team
  - detection-engineering
  - emulation-planning
  - siem
  - sigma
  - ade
  - mitre-attack
  - detection-gap-analysis
references:
  - sigmahq
  - elastic-detection-rules
  - splunk-security-content
  - azure-sentinel
  - crowdstrike-logscale
  - mitre-attack
  - adeskills
authors:
  - "@NikolasBielski (https://github.com/NikolasBielski)"
  - "@Koifman (https://github.com/Koifman)"
  - "@Adversarial-Detection-Engineering (https://github.com/Adversarial-Detection-Engineering)"
---

# PURPLE TEAM SKILL: ADE Detection-Aware Emulation Scoper

## Overview

This skill turns "we're emulating technique category X" into a **detection-aware emulation plan**: for the target's *specified* SIEM/EDR tools, it finds how X is typically detected, reasons about where those rules produce **false negatives** using the ADE detection-logic-bug taxonomy, plans emulation **variants** that exercise each suspected gap, and — after testing — recommends concrete rule mitigations.

It is a **purple-team** skill. Every emulation is a controlled test of "does this detection fire?", run under engagement authorization, with the goal of *improving* the target's rules. It is not an evasion-for-evasion's-sake workflow. The output feeds a human-reviewed test plan and a mitigation backlog.

Three pillars:
1. **Replan around the SIEM stack** — the emulation plan is keyed to the client's named detection tools, not generic ATT&CK coverage.
2. **Emulate from detection-logic bugs** — each variant is derived from a specific, named class of rule bug (ADE1–ADE4), so a "miss" is diagnosable, not mysterious.
3. **Recommend mitigations after testing** — every confirmed gap produces a rule-hardening recommendation the blue team can apply.

The summaries below are a condensed working set. **The authoritative, continually-updated ADE knowledge base is the `adeskills` repo — pull it at runtime and enrich from it (see "Context enrichment" next):** <https://github.com/Adversarial-Detection-Engineering/adeskills> → `Adversarial_Detection_Engineer/`.

## Tools Available

- `kali_shell` / `execute_code` — pull/enrich context from the `adeskills` repo (`git clone --depth 1 https://github.com/Adversarial-Detection-Engineering/adeskills` or fetch specific files), grep public rule repos, run the emulation commands under test (atomic tests, LOLBin invocations, command variants), and script variant generation.
- `execute_curl` — fetch raw rule files from public ruleset repos to read *actual* rule logic (not titles), fetch individual `adeskills` reference files, and query the target SIEM's API where the engagement provides access to confirm whether a rule fired.

Use these only within authorized scope. Pulling the knowledge base, reading public rules, and generating a plan are always safe; executing emulations requires the engagement's rules of engagement (RoE) and a human go/no-go (see Important Notes).

## Context enrichment (run first)

This skill file inlines only a condensed working set of the ADE taxonomy. Before analysis, **enrich context from the `adeskills` repo** so reasoning reflects the current, fuller framework rather than this summary alone:

```bash
git clone --depth 1 https://github.com/Adversarial-Detection-Engineering/adeskills /tmp/adeskills
# Framework entry points:
ls /tmp/adeskills/Adversarial_Detection_Engineer/ade_framework/ADE*/overview.md
# Worked technique files, logging nuances, ruleset search guidance, false-negative lenses:
ls /tmp/adeskills/Adversarial_Detection_Engineer/bug_patterns/
cat /tmp/adeskills/Adversarial_Detection_Engineer/{ade-checklist.md,rulesets.md}
```

If cloning isn't available, fetch the specific files by raw URL with `execute_curl`, e.g.
`https://raw.githubusercontent.com/Adversarial-Detection-Engineering/adeskills/main/Adversarial_Detection_Engineer/ade_framework/ADE1/overview.md`.

Pull the files relevant to the in-scope techniques and specified SIEM:
- `ade_framework/ADE{1,2,3,4}/overview.md` and the matching subcategory technique files — the detection-logic-bug classes that drive emulation variants (Phase 2).
- `bug_patterns/logging_assumption_errors.md` — telemetry/collection nuances that decide whether a rule can fire at all (Phase 1, Phase 4 collection fixes).
- `bug_patterns/sigma_field_semantics.md` and `bug_patterns/LOLBAS-gap-analysis.md` — field/backend pitfalls and LOLBin alternatives for variant generation.
- `rulesets.md` and `ade-checklist.md` — where to find each SIEM's public rules and the four false-negative lenses in depth.

Cite the specific `adeskills` file (and any public rule) that informed each planned variant, so findings are traceable.

## When to Classify Here

Route here when the request involves any of:
- "Plan/replan emulation for **<named SIEM/EDR>**" (Splunk, Elastic Security, Microsoft Sentinel, CrowdStrike Falcon/NG-SIEM/LogScale, QRadar, Chronicle/SecOps, or Sigma as cross-vendor).
- "Which variants should we test to validate detection coverage for **<ATT&CK technique>**?"
- "Why might this detection rule miss **<technique>**?" / "detection gap analysis" / "false-negative analysis".
- "Turn these test results into rule fixes / mitigation recommendations."
- Any mention of ADE, adversarial detection engineering, detection-logic bugs, or purple-team scoping against a specific detection stack.

Do **not** classify here for live black-box evasion whose goal is to defeat a control undetected with no intent to report or fix it — that is not purple teaming. Redirect to the human red-team lead.

## Inputs to gather first

Ask for whatever the conversation hasn't already supplied (one question at a time, don't guess):
1. **Specified SIEM/EDR tool(s)** — the exact detection stack in scope. This drives ruleset selection and field/telemetry assumptions.
2. **In-scope ATT&CK technique categories** and authorized systems/segments.
3. **Telemetry reality** — which sensors are actually deployed and how (Sysmon config, Windows Security 4688 command-line auditing on/off, PowerShell Script Block Logging, EDR agent). Detection coverage is a property of deployed telemetry, not of rule text.
4. **Rule visibility** — will the client share their actual deployed rules, or only claimed coverage? Claimed-but-unshared coverage stays an *open question*, never an assumption.

## Ruleset map (per specified SIEM)

Match the client's stack to its public ruleset; if unknown, default to **Sigma** (transpiles to most backends). Read the *rule body*, not the title — fetch the raw file.

| SIEM / EDR | Public ruleset (repo) | Query language | ATT&CK encoded as |
|---|---|---|---|
| Cross-vendor default | SigmaHQ/sigma | Sigma YAML | `tags: attack.tXXXX` |
| Splunk | splunk/security_content | SPL | `tags.mitre_attack_id` |
| Elastic Security | elastic/detection-rules | KQL/EQL/Lucene | `[[rule.threat]]` |
| Microsoft Sentinel | Azure/Azure-Sentinel | KQL | `relevantTechniques:` |
| CrowdStrike | CrowdStrike/logscale-community-content | LogScale (LQL) | keyword/tags |

Search by ATT&CK ID (e.g. GitHub code search `attack.t1218.011 repo:SigmaHQ/sigma`), then fetch raw:
`https://raw.githubusercontent.com/SigmaHQ/sigma/master/rules/windows/process_creation/<rule>.yml`

The fields that decide false-negative behavior: `logsource` (sensor dependency), `detection.selection*` (what strings/fields it keys on), `condition` (Boolean, incl. any `not filter`), and modifiers (`|contains`, `|endswith`, `|re`, `|windash`, `|all`).

## PHASE 1 — Detection-surface reconnaissance

For each in-scope technique category:
1. Resolve the MITRE ATT&CK technique ID(s).
2. Pull the matching rule(s) from the specified SIEM's ruleset (above). Record repo + rule name for citation.
3. Read the actual rule logic and note its `logsource`, key fields, condition, and modifiers.
4. Cross-check telemetry reality (input #3): does the sensor the rule depends on actually exist and emit the needed fields on the in-scope hosts? A rule against `OriginalFileName` on a 4688-only host, or against `CommandLine` with 4688 command-line auditing off, contributes zero coverage — silently.

Output of this phase: a per-technique inventory of "here is the rule, here is exactly what it keys on, here is the telemetry it assumes."

## PHASE 2 — Detection-logic-bug analysis & emulation replanning

Apply the **four false-negative lenses** to each rule, and for each suspected gap emit a concrete **emulation variant**. The variant is the test; the bug class is the hypothesis for why it might miss.

**The four lenses**
- **Data-source dependency** — what sensor/field/EID must be enabled for this rule to fire at all? Gap → emulate on a host class where that source is absent/misconfigured (WSL2 blind spot, PowerShell v2 downgrade removing 4104, minimal Sysmon config, 4688 cmdline auditing off).
- **Threshold assumptions** — count/rate/time-window/"newly seen"/baseline logic. Gap → emulate the same action low-and-slow, below the count, spread past the correlation window, or matched to an existing baseline.
- **Scope assumptions** — one binary/protocol/OS/auth-method/version, or one literal string. Gap → emulate an in-scope *alternative* (different LOLBin, renamed binary, alternate method/path/version) or the same command *reformatted*.
- **Environment drift** — exclusion filters / allow-lists / "known-good" baselines tuned elsewhere. Gap → emulate activity that lands inside an inherited exclusion, or that references a filter field absent on this telemetry (which can invert a `not filter`).

**The ADE detection-logic-bug taxonomy** (maps each variant to a named, diagnosable bug class):

- **ADE1 — Reformatting in Actions.** The same action, reformatted, breaks literal-substring/flag-format matches. Emulation variants: caret/quote/tick insertion, whitespace runs, env-var splicing, flag-prefix abbreviation (`-e`…`-EncodedCommand`), boolean/delimiter swaps, NTFS 8.3 short names, path canonicalization forms. → tests rules that `|contains` a canonical string.
- **ADE2 — Omit Alternatives.** The rule enumerates a subset of an equivalence class. Emulation variants: alternate LOLBin/method for the same objective, alternate download/exec technique, alternate location/file-type, deprecated→replacement API, alternate OS/version. → tests rules anchored on one binary/method. See the LOLBAS gap catalog in the ADE repo.
- **ADE3 — Context Development.** Manipulate the aggregate/timing the rule keys on. Emulation variants: stay one below a threshold, precondition a UEBA/"new terms" baseline (run benign first), fragment a payload across events so a single-event `contains|all` misses it, spread steps past `maxspan`, exploit clock skew. → tests correlation/aggregation/threshold rules.
- **ADE4 — Logic Manipulation.** The rule's Boolean/field logic is wrong or invertible. Emulation variants: satisfy an exclusion filter (`and not filter`) with an attacker-supplied sentinel; exercise a rule on a backend/source where a referenced field is absent or renamed (field mismatch, `not filter` inversion via null-handling); exercise AND-where-OR / mutually-exclusive conditions that never fire. → tests filter-heavy and cross-backend rules.

**Replanning rule:** the emulation plan is ordered by the *specified SIEM's* most likely gaps first. If the client runs Elastic with RE2 (no lookbehind) or Sentinel KQL, prioritize ADE4 field/regex-flavor variants; if they rely on minimal Sysmon, prioritize ADE1/ADE2 telemetry-blind variants; if they lean on correlation/UEBA, prioritize ADE3. Tie each planned variant to the exact rule it probes and the bug class it tests.

## PHASE 3 — Validation execution (purple-team)

For each planned variant, under RoE and with human go/no-go:
1. Execute the emulation on an in-scope host (prefer known-benign, atomic, reversible actions; use non-destructive equivalents).
2. Observe the specified SIEM: did the target rule fire? Capture the alert (or its absence), the raw telemetry event, and which field/condition matched or failed.
3. Classify the result: **Detected** (rule fired as intended), **Missed** (confirmed false negative — record the bug class from Phase 2), or **No telemetry** (the event never reached the SIEM — a data-source gap, not a logic gap).
4. Keep it validation-framed: the artifact of each test is "did detection X catch action Y, and if not, why" — never a reusable evasion recipe divorced from the fix.

## PHASE 4 — Mitigation recommendations (after testing)

Turn every confirmed **Missed** / **No telemetry** result into a rule-hardening recommendation for the blue team:
- **ADE1 miss** → add `OriginalFileName`/hash anchors, `|windash`, normalize case/separators, match parameter *names* not values; stop relying on a single literal substring.
- **ADE2 miss** → enumerate the alternatives as an OR (alternate binaries/methods/paths), prefer behavior/module anchors over one image name.
- **ADE3 miss** → revisit threshold/`maxspan`/baseline settings; reassemble chunked events (e.g. Script Block `ScriptBlockId`); normalize to UTC with skew slack.
- **ADE4 miss** → fix the Boolean (AND↔OR), guard negated filters with an `|exists`/presence check so an absent field can't invert the rule, pin `logsource.service`, and validate the transpiled query per backend.
- **No telemetry** → a collection recommendation, not a rule edit: enable the missing sensor/EID/field (Sysmon config coverage, 4688 command-line auditing, Script Block Logging), then re-test.

Cite the public rule (repo + name) so the blue team can diff their deployed version against it.

## OUTPUT FORMAT

**A. Emulation plan** — one row per planned variant:

| Technique (ATT&CK ID) | Specified SIEM rule (repo + name) | Telemetry it assumes | Suspected bug class (ADE1–4) | Emulation variant to run | What a miss would prove |
|---|---|---|---|---|---|

**B. Test results** — appended after execution: per variant, one of Detected / Missed (bug class) / No telemetry, with the captured evidence reference.

**C. Mitigation backlog** — one row per confirmed gap:

| Gap (rule + bug class) | Observed miss | Recommended rule/collection fix | Re-test result |
|---|---|---|---|

Follow the tables with **Notes for the human operator**: judgment calls, anything the public rules didn't cover, open questions to put to the client, and a reminder that this feeds the human-authored test plan/RoE and the blue team's backlog.

## Important Notes

- **Authorization first.** Every Phase 3 execution requires engagement RoE and a human go/no-go. This skill plans and reasons freely; it does not auto-execute emulations against a live target without that gate.
- **Purple, not covert.** The purpose is to validate and *improve* detections. Do not produce a bypass whose only purpose is to defeat a control undetected with no reporting/fix path. If a request drifts that way, stop and route to the human red-team lead.
- **Telemetry ≠ rule text.** A rule can be perfectly written and still contribute zero coverage where its data source isn't collected. Always separate a *logic* miss (Phase 4 rule fix) from a *telemetry* miss (collection fix).
- **Public rule ≠ deployed rule.** Vendors and clients tune/disable/replace rules. Treat public rules as the typical shape of coverage; confirm the client's deployed, tuned version, or record it as an open question.
- **Cite everything.** Repo + rule name for every rule; "client-provided, <date>" for shared internal rules (keep their content in the engagement's access-controlled notes, not in this skill).
- **Backend divergence is real.** The same Sigma rule behaves differently across Splunk/Elastic/Sentinel/CrowdStrike (regex flavor, field mapping, null-handling). Validate per specified backend, not once.
- Deeper reference (taxonomy, worked technique files, logging nuances, ruleset search guidance) — pull at runtime per "Context enrichment": <https://github.com/Adversarial-Detection-Engineering/adeskills> → `Adversarial_Detection_Engineer/{ade_framework,bug_patterns,ade-checklist.md,rulesets.md}`.
