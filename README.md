# ADE Skills — Adversarial Detection Engineering Knowledge Base

A working knowledge base for **Adversarial Detection Engineering (ADE)**: reasoning about the **false negatives** in SIEM/EDR/XDR detection rules — the mismatches between what a rule *intends* to catch and what it *actually* catches — before a threat actor abuses them.

It packages the ADE taxonomy as worked technique files, platform-specific bug-pattern references, pre-engagement scoping tooling, and a Redamon skill, all grounded in analysis of real public detection rulesets (Sigma, Elastic Security, Microsoft Sentinel).

> **Defensive use only.** This material is for detection engineering, purple-team scoping, and risk assessment. Obtain explicit written authorization before testing detections or systems you do not own or operate. See each technique's own guardrails.

## The ADE taxonomy

Four categories of detection-logic bug, 15 subcategories, 37 worked technique files:

```
ADE1 — Reformatting in Actions        (the logged input is reshaped so a string match fails)
  ADE1-01 Substring Manipulation
  ADE1-02 Normalization Asymmetry

ADE2 — Omit Alternatives              (an in-scope alternative is not enumerated by the rule)
  ADE2-01 Method / Binary
  ADE2-02 Versioning
  ADE2-03 Locations
  ADE2-04 File Types

ADE3 — Context Development            (surrounding context is shaped, not the primary action)
  ADE3-01 Process Cloning
  ADE3-02 Aggregation Hijacking
  ADE3-03 Timing and Scheduling
  ADE3-04 Event Fragmentation
  ADE3-05 Lineage Spoofing

ADE4 — Logic Manipulation             (Boolean / filter / field logic is inverted or wrong)
  ADE4-01 Gate Inversion
  ADE4-02 Conjunction Inversion
  ADE4-03 Incorrect Expression
  ADE4-04 Field Mismapping & Semantics
```

Start with the category overviews: [ADE1](Adversarial_Detection_Engineer/ade_framework/ADE1/overview.md) · [ADE2](Adversarial_Detection_Engineer/ade_framework/ADE2/overview.md) · [ADE3](Adversarial_Detection_Engineer/ade_framework/ADE3/overview.md) · [ADE4](Adversarial_Detection_Engineer/ade_framework/ADE4/overview.md).

## Repository layout

```
Adversarial_Detection_Engineer/
  ade_framework/
    ADE1..ADE4/                      category overview + per-subcategory folders
      ADEn-NN-<subcategory>/         README + one .md per worked technique
    detection-logic-bugs.md          theory: what a detection-logic bug is
    bug-likelihood-test.md           fast pre-analysis heuristic for a rule
    mitigations.md                   fixes by ADE category + per-platform section
    experiment.md
  bug_patterns/                      cross-cutting + platform bug catalogs (see its README)
  ade-checklist.md                   the four false-negative lenses in depth
  rulesets.md                        where to find public rulesets and how to search them
redamon/                            Redamon-packaged skill (ade_scoper) + README
```

### Key entry points

| I want to… | Go to |
|---|---|
| Understand the theory | [detection-logic-bugs.md](Adversarial_Detection_Engineer/ade_framework/detection-logic-bugs.md) |
| Triage a rule quickly | [bug-likelihood-test.md](Adversarial_Detection_Engineer/ade_framework/bug-likelihood-test.md) · [ade-checklist.md](Adversarial_Detection_Engineer/ade-checklist.md) |
| See worked technique files | the `ADEn-NN-*/` folders under [ade_framework](Adversarial_Detection_Engineer/ade_framework/) |
| Fix a vulnerable rule | [mitigations.md](Adversarial_Detection_Engineer/ade_framework/mitigations.md) (incl. per-platform sections) |
| Platform-specific pitfalls | [bug_patterns/](Adversarial_Detection_Engineer/bug_patterns/) — [Elastic](Adversarial_Detection_Engineer/bug_patterns/elasticsecurity.md) · [Sentinel](Adversarial_Detection_Engineer/bug_patterns/microsoftsentinel.md) · [Sigma](Adversarial_Detection_Engineer/bug_patterns/sigma.md) |
| Scope a purple-team engagement | [rulesets.md](Adversarial_Detection_Engineer/rulesets.md) · [redamon/ade_scoper.md](redamon/ade_scoper.md) |
| Browse the raw findings catalog | [total_bugs.md](total_bugs.md) — 620 definite bypass findings across Elastic/Sentinel/Sigma |

## How a technique file is structured

Each worked file carries YAML frontmatter (`id`, `title`, `ade_category`, `ade_subcategory`, named `mitre_attack` tags, `platform`, `testable`) and a consistent body: **Summary → ADE Classification → The Technique → Vulnerable Rule → Hardened Rule → Detection Layers → Implementation Nuances → References**. Many are grounded in specific real findings, with a *Documented instances* table naming the affected vendor rules.

## Authors

- **Nikolas Bielski** — author & lead maintainer ([GitHub](https://github.com/NikolasBielski) · [LinkedIn](https://www.linkedin.com/in/nikbielski/))
- **Daniel Koifman** — co-maintainer ([GitHub](https://github.com/Koifman) · [LinkedIn](https://www.linkedin.com/in/koifman-daniel/))

## License

MIT. Attribution required. Provided "as is" without warranty of any kind.

## Disclaimer

Intended solely for defensive security research, detection engineering, and risk assessment. Users are responsible for complying with all applicable laws, regulations, and authorization requirements. Detection rules and monitoring content are generally out of scope for vendor vulnerability disclosure and bug-bounty programs; treat examples with responsible-disclosure considerations.
