# Redamon Skills

Redamon-format skill files packaged from this repo's Adversarial Detection Engineering (ADE) framework, for use with [Redamon](https://github.com/samugit83/redamon). Each file is self-contained: download a single `.md` and upload it via **Global Settings → Agent Skills** to activate it.

These are the Redamon-packaged distribution of the ADE material. The full framework — taxonomy, worked technique files, logging nuances, ruleset search guidance — lives under [`../Adversarial_Detection_Engineer/`](../Adversarial_Detection_Engineer/) and is left in its own structure; the files here condense it into Redamon's single-file skill contract.

## Skills

| Skill | Author | Description |
|-------|--------|-------------|
| [ade_scoper.md](ade_scoper.md) | [@NikolasBielski](https://github.com/NikolasBielski), [@Koifman](https://github.com/Koifman) | Purple-team emulation scoper: replans adversary emulation around a specified SIEM/EDR stack, derives emulation variants from the ADE detection-logic-bug taxonomy (ADE1–4) to probe likely false negatives, and recommends rule/collection mitigations after testing. |

## Using a skill

1. Open the `.md` file and download it (or copy its contents).
2. In your Redamon instance, go to **Global Settings → Agent Skills** and upload it.
3. The skill classifies on its `description`; it loads when a request matches its **When to Classify Here** triggers (e.g. "plan emulation for Splunk/Elastic/Sentinel", "detection gap analysis", "turn test results into rule fixes").

## Contributing these upstream

To offer one of these to Redamon's community skills, follow their flow ([`agentic/community-skills/README.md`](https://github.com/samugit83/redamon/blob/master/agentic/community-skills/README.md)):

1. Confirm fit first — these are **purple-team / planning** skills, a different shape from Redamon's offensive attack-skill workflows; raise an issue with the maintainer before investing in a PR.
2. Test the `.md` in a Redamon instance by uploading via Global Settings.
3. Fork [samugit83/redamon](https://github.com/samugit83/redamon), add the `.md` to `agentic/community-skills/`, and add a row to that folder's table with your GitHub username.
4. Open a Pull Request.

## Scope note

These skills plan and reason about detection coverage and emulation; live execution belongs to an authorized engagement with a human go/no-go. Each skill states its own guardrails in its **Important Notes** section — purple-team framing, authorization gates, and cite-your-sources discipline.
