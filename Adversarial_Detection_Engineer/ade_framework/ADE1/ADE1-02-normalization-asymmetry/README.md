# ADE1-02 · Normalization Asymmetry

Parent category: [ADE1 — Reformatting in Actions](../overview.md)

A mismatch between how the logging/normalization pipeline records a value and how the OS or interpreter actually parses it. The rule matches the normalized form while the parser executes an equivalent, different-looking form — so the same action is logged one way and matched another.

**Why it's a bug:** normalization happens in more than one place and the layers disagree. 8.3 short names, forward vs back slashes, case-insensitive paths, trailing dots/spaces, Unicode homoglyphs, and non-breaking whitespace all resolve to the same thing at execution but not at match time.

## Two facets

**1. Single-value spelling asymmetry.** One field is logged in a form the OS treats as equivalent to the canonical value but the rule's literal/normalized match does not — the 8.3 short name, slash direction, homoglyph, or trailing-dot cases above.

**2. Join on an attacker-mutable key.** A correlation rule joins two records (e.g. Sysmon EID 1 + Security 4688, or a file-write event + the process-execution that runs it) on a **key**, and part of that key is a value the attacker can mutate — or that the two sources normalize/populate differently. Both records are logged, but the join key doesn't line up on both sides, so the correlation produces no hit and the rule never fires. As per the ADE framework examples: the bug is not that an event is missing, but that the *representation of the join key* is asymmetric across the joined sources (or across log time vs execution time), and the attacker only has to perturb the mutable key part — a filename, an image/path spelling, a hostname/user field, a short-lived id — to break the correlation. Prefer joining on a stable, non-mutable key (a hash, a system-assigned id) and normalize the key identically on both sides before the join.

## Techniques

- [NTFS Short Names](ntfs-short-names.md)

_Join-on-attacker-mutable-key has no standalone worked file yet; see the correlation-join treatment in [ADE3-04 Event Fragmentation](../../ADE3/ADE3-04-event-fragmentation/fragmentation-chaining.md), which shares the join-key concern from the aggregation side._

## See also

- Implementation Nuances #10 (8.3 short names), #21 (path canonicalization), #22 (timestamps/skew across joined sources) — [logging_assumption_errors.md](../../../bug_patterns/logging_assumption_errors.md)
