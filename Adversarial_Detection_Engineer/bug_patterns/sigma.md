# Sigma — Detection-Logic Bug Patterns

Platform-specific pitfalls for Sigma rules (`SigmaHQ/sigma`, generic YAML) and their transpilation. Sigma is backend-agnostic, so its bugs live in two places: the rule's own logic, and the **transpilation** to a concrete SIEM. Pair with [`sigma_field_semantics.md`](sigma_field_semantics.md) (field naming/modifier catalog) and [`logging_assumption_errors.md`](logging_assumption_errors.md).

## Detection-block Boolean semantics (the #1 authoring bug — ADE4)

Sigma's YAML has implicit Boolean structure that many authors misread:

```yaml
detection:
  selection:
    Image|endswith:            # a LIST under a key = OR
      - '\curl.exe'
      - '\wget.exe'
    CommandLine|contains: 'http'  # separate KEY in the same map = AND
  condition: selection
```

- **List under a key → OR.** Values are alternatives.
- **Multiple keys in a map → AND.** All must match the *same* event.
- Putting alternatives as separate keys accidentally requires all of them (`CommandLine|contains: 'curl'` AND `CommandLine|contains: 'wget'` almost never fires — real bug, *Suspicious Shell Script Detected*, ADE4-03).
- Use `1 of selection_*` / `all of selection_*` and an explicit `condition` to state intent. See [ADE4-03 AND-vs-OR](../ade_framework/ADE4/ADE4-03-incorrect-expression/and-vs-or-confusion.md).

## `logsource` binds the sensor (ADE2-01/2-02, ADE4-04)

`logsource: {product, category, service}` decides which telemetry the rule compiles against. Pitfalls:
- `category: process_creation` maps to Sysmon EID 1 **or** Security 4688 depending on the backend pipeline; field availability differs (`OriginalFileName` is Sysmon-only; 4688 command-line auditing is off by default). Pin `service: sysmon` when you depend on a Sysmon-only field. See [logging_assumption_errors #14/#23](logging_assumption_errors.md).
- A rule bound to one `service`/`product` silently covers only that source.

## Modifiers and their blind spots

| Modifier | Behavior | Blind spot |
|---|---|---|
| `\|contains` | substring | over-matches (`-enc` matches `-encoding`); still literal — breaks on reformatting (ADE1) |
| `\|startswith`/`\|endswith` | anchored | misses trailing space/dot, `.bak`, short names |
| `\|all` | AND across a list | fragmentable — split indicators across events (ADE3-04) |
| `\|base64offset\|contains` | encoded match | misses other encodings/utf16 if omitted |
| `\|windash` | normalizes `-`/`/` | only the prefix half of parameter obfuscation |
| `\|re` | regex | **flavor varies by backend** (see below) |
| `\|cidr` | IP range | none, but only where the field is a clean IP |
| `\|exists` | field presence | use it to guard negated filters (ADE4-04) |

## Transpilation bugs (the Sigma-specific class)

A Sigma rule that reads correctly can **behave differently or fail to compile** per backend:

1. **Regex flavor (`|re`).** Splunk = PCRE (lookaround OK); Elasticsearch = Lucene regex (no lookaround); Sentinel KQL, Google SecOps YARA-L, CrowdStrike LogScale = RE2 (no lookaround/backrefs). A `|re` using lookbehind silently fails to transpile or matches nothing on RE2 backends — a zero-coverage gap. See [logging_assumption_errors #5](logging_assumption_errors.md).
2. **Field mapping.** The backend pipeline (pySigma processing pipeline) maps Sigma field names to concrete columns. An unmapped field can resolve to *nothing* rather than erroring — `CommandLine` → `Process Command Line` (4688), `process.command_line` (ECS), etc. See [ADE4-04 field mismatch](../ade_framework/ADE4/ADE4-04-field-mismapping-semantics/field-name-mismatch.md).
3. **Case sensitivity.** Sigma is case-insensitive in spec, but the compiled query may be case-sensitive on the target store; a `contains` becomes a case-sensitive substring on some backends.
4. **Null-handling in `not filter`.** `condition: selection and not filter` inverts differently across backends when `filter`'s field is absent (three-valued logic) — false negatives on one SIEM, false positives on another. See [ADE4-04 absent-field inversion](../ade_framework/ADE4/ADE4-04-field-mismapping-semantics/absent-field-inverts-filter.md).

**Always inspect the transpiled query**, not just the Sigma source; a rule that fails to transpile is silent zero coverage.

## Field-name typos and normalization (ADE4-04)

Exact-spelling matters and fails silently: Sigma uses `TargetFilename` (lowercase `n`), `OriginalFileName`, `ParentImage`. `Commandline`/`command_line`/`TargetFileName` typos resolve to no column on case/spelling-sensitive backends. Prefer the taxonomy's canonical names and let the pipeline map them. Full catalog: [`sigma_field_semantics.md`](sigma_field_semantics.md).

## Literal-string fragility (ADE1)

Because Sigma is largely `contains`/`endswith` on raw fields, it inherits every ADE1 reformatting bypass (carets, quotes, ticks, whitespace, env-var splicing, short names) — Sysmon logs the command line *raw*, so obfuscation survives to match time. Anchor on `OriginalFileName`/behavior and add `|windash`/`|base64offset` where relevant. See [ADE1](../ade_framework/ADE1/overview.md) and [`cmdline_obfuscation.md`](cmdline_obfuscation.md).

## IOC / hash rules and threat-intel specificity (ADE1-01, ADE2-02)

Many Sigma rules encode a point-in-time indicator (a specific filename like `ebpfbackdoor`, a hash, a fixed path). Renaming the file or recompiling defeats them (DLE-2026-00003, *Triple Cross rootkit*). Treat these as IOC rules, not behavioral coverage; generalize to the behavior (persistence dir + content) where possible.

## Correlation rules (newer Sigma spec)

Sigma correlation (`type: event_count | value_count | temporal | temporal_ordered`) adds aggregation/timing — and with it ADE3 exposure: `timespan` windows (ADE3-03 straddle/slow), `group-by` fields that are attacker-controllable (ADE3-02). Apply the same window/aggregation scrutiny as native SIEM rules.

## Quick audit checklist for a Sigma rule

- Are alternatives ORed (list) not accidentally ANDed (separate keys)? Check `condition`.
- Is `logsource` pinned to a source that actually has the fields used?
- Does `|re` use lookaround that won't survive RE2/Lucene backends?
- Read the **transpiled** query for your backend — field mapped? case? null-handling of `not filter`?
- Field names spelled to the canonical taxonomy (`TargetFilename`, `OriginalFileName`)?
- Is it a literal-substring/IOC rule that ADE1 reformatting or a rename defeats?

## References
- [SigmaHQ/sigma](https://github.com/SigmaHQ/sigma) · [Sigma specification](https://github.com/SigmaHQ/sigma-specification) · [Conditions](https://sigmahq.io/docs/basics/conditions.html) · [Modifiers](https://sigmahq.io/docs/basics/modifiers.html) · [pySigma pipelines](https://sigmahq-pysigma.readthedocs.io/en/latest/Processing_Pipelines.html)
