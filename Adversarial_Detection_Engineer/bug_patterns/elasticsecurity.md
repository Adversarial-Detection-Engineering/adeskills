# Elastic Security — Detection-Logic Bug Patterns

Platform-specific pitfalls for Elastic Security detection rules (`elastic/detection-rules`, TOML). Each entry is a recurring source of false negatives observed while mapping the Elastic ruleset to the ADE taxonomy. Field names are ECS. Pair this with [`logging_assumption_errors.md`](logging_assumption_errors.md) and [`sigma_field_semantics.md`](sigma_field_semantics.md).

## Rule types and where each one breaks

| `type` | What it does | Dominant ADE exposure |
|---|---|---|
| `query` | single-event KQL/Lucene match | ADE1 (string), ADE2 (omitted alt) |
| `eql` | event sequences with `sequence by ... with maxspan` | ADE3-03 (maxspan delay), ADE3-01 (process.name anchors) |
| `threshold` | `count`/`cardinality` over `field` + window | ADE3-02 (per-entity dilution), ADE3-03 (window) |
| `new_terms` | first-seen values over a history window | ADE3-02 (baseline seeding / narrow key) |
| `machine_learning` | anomaly job score | ADE2-02 (model version drift), ADE3-02 (baseline poisoning) |
| `esql` | ES\|QL `STATS ... BY DATE_TRUNC(...)` | ADE3-02/03 (bucket dilution + boundary straddle) |

## 1. `new_terms` keyed too narrowly (ADE3-02)

`new_terms` fires only the first time a value tuple is seen in `history_window_start`. The recurring bug is a key of **`host.id` alone** (or one field), so:
- prior in-window occurrence suppresses the alert, and
- a single benign "seed" event poisons the baseline (baseline poisoning).

Seen in: *AWS CLI Command with Custom Endpoint URL*, *First Time Seen Commonly Abused Remote Access Tool Execution*, and many `by Unusual User` cloud rules keyed on `cloud.account.id, user.name` where a routinely-active role covers the malicious act.

**Mitigation:** widen `new_terms_fields` to include identity + action (`user.name`, `process.args`, an executable hash), not just `host.id`. See [ADE3-02 baseline hijacking](../ade_framework/ADE3/ADE3-02-aggregation-hijacking/baseline-and-threshold-hijacking.md).

## 2. `threshold` counts per attacker-controlled field (ADE3-02)

`threshold` on `field = ["source.ip"]` or `["user.id"]` counts per that entity. An attacker distributes across IPs/accounts to keep every bucket under `value` (e.g. Okta spray via proxy pool; Bedrock abuse across accounts). Use `threshold.cardinality` to count *distinct* attacker entities against a target, and add a coarser account/tenant bucket. See [ADE3-02 distribution across entities](../ade_framework/ADE3/ADE3-02-aggregation-hijacking/distribute-across-entities.md).

## 3. ES|QL `DATE_TRUNC` bucket boundaries (ADE3-03)

`STATS count(*) BY DATE_TRUNC(1 minute, @timestamp)` creates hard bucket edges. `N-1` events at `HH:MM:59` and `N-1` at `HH:MM+1:02` never fill a bucket though they are seconds apart. Prefer sliding windows / `EVAL` bucketed with overlap, or evaluate over a longer trailing window. Seen in *Potential Denial of Azure OpenAI ML Service*, *OneDrive Excessive File Downloads*.

## 4. EQL `sequence ... with maxspan` (ADE3-03)

A short `maxspan` (e.g. `5s`) assumes the correlated step follows immediately. A `sleep`, `awk 'BEGIN{system("sleep 4 && ...")}'`, or scheduled delay lets the sequence expire. Widen `maxspan` to realistic dwell, or decouple into stateful detections joined on a stable key. Seen in *Curl or Wget Egress via LoLBin*, *cat network activity*, *Chisel client*. See [ADE3-03 maxspan/jitter](../ade_framework/ADE3/ADE3-03-timing-and-scheduling/maxspan-delay-and-beacon-jitter.md).

## 5. `process.name` vs `process.executable` vs `process.args` (ADE3-01, ADE2-04)

- `process.name` is the filename only — defeated by cloning/renaming (`cp /bin/nc /tmp/kworker`) and by interpreter wrapping (`bash script.sh` → `process.name` = `bash`).
- Anchor on `process.executable` (full path), `process.code_signature.*`, or `process.hash.*` where available, and always also match the target in `process.args`/`process.command_line`.
- Sequence rules that key on `process.name` in *both* states fail entirely on a single rename (e.g. *Network Activity Detected via cat*). See [ADE3-01](../ade_framework/ADE3/ADE3-01-process-cloning/) and [ADE2-04 interpreter wrapping](../ade_framework/ADE2/ADE2-04-file-types/interpreter-wrapper-and-double-extension.md).

## 6. Positive `file.extension` lists and magic-byte checks (ADE2-04)

Rules enumerating `file.extension in ["exe","dll","zip"]` (± PE magic bytes) miss non-PE archives (`7z/gz/bz2/tar`), scripts (`py/sql/psm1`), macro docs (`xlsm/docm`), extensionless files, and renamed/double extensions. Prefer "alert broadly, suppress trusted (path/signer)". Seen in *Ingress Transfer via Windows BITS*, *SSL Certificate Deletion* (`.cer`), *Executable File with Unusual Extension*.

## 7. Query-language matching quirks

- **`like~` / `:` are case-insensitive** in KQL; EQL `like` is case-sensitive unless `~` is used — a rule can silently miss case variants (`AdFind` vs `adfind`).
- **`process.args` is an array**; `process.args : "-e*"` matches any element. Rules using a single wildcard on `process.args` (e.g. `"-*e*"` for netcat `-e`) miss `--exec`/`--ssl`-style long options (seen in *File Transfer or Listener via Netcat*, *Curl SOCKS Proxy*).
- **Lucene/`match`/regex**: Elasticsearch regex is Lucene-flavored (anchored, no lookbehind); complex patterns behave differently than PCRE. Confirm the pattern compiles and anchors as intended.
- **`event.type`/`event.action`/`event.dataset`** are normalization-dependent; a rule pinned to one dataset misses the same behavior from another integration (ADE2-01/2-02).

## 8. Integration and `event.module` coverage (ADE2-02, ADE2-03)

An Elastic rule is scoped to specific integrations. The same technique arriving through a different integration, a `--root-dir`/custom-socket configuration, or an unmonitored container path (`/opt/app/...`) is out of the rule's data scope. "Defend for Containers" rules were frequently bypassed by execution from `/tmp` or a copied binary. See [ADE2-03 alternate paths](../ade_framework/ADE2/ADE2-03-locations/alternate-paths-and-directories.md).

## 9. `machine_learning` and schema drift (ADE2-02)

ML jobs are trained on a field layout and a behavioral baseline. A new product version that renames a field (`event.code`, `cloud_defend` module version), a new OS build in the training-relevant fields, or deliberate baseline poisoning degrades the job silently. Treat ML detections as high-value but drift-prone; corroborate with rule-based coverage.

## Quick audit checklist for an Elastic rule

- Is a `threshold`/`new_terms` key attacker-controllable or too narrow? Add cardinality / widen the key.
- Does an `eql sequence` have a tight `maxspan`? Can a `sleep` expire it?
- Does it anchor on `process.name`? Add `process.executable`/hash + `process.args`.
- Is there a positive `file.extension` list? Invert to allow-list-suppression.
- Does it parse a message string or pin a static hash/value that a version bump changes? (ADE2-02 — see [`microsoftsentinel.md`](microsoftsentinel.md) §parse too.)

## References
- [Elastic detection-rules](https://github.com/elastic/detection-rules) · [ECS reference](https://www.elastic.co/guide/en/ecs/current/index.html) · [EQL](https://www.elastic.co/guide/en/elasticsearch/reference/current/eql.html) · [ES\|QL](https://www.elastic.co/guide/en/elasticsearch/reference/current/esql.html)
