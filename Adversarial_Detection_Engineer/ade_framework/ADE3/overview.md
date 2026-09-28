# ADE3: Context Development

Context Development bugs occur when an attacker takes additional steps to **manipulate or poison the contextual data** a detection rule relies on, causing in-scope activity to bypass rule conditions. Rather than changing the primary malicious action, the attacker shapes the *surrounding context* — process relationships, timing, event fragmentation, telemetry sources — so that no single event contains enough information to trigger the rule.

## Core Insight

Single-event rules are structurally blind to attacks distributed across multiple events, processes, or time windows. Correlation rules add coverage but introduce timeframe tradeoffs the attacker can exploit.

## Why It's Powerful

ADE3 bugs often don't require the attacker to know the detection rule exists — the bypass is a natural consequence of normal behavior:

- **Process cloning** is a routine evasion/privilege step
- **Reconnaissance before attacking** naturally poisons aggregations
- **Operational security** naturally involves timing spacing
- **Piped commands** are standard shell usage — fragmentation is *unintentional* evasion
- **Data volume grows on its own** — limit saturation degrades a rule with no attacker involvement at all

## Subcategories

### ADE3-01: Process Cloning
Logic identifies a process/binary by **string-based name** while assuming the attacker cannot clone or rename binaries. With sufficient privilege, the attacker copies and renames a binary and executes identical behavior under a different process name. The file hash is unchanged — only the name field changes — so rules checking only `process.name`/`Image` miss it.

### ADE3-02: Aggregation Hijacking
Logic relies on **aggregated values** the attacker can influence or precondition: threshold rules ("alert if >10" → stay at 9), "newly seen"/new-terms logic (run a benign version first), UEBA entity grouping (match an existing baseline), or file size/name-length aggregations. Pattern: recon current baselines → precondition the buckets → execute within the established baseline.

### ADE3-03: Timing and Scheduling
Logic relies on **time-based assumptions** (execution frequency, duration, inter-event timing). By spacing, batching, or scheduling actions outside rule windows — `maxspan`, file-age checks, lookback periods, rate limits — the attacker bypasses detection without changing behavior.

### ADE3-04: Event Fragmentation
Logic uses **multi-substring matching** (`contains|all`, multiple ANDs) assuming all substrings appear in a single event. Shell operators (`|`, `&`, `&&`, `||`) split commands into separate process-creation events, so no single event contains all required substrings.

### ADE3-05: Lineage Spoofing
Logic relies on the **parent-process relationship** (e.g., "PowerShell spawned by Word = suspicious") while assuming the logged parent is truthful. Using a legitimate API (`PROC_THREAD_ATTRIBUTE_PARENT_PROCESS`), the attacker sets an arbitrary parent, so the event still fires but the `ParentImage`/`ParentProcessId` the rule trusts is poisoned. Like ADE3-01/02, the telemetry exists — a contextual field has been falsified.

### ADE3-06: Limit Saturation
Logic routes part of its evaluation through an operator with a **bounded working set** — a join or subsearch, a group table, a sort — while assuming every in-scope record is evaluated. Past the limit (Splunk `join` 50,000 rows; LogScale `groupBy()` 20,000 groups, `join()` 100,000 rows) the engine truncates without an error, and the record the rule needed may be dropped. Volume growth alone triggers it; see the [ADE3-06 README](ADE3-06-limit-saturation/).

> **Out of scope — telemetry suppression.** Techniques that *remove* telemetry entirely (ETW/AMSI patching, provider unregistration, disabling logging) are **not** ADE bugs. ADE presupposes the event reaches the SIEM and asks why the rule didn't match; suppression is an upstream collection-integrity attack (MITRE T1562, Impair Defenses) — a precondition for the ADE categories, not an instance of one. Detecting suppression itself is a telemetry-integrity concern (see Detection Strategy below).

## Techniques in This Category

Grouped by subcategory — see each subcategory's README for its definition and detection guidance.

### [ADE3-01 Process Cloning](ADE3-01-process-cloning/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Process Name Masquerading](ADE3-01-process-cloning/process-name-masquerading.md) | Copy/rename binary to defeat Image-based rules | Yes | New |

### [ADE3-04 Event Fragmentation](ADE3-04-event-fragmentation/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Fragmentation and Chaining](ADE3-04-event-fragmentation/fragmentation-chaining.md) | Script file separates payload from LOLBin command line | Yes | DEaTHCon Demo 02 |

### [ADE3-05 Lineage Spoofing](ADE3-05-lineage-spoofing/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Parent PID Spoofing](ADE3-05-lineage-spoofing/parent-pid-spoofing.md) | CreateProcess with a spoofed parent-process attribute | Lab-only | New |

### [ADE3-02 Aggregation Hijacking](ADE3-02-aggregation-hijacking/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Baseline and Threshold Hijacking](ADE3-02-aggregation-hijacking/baseline-and-threshold-hijacking.md) | Match/seed a new-terms baseline, stay under a threshold, or abuse an exclusion bucket | Logic analysis | Elastic new-terms findings (DLE-2026-00006/07/13) |
| [Distribution Across Entities](ADE3-02-aggregation-hijacking/distribute-across-entities.md) | Spread across many users/accounts/IPs/senders to stay under per-entity thresholds or Top-N | Logic analysis | Bedrock/spray/Top-N email findings |

### [ADE3-03 Timing and Scheduling](ADE3-03-timing-and-scheduling/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Correlation Window Evasion](ADE3-03-timing-and-scheduling/window-evasion.md) | Space actions outside a fixed queryPeriod/rate window (slow-and-low) | Logic analysis | Sentinel brute-force + Elastic Outlook COM (DLE-2026-00009) |
| [Maxspan Delay, Boundary Straddling, and Beacon Jitter](ADE3-03-timing-and-scheduling/maxspan-delay-and-beacon-jitter.md) | Sleep past a sequence maxspan, straddle a date_trunc bucket edge, or jitter a beacon | Logic analysis | Elastic LoLBin/OpenAI/beaconing findings |

### [ADE3-06 Limit Saturation](ADE3-06-limit-saturation/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Join, Subsearch, and Group-Limit Saturation](ADE3-06-limit-saturation/join-and-group-limit-saturation.md) | Volume past a join/subsearch row cap or a groupBy group limit truncates the needed record | Logic analysis | Splunk ESCU + CrowdStrike LogScale community findings |

## Detection Strategy

1. **Multi-event correlation** — file-create + process-create within a time window, same user
2. **OriginalFileName** — survives binary copy/rename (PE header, not filesystem)
3. **Hash matching** — Sysmon computes hashes at process start, matching known binaries regardless of name
4. **Parent process validation** — unexpected parent for a given binary (e.g., wsl.exe spawning cmd.exe)
5. **Telemetry integrity monitoring** — detect ETW/AMSI patching via kernel callbacks or integrity checks
6. **Behavioral invariants** — detect correlation-resistant outcomes (network, registry, file)

## Testing Your Rules

- **Process Cloning:** Rule checks only process names, not hashes/signatures? Can the binary be copied by a user with the expected privileges?
- **Aggregation Hijacking:** Can the attacker see current baselines/thresholds? Could benign preparatory activity poison the aggregation?
- **Timing:** Hard-coded time windows (`maxspan`, lookback)? Could an attacker simply wait them out?
- **Event Fragmentation:** Multi-substring (`contains|all`) against command-line fields that shell operators could split?
- **Limit Saturation:** A `join`, subsearch, high-cardinality `groupBy`, or `sort` whose bounded side is filtered only by event type? Could that side exceed the engine's default in your largest environment? Does a rarity filter run *after* a top-N group limit?

## Related Categories

- **ADE1 (Substring Manipulation)** — context manipulation often involves string changes
- **ADE2 (Omit Alternatives)** — cloned binaries are alternative execution methods
- **ADE4 (Gate Inversion)** — timing/aggregation manipulation can flip Boolean gates

## Further Reading

- [Detection Pitfalls by Daniel Koifman](https://detect.fyi/detection-pitfalls-you-might-be-sleeping-on-52b5a3d9a0c8)
- [Unintentional Evasion: Command Line Logging Gaps by Kostas](https://detect.fyi/unintentional-evasion-investigating-how-cmd-fragmentation-hampers-detection-response-e5d7b465758e)
