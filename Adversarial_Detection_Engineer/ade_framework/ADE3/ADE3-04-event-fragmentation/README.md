# ADE3-04 · Event Fragmentation

Parent category: [ADE3 — Context Development](../overview.md)

Detection uses **multi-substring matching** (`contains|all`, multiple ANDs) assuming all substrings appear in a single event. Shell operators (`|`, `&`, `&&`, `||`) split commands into separate process-creation events, so no single event contains all required substrings.

**Why it's a bug:** this is often *unintentional* evasion — piped commands are standard shell usage. Single-event rules are structurally blind to it; correlation is required.

## Techniques

- [Fragmentation and Chaining](fragmentation-chaining.md)

## See also

- Implementation Nuances #2 (raw command line), #16 (script-block chunking) — [logging_assumption_errors.md](../../../bug_patterns/logging_assumption_errors.md)
