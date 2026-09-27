# ADE3-01 · Process Cloning

Parent category: [ADE3 — Context Development](../overview.md)

Detection identifies a process/binary by **string-based name** while assuming the attacker cannot clone or rename binaries. With sufficient privilege the attacker copies and renames a binary and executes identical behavior under a different process name; the file hash is unchanged, only the name field differs.

**Why it's a bug:** rules that check only `process.name`/`Image` trust a mutable field. `OriginalFileName` (PE header) and hashes survive the rename.

## Techniques

- [Process Name Masquerading](process-name-masquerading.md)

## See also

- Implementation Nuances #1, #11, #12 — [logging_assumption_errors.md](../../../bug_patterns/logging_assumption_errors.md)
