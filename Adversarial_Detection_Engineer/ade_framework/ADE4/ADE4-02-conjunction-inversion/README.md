# ADE4-02 · Conjunction Inversion

Parent category: [ADE4 — Logic Manipulation](../overview.md)

An AND condition checks a value the attacker can manipulate through poisoned data before record generation — e.g. adding a "safe" sentinel string to a payload to satisfy `... AND not (field contains "safe_string")`, or filling an array so a non-empty check reads as benign.

## Techniques

- [Conjunction Inversion](conjunction-inversion.md)
