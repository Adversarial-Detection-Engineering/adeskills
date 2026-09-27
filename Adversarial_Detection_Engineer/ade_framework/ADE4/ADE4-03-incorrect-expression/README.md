# ADE4-03 · Incorrect Expression

Parent category: [ADE4 — Logic Manipulation](../overview.md)

The interpreted query rarely produces hits by construction — wrong choices between negations, conjunctions, or disjunctions. Ineffective *by design*, not by attacker action. Classic mistakes: AND where OR is required (requiring `curl` AND `wget` in one command line), mutually exclusive conditions, or negating privileged accounts in non-privesc rules.

## Techniques

- [AND vs OR Confusion](and-vs-or-confusion.md)
