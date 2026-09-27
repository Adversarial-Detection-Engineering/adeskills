# ADE4-01 · Gate Inversion

Parent category: [ADE4 — Logic Manipulation](../overview.md)

A NOT clause (negation) checks values the attacker can make appear through poisoned data inserted before the record is generated — often in rule exceptions/filters. Chained negations that simplify via De Morgan's Laws hide the gap: `not A and not B` is equivalent to `not (A or B)`, so inserting `A` **or** `B` drives the whole rule False.

## Techniques

- [Gate Inversion](gate-inversion.md)
