
## Canonical ADE SubCategories
ADE1 – Reformatting in Actions
    └─ ADE1-01 Substring Manipulation
ADE2 – Omit Alternatives
    ├─ ADE2-01 Method/Binary
    ├─ ADE2-02 Versioning
    ├─ ADE2-03 Locations
    └─ ADE2-04 File Types
ADE3 – Context Development
    ├─ ADE3-01 Process Cloning
    ├─ ADE3-02 Aggregation Hijacking
    └─ ADE3-03 Timing and Scheduling
    └─ ADE3-04 Event Fragmentation
ADE4 – Logic Manipulation
    ├─ ADE4-01 Gate Inversion
    ├─ ADE4-02 Conjunction Inversion
    └─ ADE4-03 Incorrect Expression

## Quick Reference

**By Attack Vector:**
- String manipulation → ADE1-01
- Missing methods/binaries → ADE2-01
- Version drift → ADE2-02
- Process renaming → ADE3-01
- Threshold evasion → ADE3-02
- Timing manipulation → ADE3-03
- Piped commands → ADE3-04
- Logic flaws → ADE4

**By Detection Pattern:**
- `contains` on cmdline → ADE1-01, ADE3-04
- Process name checks → ADE3-01
- Method-specific queries → ADE2-01, ADE2-02
- File paths → ADE2-03
- File extensions → ADE2-04
- Thresholds/counts → ADE3-02
- Sequence rules → ADE3-03
- Multiple `NOT` → ADE4-01


