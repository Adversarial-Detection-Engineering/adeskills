---
id: ADE2-010
title: Omitted File Extensions and Formats
ade_category: ADE2
ade_subcategory: ADE2-04
mitre_attack:
  - T1105 (Ingress Tool Transfer)
  - T1027 (Obfuscated Files or Information)
platform: Windows
testable: true
---

# Omitted File Extensions and Formats

## Summary

A detection rule enumerates a fixed allow/deny list of file extensions (or a magic-byte check), while an **in-scope alternative format** carries the same payload past it. Same transfer, same execution — a different container the rule never listed.

Grounded in a real finding (DLE-2026-00005): the Elastic rule **"Ingress Transfer via Windows BITS"** restricts monitoring to a set of executable/archive extensions plus a PE-header byte check. Non-PE archives, interpreted scripts, alternate PowerShell module formats, and macro-enabled Office documents transferred via BITS never match.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-04 — File Types
**Core principle:** the file extension/format is an attacker-choosable wrapper, not the behavior. Any rule that enumerates "the dangerous file types" is enumerating a subset; the equivalence class of payload-bearing formats is far larger and keeps growing.

## The Technique

The BITS ingress rule keys on a list like `.exe/.dll/.zip/.rar` plus a PE magic-byte test. Equivalent payloads that fall outside that list:

| Omitted class | Examples |
|---|---|
| Non-PE archives | `.7z`, `.gz`, `.bz2`, `.tar`, `.tgz`, `.cab`, `.iso`, `.img` |
| Interpreted scripts | `.py`, `.sql`, `.js`, `.vbs`, `.bat`, `.ps1` |
| Alternate PowerShell module formats | `.psm1`, `.psd1` |
| Macro-enabled / OOXML documents | `.xlsm`, `.xlsb`, `.docm`, `.pptm` |
| Extensionless / mismatched | payload with no extension, or `.txt` renamed post-transfer |

Because BITS delegates the actual download to `svchost.exe` (see [BITS Jobs, ADE2-01](../ADE2-01-method-binary/bits-jobs.md)), the transfer of any of these types is both a **file-type** omission and a method-attribution problem. The attacker fetches `payload.7z` (or a `.xlsm`) via BITS, then unpacks/executes locally — the ingress rule's extension list and PE check both evaluate false.

## Vulnerable Rule

```yaml
# Paraphrased from the Elastic BITS ingress rule
title: Ingress Transfer via Windows BITS
detection:
    selection_bits:
        process.name: 'svchost.exe'
        # BITS job wrote a file
    selection_filetype:
        file.extension:
            - 'exe'
            - 'dll'
            - 'zip'
            - 'rar'
        # OR PE magic-byte header present
    condition: selection_bits and selection_filetype
```

### Why it misses

`payload.7z`, `stage.py`, `loader.psm1`, or `macro.xlsm` transferred by the same BITS job satisfy `selection_bits` but not `selection_filetype`, so the rule never fires. The extension list encodes an assumption that malicious ingress is always a PE or a common archive.

## Hardened Rule

```yaml
title: Suspicious BITS Ingress by File Type (Hardened)
description: |
    Do not rely on a positive list of "bad" extensions. Alert on BITS-delivered
    files broadly, then suppress known-good, rather than enumerating bad types.
detection:
    selection_bits_write:
        process.name: 'svchost.exe'
        # correlated to a BITS-Client job (EID 59/60) writing to disk
    filter_trusted_dest:
        file.path|startswith:
            - 'C:\Windows\SoftwareDistribution\'
            - 'C:\ProgramData\Microsoft\Windows\'
    filter_signed:
        file.code_signature.trusted: true
    condition: selection_bits_write and not (filter_trusted_dest or filter_signed)
falsepositives:
    - WSUS/SCCM and vendor auto-updaters using BITS
level: medium
```

### Why the hardened rule works

It inverts the logic: match **BITS-delivered files generally**, then subtract trusted destinations/signers — so a novel or uncommon extension can't slip through a positive allow-list. Where a type filter is unavoidable, expand it to the full class above and add extensionless/mismatched handling, and corroborate with the [BITS-Client event log](../ADE2-01-method-binary/bits-jobs.md).

## Detection Layers

| Audit method | Catches type swap? | How |
|---|---|---|
| Positive extension list | No | Any unlisted extension passes |
| PE magic-byte check | No | Non-PE payloads (scripts, archives, docs) pass |
| Match broadly + suppress known-good | Yes | Coverage no longer depends on predicting every bad type |
| Behavior after transfer | Yes | Unpack/exec of the delivered file is format-independent |
| Content inspection | Partial | Detects payloads inside archives/docs but is costly and evadable |
| Emulate with an omitted type | Yes | Transfer `.7z`/`.xlsm` via BITS; confirm the rule fires |

## Implementation Nuances

- ADE2-04 stacks with ADE2-01 (the delivery *method*) and ADE3-02 (a co-located exclusion/threshold) on the same BITS rule — the corpus flagged all three on this one rule, giving independent, stackable bypass paths.
- A positive "bad extensions" list is the anti-pattern; prefer "alert broadly, suppress trusted." The list of payload-capable formats only grows (new archive tools, new script engines, new OOXML variants).
- Extension ≠ content: a payload can be transferred as `.txt` and renamed, or executed by engine flag regardless of extension (see [Implementation Nuances #13](../../../bug_patterns/logging_assumption_errors.md) — wscript `//e:` engine selection).

## References

- [MITRE ATT&CK T1105 — Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1027 — Obfuscated Files or Information](https://attack.mitre.org/techniques/T1027/)
- [Elastic detection-rules — Ingress Transfer via Windows BITS](https://github.com/elastic/detection-rules/blob/main/rules/windows/command_and_control_ingress_transfer_bits.toml)
