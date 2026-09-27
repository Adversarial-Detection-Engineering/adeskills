---
id: ADE2-014
title: Interpreter Wrapping and Extension Masquerade
ade_category: ADE2
ade_subcategory: ADE2-04
mitre_attack:
  - T1059 (Command and Scripting Interpreter)
  - T1036.007 (Masquerading: Double File Extension)
platform: Cross-platform
testable: true
---

# Interpreter Wrapping and Extension Masquerade

## Summary

Two closely-related ADE2-04 moves that both defeat file-type/extension logic without changing the payload:

- **Interpreter wrapping** — instead of executing a script directly (so `process.name` = the script), run it *through its interpreter* (`bash script.sh`, `python3 exploit.py`), so `process.name` = the interpreter and the rule's script-name / extension list never matches.
- **Extension masquerade** — rename or double-extension the file (`calc.exe` → `invoice.odt`, `payload.jpg`, `SystemUpdate.jpg.ps1`) so the reported `file.extension` / `FileName` is benign while the content/engine is unchanged.

Both appear repeatedly across the Elastic and Sentinel rulesets flagged ADE2-04.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-04 — File Types
**Core principle:** the file's *type as the rule perceives it* — its extension, or the `process.name` of a script — is a wrapper the attacker chooses, not the behaviour. Interpreter invocation and extension renaming both change the perceived type while preserving execution.

## The Pattern

1. **Run via interpreter** — `bash /path/linpeas.sh` (process.name `bash`, not `linpeas.sh`); `python3 /tmp/exploit.py`; `perl /usr/sbin/adduser ...`; `tmux new -s x 'bash -c ...'`; `powershell.exe -File malicious.ps1` under a signed interpreter. The rule's `process.name in [...]` or script-extension check misses the interpreter form.
2. **Rename / wrong extension** — an executable or script given a benign or omitted extension: `.cer` not in an SSL-cert list, `.ashx`/`.dll` webshell not in `scriptExtensions`, `payload.jpg` loaded via `rundll32`, an extensionless binary in `/var/run/`.
3. **Double extension** — `InvoiceDetails.zip.vbs`, `SystemUpdate.jpg.ps1`, `invoice.settingcontent-ms.txt` — the tail or head extension reads as benign to a single-extension check (see [Implementation Nuances #13](../../../bug_patterns/logging_assumption_errors.md); classic Masquerading T1036.007).

## Documented instances (from the analysis corpus)

| Rule (platform) | Field | Bypass |
|---|---|---|
| Potential Linux Hack Tool Launched (Elastic) | `process.name` | `bash /path/linpeas.sh` → process.name is `bash` |
| Potentially Suspicious Process via tmux or screen (Elastic) | `process.name` | `tmux new -s x 'bash -c "reverse shell"'` |
| Linux User Added to Privileged Group (Elastic) | `process.name` | `perl /usr/sbin/adduser attacker sudo` (interpreter form) |
| Potential Impersonation Attempt via Kubectl (Elastic) | `process.parent.name` | Python script wraps `kubectl` → parent is `python3` |
| Execution of an Unsigned Service (Elastic) | `code_signature.*` | signed `powershell.exe` runs an unsigned `.ps1` |
| Rare Process as a Service (Sentinel/KQL) | `ProcessCommandLine` | service runs `powershell.exe -File malware.ps1` |
| SSL Certificate Deletion (Elastic) | `file.extension` | delete `.cer` cert not in the extension list |
| Silk Typhoon Suspicious File Downloads (Sentinel/KQL) | `Extension` | `.ashx` webshell / `.dll` ISAPI filter not in `scriptExtensions` |
| Executable File with Unusual Extension (Elastic) | `file.extension` | rename `calc.exe` → `.odt` and execute |
| Process Started from PID File (Elastic) | `process.executable` | extensionless `malware` in `/var/run/` executed as root |
| Suspicious Image Load related to IcedID (Sentinel/KQL) | `FileName` | rename malicious DLL `payload.jpg`, load via rundll32 |
| Exes with double file extension (Sentinel/KQL) | `OfficeObjectId` | upload `InvoiceDetails.zip.vbs` / `SystemUpdate.jpg.ps1` |

## Vulnerable Rule

```toml
# Paraphrased: hack-tool launch keyed to the script's own process.name
query = '''
process where event.type == "start" and
  process.name in ("linpeas.sh","lse.sh","pspy","LinEnum.sh")
'''
```

### Why it misses

`bash /tmp/linpeas.sh` sets `process.name` to `bash`; the script name appears only in `process.args`/`command_line`. The rule's `process.name` list never matches the interpreter form, so the recon tool runs undetected.

## Hardened Rule

```toml
query = '''
process where event.type == "start" and (
  process.name in ("linpeas.sh","lse.sh","pspy","LinEnum.sh") or
  // interpreter form: script name appears in the arguments
  (process.name in ("bash","sh","dash","python","python3","perl","ruby") and
   process.args : ("*linpeas*","*LinEnum*","*/lse.sh","*pspy*"))
)
'''
```

Match the script name in **`process.args`/`command_line`** as well as `process.name`, and for file-type rules prefer content/behaviour or "alert broadly + suppress known-good" over a positive extension list (see [Omitted File Extensions and Formats](omitted-file-extensions.md)).

## Detection Layers

| Audit method | Catches wrap/masquerade? | How |
|---|---|---|
| Match script name in args, not just process.name | Yes | Catches `bash script.sh` interpreter form |
| Inspect parent + child for interpreter chains | Yes | Python/Perl wrapping a target binary |
| Content/magic-byte over extension | Yes | Renamed/extensionless payloads still identified |
| Handle double extensions explicitly | Yes | Match any component, not the last one |
| Emulate interpreter + renamed forms | Yes | Reproduce `bash script.sh` and `payload.jpg`; confirm coverage |

## Implementation Nuances

- Interpreter wrapping overlaps [ADE3-01 Process Cloning](../../ADE3/ADE3-01-process-cloning/) (both make `process.name` unreliable) — anchor on args/behaviour, not the process name string.
- See [Implementation Nuances #13](../../../bug_patterns/logging_assumption_errors.md): `wscript //e:` selects the script engine regardless of extension — the Windows analogue of interpreter wrapping.
- Extension is content-independent; a positive extension list is the ADE2-04 anti-pattern (see the sibling [Omitted File Extensions and Formats](omitted-file-extensions.md)).

## References

- [MITRE ATT&CK T1059 — Command and Scripting Interpreter](https://attack.mitre.org/techniques/T1059/)
- [MITRE ATT&CK T1036.007 — Double File Extension](https://attack.mitre.org/techniques/T1036/007/)
- [Elastic detection-rules](https://github.com/elastic/detection-rules) · [Azure-Sentinel](https://github.com/Azure/Azure-Sentinel)
