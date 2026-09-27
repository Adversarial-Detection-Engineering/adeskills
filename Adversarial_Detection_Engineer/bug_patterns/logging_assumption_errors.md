# Implementation Nuances

Critical gotchas for anyone writing or deploying detection rules. Each entry is a place where a reasonable-looking rule silently fails because a logging, parsing, or backend assumption doesn't hold in practice. Every technique in this repo has been checked against these — verify your own rules before deployment.

Items are numbered and stable: other documents reference them as **NUANCES #N**, so numbers never change. New nuances are appended, not renumbered.

## Quick index by theme

- **Binary & process identity:** #1 (OriginalFileName anomalies), #4 (.mui stripping), #10 (8.3 short names), #11 (OriginalFileName survives rename), #12 (hashes at process start), #20 (ordinal exports)
- **Command-line fidelity & parsing:** #2 (raw, not deobfuscated), #3 (Image contains spaces), #7 (parameter prefix parsing), #9 (boolean values cosmetic), #13 (wscript engine flag), #18 (length limits/truncation), #19 (env-var runtime resolution), #21 (path canonicalization)
- **Telemetry availability & boundaries:** #6 (correlation timeframes), #8 (WSL2 boundary), #14 (4688 command-line auditing), #15 (PowerShell v2 downgrade), #16 (Script Block Logging chunking), #17 (AMSI patching), #22 (time zones/clock skew), #23 (Sysmon config coverage)
- **Backend & query behavior:** #5 (regex flavor varies)

Each item is tagged with the ADE category it most directly informs.

---

## 1. OriginalFileName Is Not Always What You Expect

*(ADE1-01, ADE2-01, ADE3-01)*

The PE `VERSION_INFO` `OriginalFileName` field frequently differs from the binary name on disk. Before writing ANY rule that uses `OriginalFileName`, query Sysmon EID 1 for the actual value:

```powershell
Get-WinEvent -LogName "Microsoft-Windows-Sysmon/Operational" `
  -FilterXPath "*[System[EventID=1] and EventData[Data[@Name='Image'] and contains(Data,'binary.exe')]]" `
  -MaxEvents 1 |
  ForEach-Object {
    ([xml]$_.ToXml()).Event.EventData.Data |
      Where-Object { $_.Name -eq 'OriginalFileName' }
  }
```

Known anomalies:

| Binary on disk | OriginalFileName in Sysmon | Why |
|---|---|---|
| `pwsh.exe` | `pwsh.dll` | PowerShell 7 is a .NET host; the DLL is the "original" |
| `nltest.exe` | `nltestrk.exe` | Internal Microsoft name from Resource Kit lineage |
| `systeminfo.exe` | `sysinfo.exe` | Truncated internal name |

**Rule pattern** — always OR the Image and OriginalFileName fields:

```yaml
detection:
  selection:
    - Image|endswith: '\pwsh.exe'
    - OriginalFileName:
        - 'pwsh.dll'
        - 'pwsh.exe'
```

## 2. Sysmon CommandLine Is Raw, Not Deobfuscated

*(ADE1-01)*

Sysmon logs the command line exactly as the parent process passed it. Carets (`w^h^o^a^m^i`), quotes (`who"a"mi`), extra spaces, and environment-variable references are preserved verbatim. The OS parser strips them at execution time — Sysmon does not.

- **Substring matches break** on any reformatting technique.
- **Regex rules must account** for optional junk characters between meaningful tokens.
- **Script Block Logging (EID 4104)** shows the deobfuscated PowerShell — but only for PowerShell, not cmd.exe (and see #15/#16 for when even that goes blind).

## 3. Image Field Can Contain Spaces

*(ADE1-01)*

`Image` is populated from OS process metadata, not parsed from the command line. Binaries under `C:\Program Files\...` legitimately contain spaces in the path. Rules using `Image|contains` must account for this: the field is NOT whitespace-immune — it accurately reflects the real path, spaces included. This is the opposite failure mode from #2: here the spaces are real path components, not parser artifacts.

## 4. Sysmon .mui Suffix Stripping

*(ADE2-01)*

Some binaries carry `filename.exe.mui` in their PE `VERSION_INFO`. Sysmon strips the `.mui` suffix before logging `OriginalFileName`. If you inspect the PE directly (e.g., `Get-Item ... | Select-Object VersionInfo`), you may see the `.mui` — Sysmon won't. Write rules against the stripped form (`certutil.exe`, not `certutil.exe.mui`).

## 5. Sigma `|re` Regex Flavor Varies by Backend

*(ADE4-04)*

Sigma regex patterns compile differently across SIEM backends:

| Backend | Regex Engine | Lookahead/Lookbehind |
|---------|-------------|---------------------|
| Splunk | PCRE | Yes |
| Elasticsearch | Lucene regex | No |
| Microsoft Sentinel (KQL) | RE2 | No |
| Google SecOps (YARA-L) | RE2 | No |
| CrowdStrike LogScale | RE2 | No |

Stick to basic regex features (character classes, quantifiers, alternation, grouping) unless you are targeting a specific backend. Always confirm the regex compiles before publishing — a rule that fails to transpile is a silent zero-coverage gap.

## 6. Correlation Rule Timeframes

*(ADE3-03)*

Multi-event correlations depend on `timeframe`/`maxspan` settings:

- Too short (5s): misses attackers who add `sleep` between commands.
- Too long (10m): generates false positives from normal admin activity.
- Document the tradeoff in each technique that uses correlation.

## 7. PowerShell Parameter Prefix Parsing

*(ADE1-01)*

PowerShell accepts both `-` and `/` as parameter prefixes, and any *unambiguous* prefix abbreviation. `-e`, `-en`, `-enc`, … `-EncodedCommand` all resolve to the same parameter. Rules must use a regex covering the minimum unambiguous prefix, not just the full parameter name. The same applies to `nslookup`, `netsh`, and other tools with prefix-abbreviated parameters. (Sigma's `|windash` modifier handles the `-`/`/` half of this.)

## 8. WSL2 Telemetry Boundary

*(ADE2-01, ADE3)*

| Action | Visible to Windows Sysmon? |
|--------|---------------------------|
| WSL interop (calling `.exe` from WSL) | Yes — EID 1, parent = `wsl.exe` |
| Linux-native commands (including Linux `pwsh`) | No |
| File writes via `/mnt/c/` | Yes — EID 11 via `dllhost.exe` |
| Network connections from WSL2 | No — the Hyper-V VM has its own network stack |

Windows-side Sysmon cannot see inside WSL2. You need SysmonForLinux (eBPF) or an EDR agent installed inside the distro.

## 9. Boolean Values Are Cosmetic in PowerShell

*(ADE1-01)*

`-Force:$true`, `-Force:1`, `-Force`, and `-Force:([bool]::Parse('true'))` are all identical to the engine. Rules matching the value portion (`:$true`, `:1`) miss the other forms. Match the parameter NAME only.

## 10. NTFS 8.3 Short Names in Image Field

*(ADE1-02, ADE2-03)*

If a process is launched via its 8.3 short name (`C:\PROGRA~1\...`), Sysmon may log the short name in the `Image` field. Some Sysmon versions resolve to the long name, some don't — test on your target version. Rules using `Image|endswith: '\Program Files\'` will miss `\PROGRA~1\`.

## 11. OriginalFileName Survives Binary Copy/Rename

*(ADE2-01, ADE3-01)*

When an attacker copies `cmd.exe` to `C:\Users\Public\svchost.exe`, the `Image` field shows `C:\Users\Public\svchost.exe` but `OriginalFileName` still shows `Cmd.Exe`. This is the single most reliable field for binary identity — it comes from the PE header, not the filesystem.

## 12. Sysmon Hashes Are Computed at Process Start

*(ADE2-01, ADE3-01)*

Sysmon computes file hashes (MD5, SHA256, IMPHASH) when the process starts. Even if the attacker deletes or modifies the binary after execution, the hash in the EID 1 event reflects the file at launch time. Use hash-based detection as a complement to name-based detection for known-bad binaries.

## 13. WScript/CScript Execute Without a .vbs Extension via `//e:`

*(ADE1-01, ADE2-04)*

`wscript.exe` and `cscript.exe` accept `//e:<engine>` to explicitly specify the script engine, bypassing any file-extension check. A file with no extension, a random name, or an NTFS alternate-data-stream path is executed as VBScript (or JScript) when the engine flag is present. The `//b` flag additionally suppresses all dialog boxes (batch/silent mode).

```cmd
:: Execute VBScript from a file with no extension — %TEMP%\:divedz0f is an ADS on the TEMP directory
wscript.exe "%TEMP%\:divedz0f" [RANDOM ARGS] //b //e:vbscript

:: Equivalent for JScript
wscript.exe payload.txt //b //e:jscript
```

**Rule pattern that fails:**

```yaml
detection:
  selection:
    Image|endswith:
      - '\wscript.exe'
      - '\cscript.exe'
    CommandLine|contains: '.vbs'
  condition: selection
```

`CommandLine|contains: '.vbs'` misses every invocation where the engine is declared via `//e:vbscript` instead of the file extension. The extension is irrelevant when the engine flag is present.

**Hardened pattern** — match extension OR engine flag:

```yaml
detection:
  selection_img:
    - Image|endswith:
        - '\wscript.exe'
        - '\cscript.exe'
    - OriginalFileName:
        - 'wscript.exe'
        - 'cscript.exe'
  selection_ext:
    CommandLine|contains:
      - '.vbs'
      - '.js'
  selection_engine:
    CommandLine|re|i: 'e:(vbscript|jscript)'
  condition: (selection_img) and (selection_ext or selection_engine)
```

The NTFS ADS variant (`%TEMP%\:divedz0f`) stores the payload in the named stream of a directory rather than a standalone file, further reducing filesystem visibility — no conventional file exists at that path. Combine with Sysmon EID 15 (FileCreateStreamHash) to detect ADS writes.

## 14. Windows Security 4688 Command-Line Auditing Is Off by Default

*(ADE4-04, ADE2-02)*

A rule keyed on `CommandLine` behaves very differently depending on whether the event comes from Sysmon EID 1 or Windows Security EID 4688:

- **Sysmon EID 1** always includes the full command line (subject to config — see #23).
- **Security EID 4688** includes a command line **only if two things are enabled**: the *Audit Process Creation* subcategory, **and** the GPO *Administrative Templates → System → Audit Process Creation → Include command line in process creation events* (registry `ProcessCreationIncludeCmdLine_Enabled`). The 4688 field is literally named `Process Command Line`, not `CommandLine`.
- On Windows ≤ 7 / Server 2008 R2, 4688 has no command-line field at all.

A cross-source rule authored against Sysmon field names, applied to a 4688-only host with command-line auditing off, matches **nothing** and does so silently. Pin the log source (`service: sysmon`) or explicitly handle both event IDs and both field names.

## 15. PowerShell v2 Downgrade Blinds AMSI and Script Block Logging

*(ADE2-01, ADE1-01)*

`powershell.exe -Version 2` launches the legacy v2 engine when the .NET 2.0/3.5 feature is present. The v2 engine predates **AMSI** (Windows 10 / PS 5.0) and has **no Script Block Logging (EID 4104)** and no module logging. Every deobfuscation-based detection in #2/#16/#17 goes dark; only the raw process command line remains.

```
powershell -version 2 -Command "IEX(...)"
powershell -v 2 -enc <base64>
```

Detect the downgrade itself, regardless of payload: match `-version 2` / `-v 2` on the command line, and corroborate with **EID 400** (`EngineVersion=2.0`) from the PowerShell operational log. Absence of expected 4104 events for an observed powershell.exe launch is itself a signal.

## 16. Script Block Logging Chunks Large Scripts (EID 4104)

*(ADE3-04)*

Script Block Logging does not guarantee one script = one event. Large script blocks are split across multiple EID 4104 events, each carrying `MessageNumber` and `MessageTotal` fields; the full script only exists once the chunks are reassembled. Consequences:

- A `contains|all` rule expecting several indicators in a single 4104 event can miss indicators that landed in different chunks — the same single-event blind spot as command fragmentation (#2, ADE3-04), but inside the logging layer.
- With full SBL disabled, PowerShell still auto-logs *suspicious* blocks at warning level, so partial coverage exists even when operators think logging is off — don't assume silence means safety, and don't assume completeness either.

Reassemble on `ScriptBlockId` + `MessageNumber`/`MessageTotal` before applying multi-token logic, or match per-chunk primitives.

## 17. AMSI Sees Deobfuscated Code — Until It's Patched Out

*(ADE3)*

AMSI (`amsi.dll`, `AmsiScanBuffer`) scans content **after** the runtime deobfuscates it, covering PowerShell, VBA, JScript/VBScript, and .NET. That makes it powerful — and a target. In-process bypasses neutralize it without leaving process-creation telemetry:

- Patching `AmsiScanBuffer`/`AmsiOpenSession` in memory
- Forcing `amsiInitFailed = $true` via reflection
- Unregistering or corrupting the AMSI provider
- Downgrading to an engine with no AMSI (see #15)

Treat AMSI results as high-value but not guaranteed. Monitor for AMSI tampering (AMSI/Defender ETW providers such as `Microsoft-Antimalware-Scan-Interface`, unexpected writes to `amsi.dll` regions) as its own signal — this is telemetry-integrity monitoring, the same principle as ETW blinding (ADE3).

## 18. Command-Line Length Limits and Field Truncation

*(ADE1-01, ADE4-04)*

Two different length ceilings bite detection:

- **Execution ceiling:** `cmd.exe` caps a command line at ~8191 characters; PowerShell and `CreateProcess` have their own limits. Payloads are engineered around these (staging, here-strings, encoded blobs).
- **Telemetry ceiling:** some collection paths truncate the command-line field before it reaches the rule — historically certain EDR/`DeviceProcessEvents` tables and constrained log-forwarding transports. An attacker can pad the front of the command line with whitespace or comments to push the meaningful indicator **past** the truncation boundary, so a `contains` match on the tail never sees it.

Anchor on early, structural tokens (the image, the first switch) rather than deep substrings, and know your pipeline's field-size limits.

## 19. Environment Variables Resolve at Runtime, Not in the Logged String

*(ADE1-01, ADE2-03)*

`%COMSPEC%`, `%SystemRoot%`, `%ProgramData%`, and delayed-expansion `!var!` are expanded by the interpreter at execution time. Sysmon logs the parent command line with the **unexpanded token as typed**, while the resulting child process's `Image` shows the **resolved** path. A rule matching `cmd.exe` against a parent command line misses `%comspec% /c ...`; a rule matching a literal path misses `%SystemRoot%\System32\...`.

Detect on the child's resolved `Image`, or add patterns for the common variable forms (`%comspec%`, `%systemroot%`, `%windir%`) alongside the literal paths. See ADE1 *env-variable-splicing* for the substring-extraction variant.

## 20. DLL Exports Can Be Called by Ordinal

*(ADE2-01)*

`rundll32.exe` and `regsvr32.exe` can invoke a DLL export by its **ordinal number** instead of its name. The canonical LSASS-dump line is usually written with the export name, but the same export has an ordinal:

```
rundll32 C:\Windows\System32\comsvcs.dll, MiniDump <pid> out.dmp full
rundll32 C:\Windows\System32\comsvcs.dll, #24 <pid> out.dmp full
```

A rule matching `CommandLine|contains: 'MiniDump'` misses the `#24` form entirely. When detecting export-based execution, match the DLL + the ordinal pattern (`,#\d+`) as well as known export names, or anchor on the module load / behavior instead of the string.

## 21. Path Canonicalization: Device, UNC, and Symlink Forms

*(ADE1-02, ADE2-03)*

The same file is reachable through many path spellings that a naive path match won't cover. Beyond 8.3 short names (#10):

| Form | Example |
|------|---------|
| Extended-length / device | `\\?\C:\Windows\System32\cmd.exe`, `\??\C:\...` |
| GLOBALROOT / volume shadow | `\\?\GLOBALROOT\Device\HarddiskVolumeShadowCopy1\...` |
| UNC to local admin share | `\\127.0.0.1\C$\Windows\System32\cmd.exe` |
| Forward slashes | `C:/Windows/System32/cmd.exe` |
| Trailing dot/space, mixed case | `cmd.exe ` , `C:\WINDOWS\SYSTEM32\CMD.EXE` |
| Symlink / junction / hardlink | a link in a user-writable dir pointing at the real binary |

Anchor on `OriginalFileName`/hash (#11, #12) where possible; when a path match is unavoidable, normalize separators and case and account for the device/UNC prefixes. On Linux, the analogous traps are symlinks, bind mounts, and `$PATH` ordering.

## 22. Timestamps, Time Zones, and Clock Skew

*(ADE3-03)*

Correlation logic assumes events can be ordered on a common clock. In practice:

- Sysmon events carry an explicit `UtcTime` field in EventData; the Security log's rendered time is derived from the record's UTC `SystemTime`. Mixing a rendered local time with a UTC field in the same correlation misaligns events.
- Across hosts, **clock skew** shifts a multi-step attack's apparent timing, so a tight `maxspan` (#6) can drop legitimately-related events or, worse, reorder cause and effect.
- Sequence/`maxspan` rules should normalize everything to UTC and leave slack for skew; consider host-level time-sync monitoring as a prerequisite for time-based detections.

## 23. Your Sysmon Config Decides What Exists

*(ADE4-04)*

Every field and event this document relies on is only present if the deployed Sysmon configuration emits it. A minimal or aggressively-filtered config can:

- Exclude whole event IDs (no EID 11 file-create, no EID 3 network, no EID 15 ADS) that a correlation rule depends on.
- Drop or not compute fields (e.g., hashing disabled → no `Hashes` for #12; `CommandLine` present but `OriginalFileName` filtered).
- `<Exclude>` the very processes an attacker abuses (common `svchost.exe`/`msbuild.exe`/`rundll32.exe` noise-reduction excludes create exact ADE2-01 blind spots).

A rule is only as good as the config feeding it. Validate that the target field/EID is actually being produced in the environment before claiming coverage — this is the environment-drift question of the ADE scoping lens made concrete.
