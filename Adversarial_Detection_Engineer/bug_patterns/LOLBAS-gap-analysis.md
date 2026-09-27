# LOLBAS Gap Analysis

**Variants that the [LOLBAS project](https://github.com/LOLBAS-Project/LOLBAS) does not capture** (alternative commands, flag/format variations, and detection nuances). It is a contribution backlog — each item names the LOLBAS `.yml` to update and the evasion-eng source to update it *from*.

*
**Scope note.** LOLBAS's data model is *binary → canonical Command → Category → Detection/IOC → Resources*. Some knowledge maps cleanly to a new `Command` entry; some only fits `Detection`/`IOC`/`Resources`; and one whole class (command-line obfuscation) has **no field** in the LOLBAS schema at all. Each item below is tagged with where it lands.

---

## Summary

| # | LOLBAS entry | Gap | Lands in | Priority |
|---|--------------|-----|----------|----------|
| 1 | `yml/OSBinaries/Mshta.yml` | `about:` protocol inline-script execution | new `Command` (Execute) | **High** |
| 2 | `yml/OSBinaries/Cmstp.yml` | UAC bypass via CMSTPLUA COM; `RunPreSetupCommandsSection` INF | new `Command` + `UAC Bypass` category | **Medium** |
| 3 | `yml/OSBinaries/Bitsadmin.yml` | Network/file activity attributed to `svchost.exe` (BITS QMGR), not bitsadmin; COM `IBackgroundCopyManager` interface | `IOC` / `Resources` | **Medium** |
| 4 | `yml/OtherMSBinaries/Wsl.yml` | Linux-native execution is invisible to Windows Sysmon; `/mnt/c/` writes surface as `dllhost.exe` EID 11; WSL2 network bypasses host stack | `IOC` / `Detection` | **Medium** |
| 5 | `yml/OSBinaries/Msbuild.yml` | `/pp` (`/preprocess`) abuse | new `Command` | Low |
| 6 | `yml/OSBinaries/Certutil.yml` | `-decode`/`-decodehex` written into an ADS (only `-urlcache`→ADS shown) | new `Command` (ADS) | Low |
| — | **All 248 entries** | Command-line obfuscation / flag-prefix variation equivalence class | schema gap — see [Cross-cutting](#cross-cutting-gap-command-line-obfuscation--flag-variation) | **High (systemic)** |

**Already well covered in LOLBAS (no action):** Regsvr32 (Squiblydoo remote/local + DLL register/unregister), Msbuild inline `CodeTaskFactory` + `/logger` + `@rsp`, Certutil download/decode subcommands, Bitsadmin ADS/Download/Copy/Execute commands.

---

## Per-binary detail

### 1. Mshta — `about:` protocol execution *(High)*

- **LOLBAS has:** `mshta.exe {PATH:.hta}`, `vbscript:Close(Execute(...))`, `javascript:...`, ADS `{PATH}:file.hta`, remote-URL download.
- **evasion-eng adds:** the `about:` protocol form —
  ```cmd
  mshta "about:<script language='VBScript'>MsgBox ""test"":close</script>"
  ```
  A fourth inline-execution moniker distinct from the `vbscript:`/`javascript:` entries LOLBAS already lists.
- **Source:** [ADE2/mshta-execution](../ade_framework/ADE2/ADE2-01-method-binary/mshta-execution.md) → "Execution modes" #4.
- **Suggested edit:** add a `Command` under `Category: Execute`, `MitreID: T1218.005`, tag `Execute: VBScript`.

### 2. Cmstp — UAC bypass + INF section variants *(Medium)*

- **LOLBAS has:** `cmstp.exe /ni /s {PATH:.inf}` (Execute), `/ni /s {REMOTEURL:.inf}` (AWL Bypass), `cmstp.exe /nf`.
- **evasion-eng adds:**
  - **UAC bypass via the `CMSTPLUA` COM object** — cmstp auto-elevates, so it is a privilege-escalation proxy, not just an execution proxy. LOLBAS has **no `UAC Bypass` category entry** for cmstp.
  - The malicious-INF anatomy showing **`RunPreSetupCommandsSection`** (arbitrary pre-install commands), complementing the `UnRegisterOCXSection`/`scrobj.dll` pattern.
- **Source:** [ADE2/cmstp-inf-injection](../ade_framework/ADE2/ADE2-01-method-binary/cmstp-inf-injection.md).
- **Suggested edit:** add a `UAC Bypass` `Command` (`MitreID: T1548.002`) and reference the INF section in a `Command` `Description`.

### 3. Bitsadmin — correct the network/file attribution *(Medium)*

- **LOLBAS IOCs say:** "Child process from bitsadmin.exe", "bitsadmin creates new files", "bitsadmin adds data to alternate data stream".
- **evasion-eng correction/addition:** the client `bitsadmin.exe` only *queues* the job; the **BITS service (QMGR) inside `svchost.exe -k netsvcs`** opens the socket and writes the file. So:
  - Sysmon **EID 3 (NetworkConnect)** attributes the download to `svchost.exe`, not bitsadmin.
  - Sysmon **EID 11 (FileCreate)** attributes the write to `svchost.exe`.
  - Rules correlating "bitsadmin process + its own network connection" find no match.
  - There are **three interfaces**: `bitsadmin.exe`, `Start-BitsTransfer`, and the **COM `IBackgroundCopyManager`** API (no bitsadmin/PowerShell process at all).
- **Source:** [ADE2/bits-jobs](../ade_framework/ADE2/ADE2-01-method-binary/bits-jobs.md).
- **Suggested edit:** refine the `IOC` block (add the svchost EID 3/11 attribution) and note the COM interface in `Resources`.

### 4. Wsl — telemetry blind-spot notes *(Medium)*

- **LOLBAS has:** `wsl.exe -e ...`, `wsl -u root -e cat /etc/shadow`, `wsl --exec bash -c "{CMD}"`, `/dev/tcp` download, bare `wsl.exe` — all as `Command`s, with **no detection notes**.
- **evasion-eng adds** (the operationally important part):
  | Action | Visible to Windows Sysmon? |
  |--------|----------------------------|
  | WSL interop (`.exe` from WSL) | Yes — EID 1, parent `wsl.exe` |
  | Linux-native commands (incl. Linux `pwsh`) | **No** |
  | File writes via `/mnt/c/` | Yes — EID 11 as **`dllhost.exe`** |
  | WSL2 network connections | **No** — Hyper-V VM has its own stack |
- **Source:** [ADE2/wsl-bypass](../ade_framework/ADE2/ADE2-01-method-binary/wsl-bypass.md).
- **Suggested edit:** add `IOC` entries (`/mnt/c/` writes attributed to `dllhost.exe`; Linux-native activity absent from process telemetry).

### 5. Msbuild — `/pp` preprocess *(Low)*

- **LOLBAS has:** `.xml`/`.csproj`/`.proj` inline tasks, `/logger:...`, `@{PATH:.rsp}`.
- **evasion-eng adds:** `/pp` (`/preprocess`) abuse for information gathering.
- **Source:** [ADE2/msbuild-inline-tasks](../ade_framework/ADE2/ADE2-01-method-binary/msbuild-inline-tasks.md) → "Additional attack vectors".

### 6. Certutil — decode-into-ADS *(Low)*

- **LOLBAS has:** ADS only for the `-urlcache` download variant.
- **evasion-eng adds:** the download→decode pipeline can also target an ADS output path (`file.txt:payload.exe`) on the `-decode`/`-decodehex` step.
- **Source:** [ADE2/certutil-variations](../ade_framework/ADE2/ADE2-01-method-binary/certutil-variations.md) → "NTFS Alternate Data Streams".

---

## Cross-cutting gap: command-line obfuscation & flag variation

This is the largest and most systemic gap, and it applies to **every** LOLBAS entry. LOLBAS records each technique's **one canonical, clean command line**. evasion-eng documents the **equivalence class** an attacker draws from — the same execution, arbitrarily reformatted — which is exactly what defeats the detections LOLBAS links in its `Detection` sections.

LOLBAS has no schema field for this, so the contribution is either (a) a per-entry `Resources` link to evasion-eng, or (b) an upstream discussion about representing obfuscation. The evasion-eng catalog:

| Variation class | Example (applied to a LOLBin) | evasion-eng source |
|-----------------|-------------------------------|--------------------|
| Flag-prefix / abbreviation | `powershell -ec` … `-e` (24+ spellings), `nslookup` prefix tricks | [ADE1/parameter-variation](../ade_framework/ADE1/ADE1-01-substring-manipulation/parameter-variation.md) |
| Caret insertion (cmd) | `c^ertu^til -urlcache …` | [ADE1/caret-insertion](../ade_framework/ADE1/ADE1-01-substring-manipulation/caret-insertion.md) |
| Quote splicing | `cert""util -de""code …` | [ADE1/quote-manipulation](../ade_framework/ADE1/ADE1-01-substring-manipulation/quote-manipulation.md) |
| Whitespace manipulation | tabs / runs of spaces between tokens | [ADE1/whitespace-manipulation](../ade_framework/ADE1/ADE1-01-substring-manipulation/whitespace-manipulation.md) |
| Env-variable splicing | `%comspec%`, substring slicing of env vars | [ADE1/env-variable-splicing](../ade_framework/ADE1/ADE1-01-substring-manipulation/env-variable-splicing.md) |
| PowerShell tick escaping | `certu`​`til` | [ADE1/powershell-tick-escaping](../ade_framework/ADE1/ADE1-01-substring-manipulation/powershell-tick-escaping.md) |
| NTFS short names | `CERTUT~1.EXE` in place of `certutil.exe` | [ADE1/ntfs-short-names](../ade_framework/ADE1/ADE1-02-normalization-asymmetry/ntfs-short-names.md) |
| Boolean / delimiter swaps | `,`/`;`/`=` delimiter juggling, boolean value swaps | [ADE1/delimiter-manipulation](../ade_framework/ADE1/ADE1-01-substring-manipulation/delimiter-manipulation.md), [boolean-replacement](../ade_framework/ADE1/ADE1-01-substring-manipulation/boolean-replacement.md) |
| Full obfuscation stack | Unicode look-alikes + quote splice + casing on a `certutil` cradle | [ADE1/obfuscation](../ade_framework/ADE1/ADE1-01-substring-manipulation/obfuscation.md) |

**Why LOLBAS should care:** its `Detection` links point at Sigma/Splunk/Elastic rules that mostly `|contains` the *literal* canonical string. Every row in the table above is a documented way past those exact rules. The evasion-eng framing (ADE1 = "reformatting in actions") is the reusable vocabulary for that.

---

## How to refresh this analysis

```bash
# 1. Update the LOLBAS clone
git -C "C:/Users/nikdb/Research/evasion-eng-main/LOLBAS" pull --ff-only

# 2. Re-run the category inventory (adjust paths as needed)
cd "C:/Users/nikdb/Research/evasion-eng-main/LOLBAS"
python -c "import glob,yaml,collections; \
c=collections.Counter(); \
[c.update([x.get('Category') for x in (yaml.safe_load(open(f,encoding='utf-8')).get('Commands') or [])]) \
for f in glob.glob('yml/**/*.yml',recursive=True)]; print(c.most_common())"
```

Then re-diff the per-binary `Commands` against the matching `ade_framework/ADE2/ADE2-01-method-binary/*.md`.
