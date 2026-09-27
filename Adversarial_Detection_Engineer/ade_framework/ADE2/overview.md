# ADE2: Omit Alternatives

A detection rule covers one tool, API, path, version, or file type but omits functionally equivalent **alternatives** that are in scope and achieve the same outcome, producing a false negative. The alternative was available during the attack and within the rule's scope — it was simply left out of the detection logic.

## Core Insight

Defenders enumerate what they've seen; attackers use what they haven't. Any rule anchored to a single binary or API name is one alternative away from bypass.

## Why It Happens

1. **Incomplete threat research** — not exhaustively enumerating alternatives
2. **Platform assumptions** — assuming one OS, version, or deployment model
3. **Tool-specific knowledge** — only knowing the most common method
4. **Aging rules** — new APIs/versions released after rule creation
5. **Copy-paste detection engineering** — reusing patterns without validation

## Subcategories

### ADE2-01: Omit Alternatives — Method / Binary / Tool
Logic searches for specific methods or binaries, but functionally equivalent alternatives exist within scope and are omitted (e.g., detecting `mimikatz.exe` but not `rundll32 + comsvcs.dll`, ProcDump, or nanodump; `Invoke-WebRequest` but not `Invoke-RestMethod` / .NET `WebClient`; `powershell.exe` but not `pwsh.exe`). This is the dominant subcategory — every concrete technique below is a method/binary alternative.

### ADE2-02: Omit Alternatives — Versioning
Logic assumes a fixed software, OS, or API version while other in-scope versions bypass it (OS/distro path differences, deprecated → replacement APIs, protocol version changes).

### ADE2-03: Omit Alternatives — Locations
Logic only searches specific paths/registry keys/URLs while other valid in-scope locations are missed (`Program Files` vs `Program Files (x86)`, `HKLM` vs `HKCU`, distro cron path differences, region-specific endpoints).

### ADE2-04: Omit Alternatives — File Types
Logic checks specific extensions/types, omitting in-scope alternatives (`.zip` but not `.7z`/`.tar`/`.gz`; `.exe` but not `.com`/`.scr`/`.pif`; `.ps1` but not `.psm1`/`.psd1`; `.docx` but not macro-enabled `.docm`).

> Related: the *encoding/obfuscation* variant of "alternate data source" overlaps heavily with **ADE1 (Reformatting)** — see `../ADE1/overview.md` and `../../bug_patterns/cmdline_obfuscation.md`.

## Techniques in This Category

All worked techniques below are method/binary alternatives (ADE2-01) — the download and execution LOLBins differ in objective but are the same taxonomy class.

### [ADE2-01 Method / Binary / Tool](ADE2-01-method-binary/)

| Technique | Target | Mechanism | From |
|-----------|--------|-----------|------|
| [WSL Bypass](ADE2-01-method-binary/wsl-bypass.md) | Windows EDR | Linux pwsh + WSL interop escapes Windows telemetry | DEaTHCon Demo 07 |
| [BITS Jobs](ADE2-01-method-binary/bits-jobs.md) | Download rules | bitsadmin/Start-BitsTransfer instead of certutil/curl | New |
| [Certutil Variations](ADE2-01-method-binary/certutil-variations.md) | Download rules | -decode, -decodehex, -verifyctl beyond -urlcache | New |
| [MSBuild Inline Tasks](ADE2-01-method-binary/msbuild-inline-tasks.md) | Execution rules | Arbitrary C# via .csproj, no suspicious cmdline | New |
| [CMSTP INF Injection](ADE2-01-method-binary/cmstp-inf-injection.md) | Execution rules | Connection Manager profile with payload in INF | New |
| [Regsvr32 Scriptlet](ADE2-01-method-binary/regsvr32-scriptlet.md) | Execution rules | Squiblydoo — COM scriptlet execution | New |
| [Mshta Execution](ADE2-01-method-binary/mshta-execution.md) | Execution rules | HTA/VBScript/JScript via mshta.exe | New |

### [ADE2-02 Versioning](ADE2-02-versioning/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Deprecated and Alternate API Versions](ADE2-02-versioning/deprecated-and-alternate-api-versions.md) | Rule pinned to one API/OS/service generation misses deprecated/replacement versions | Logic analysis | AWS RDS finding |
| [Log-Schema, Value, and Signature Drift](ADE2-02-versioning/log-schema-and-signature-drift.md) | Literal value / message format / static hash breaks on vendor update or recompile | Logic analysis | WAF, policy-rename, hash-drift findings |

### [ADE2-03 Locations](ADE2-03-locations/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Alternate Paths and Directories](ADE2-03-locations/alternate-paths-and-directories.md) | Path-anchored rule misses equivalent locations (profile.d, /tmp, cron.d) | Yes | Elastic Linux findings |
| [Source Location and Origin Distribution](ADE2-03-locations/identity-source-distribution.md) | Per-source thresholds / known-good-region baselines fall to proxies/VPNs | Logic analysis | Okta/M365/AWS identity findings |
| [Cloud and Application Destination Locations](ADE2-03-locations/cloud-destination-locations.md) | Fixed destination folders/sites/paths miss equivalent targets | Logic analysis | M365/SharePoint/spooler findings |

### [ADE2-04 File Types](ADE2-04-file-types/)

| Technique | Mechanism | Testable | From |
|-----------|-----------|----------|------|
| [Omitted File Extensions and Formats](ADE2-04-file-types/omitted-file-extensions.md) | Fixed extension list / magic-byte check misses equivalent formats | Yes | BITS ingress finding (DLE-2026-00005) |
| [Interpreter Wrapping and Extension Masquerade](ADE2-04-file-types/interpreter-wrapper-and-double-extension.md) | Run script via interpreter (process.name=bash) or rename/double-extension the file | Yes | Elastic/Sentinel findings |

Concrete alternative catalogs also live in the `bug_patterns/` references.

## Detection Strategy

1. **Behavioral grouping** — detect the BEHAVIOR (file download, code execution), not the specific TOOL
2. **Binary family enumeration** — if detecting certutil, also detect bitsadmin, esentutl, MpCmdRun, etc.
3. **Multi-event correlation** — file creation + network connection regardless of which binary did it
4. **OriginalFileName + Image OR** — catch renamed and alternative binaries
5. **Telemetry expansion** — for WSL, deploy SysmonForLinux or EDR inside the distro

## Testing Your Rules

- **Method/Binary:** Have you enumerated ALL methods/binaries achieving this outcome? Reflection/indirect invocation? Language-specific alternatives (PowerShell vs .NET vs WMI)?
- **Versioning:** When was the rule created — have APIs changed since? Does it work across all supported OS versions?
- **Locations:** 32-bit AND 64-bit paths? User-writable locations? Different Linux distributions?
- **File Types:** All relevant extensions? Magic-byte validation? Compressed/archived variants?

## Related Categories

- **ADE1 (Substring Manipulation)** — alternative methods also present different strings
- **ADE3 (Process Cloning)** — cloned binaries are "alternative" execution locations/names
- **ADE4 (Incorrect Expression)** — logic errors compound omission issues

## Reference Catalogs

Concrete, objective-organized alternative catalogs live in `bug_patterns/`:

- `../../bug_patterns/credential_access_alternatives.md` — LSASS/SAM/credential-tool alternatives
- `../../bug_patterns/windows_api_wmi.md` — process-creation and other Windows API/WMI alternatives
- `../../bug_patterns/persistence_alternatives.md` — persistence mechanism alternatives
- `../../bug_patterns/network_download_evasion.md` — download methods and protocol/channel alternatives
