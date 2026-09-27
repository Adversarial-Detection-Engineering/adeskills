# ADE2-01 · Method / Binary / Tool

Parent category: [ADE2 — Omit Alternatives](../overview.md)

Detection searches for a specific method, binary, or tool while functionally equivalent alternatives exist within scope and are omitted. The attacker uses whichever implementation is unmonitored (e.g., `mimikatz.exe` covered but not `comsvcs.dll`/ProcDump/nanodump; `certutil` but not `bitsadmin`/`esentutl`).

**Why it's a bug:** defenders enumerate what they have seen; attackers use what they have not. Any rule anchored to a single binary or API name is one alternative away from bypass. Detect the *behavior/outcome* rather than the tool name.

## Techniques

- [WSL Bypass](wsl-bypass.md)
- [BITS Jobs](bits-jobs.md)
- [Certutil Variations](certutil-variations.md)
- [MSBuild Inline Tasks](msbuild-inline-tasks.md)
- [CMSTP INF Injection](cmstp-inf-injection.md)
- [Regsvr32 Scriptlet](regsvr32-scriptlet.md)
- [Mshta Execution](mshta-execution.md)

## See also

- [credential_access_alternatives.md](../../../bug_patterns/credential_access_alternatives.md) · [windows_api_wmi.md](../../../bug_patterns/windows_api_wmi.md) · [persistence_alternatives.md](../../../bug_patterns/persistence_alternatives.md) · [network_download_evasion.md](../../../bug_patterns/network_download_evasion.md)
