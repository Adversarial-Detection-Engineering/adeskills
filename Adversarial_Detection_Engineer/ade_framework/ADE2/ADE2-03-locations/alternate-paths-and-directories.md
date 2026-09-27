---
id: ADE2-009
title: Alternate Paths and Directories
ade_category: ADE2
ade_subcategory: ADE2-03
mitre_attack:
  - T1037 (Boot or Logon Initialization Scripts)
  - T1074 (Data Staged)
platform: Linux
testable: true
---

# Alternate Paths and Directories

## Summary

A detection rule pins to a specific file path or directory (a known persistence location, a canonical binary path, a single staging dir), while an **in-scope alternative location** achieves the identical effect. The action is unchanged; only *where* it lands moves, and the path-anchored rule stops matching.

Grounded in real findings: across the Elastic Linux ruleset, ADE2-03 (Locations) was one of the most common bug classes, and the cross-ruleset kill-chain steering report chained several — e.g. MOTD persistence written to `/etc/profile.d/` instead of the monitored MOTD directory, and sensitive-file staging in `/tmp` before compression to dodge path-specific checks.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-03 — Locations
**Core principle:** a path is an attacker-choosable parameter, not a fixed property of the technique. When a rule enumerates one directory or one canonical path, any equivalent location that produces the same outcome is an omitted alternative and a silent false negative.

## The Technique

Linux offers many interchangeable locations for the same objective:

| Objective | Monitored (canonical) | In-scope alternatives the rule may omit |
|---|---|---|
| Login/boot persistence | `/etc/update-motd.d/` (MOTD) | `/etc/profile.d/*.sh`, `~/.bashrc`, `~/.bash_profile`, `/etc/rc.local` |
| Scheduled persistence | `/etc/crontab` | `/etc/cron.d/`, `/var/spool/cron/crontabs/`, `~/.config/systemd/user/` timers |
| Privilege config | `/etc/sudoers` | `/etc/sudoers.d/*` |
| Payload / data staging | `/dev/shm`, home dir | `/tmp`, `/var/tmp`, a bind-mounted path, any world-writable dir |
| Binary execution | `/usr/bin/<tool>` | a copy in `/tmp`, `$HOME`, or any dir on `$PATH` |

Two concrete moves from the indexed corpus:
1. **Persistence relocation** — append the payload to an existing script under `/etc/profile.d/` (executed at login, but not the directory a MOTD-creation rule watches), optionally with a leading-dot filename to reduce visibility.
2. **Staging relocation** — copy a sensitive file to `/tmp/mypwd` first, then compress *that* copy, so a rule keyed to the original sensitive path (e.g. `/etc/shadow`) never sees the read-and-archive step.

Windows analogues: startup-folder vs `Run` key vs scheduled task; `System32` vs `SysWOW64` vs a user-writable copy; per-user vs per-machine hives. Path canonicalization forms (8.3 short names, UNC, device paths) are the *normalization* cousin — see [ADE1-02](../../ADE1/ADE1-02-normalization-asymmetry/README.md).

## Vulnerable Rule

```yaml
# Paraphrased: MOTD persistence keyed to one directory
title: Message-of-the-Day (MOTD) File Creation
logsource:
    product: linux
    category: file_event
detection:
    selection:
        TargetFilename|startswith: '/etc/update-motd.d/'
    condition: selection
```

### Why it misses

A payload appended to `/etc/profile.d/login.sh` (or `~/.bashrc`) runs at login just like a MOTD script but never touches `/etc/update-motd.d/`, so the path-anchored rule produces no hit.

## Hardened Rule

```yaml
title: Login/Boot Script Persistence (Hardened, location-agnostic)
description: |
    Cover the class of login/boot initialization locations, not one directory.
logsource:
    product: linux
    category: file_event
detection:
    selection_paths:
        TargetFilename|startswith:
            - '/etc/update-motd.d/'
            - '/etc/profile.d/'
            - '/etc/rc.local'
            - '/etc/cron.d/'
            - '/etc/sudoers.d/'
        # plus per-user: ~/.bashrc, ~/.bash_profile, ~/.profile via a normalized home glob
    filter_pkg_mgmt:
        Image|endswith:
            - '/dpkg'
            - '/apt'
            - '/rpm'
            - '/yum'
    condition: selection_paths and not filter_pkg_mgmt
falsepositives:
    - Package managers and configuration-management agents (Ansible, Puppet, Chef)
level: medium
```

### Why the hardened rule works

It enumerates the **class** of login/boot/persistence locations rather than a single directory, and excludes the legitimate writers (package/config management) instead of narrowing the path. For staging, the analogous fix is to key on the *read of the sensitive source* (e.g. access to `/etc/shadow`) rather than the destination path the attacker controls.

## Detection Layers

| Audit method | Catches location swap? | How |
|---|---|---|
| Enumerate the location class | Yes | List all equivalent dirs/paths for the objective |
| Anchor on the invariant, not the path | Yes | The read of a sensitive source, or the login-execution behavior, is harder to relocate |
| Exclude legitimate writers | Prevents FP inflation | Package/config-mgmt allow-list instead of a narrow path |
| Emulate via an alternate path | Yes | Reproduce the technique in `/tmp`, `/etc/profile.d/`, a user dir; confirm coverage |
| World-writable directory monitoring | Partial | `/tmp`, `/var/tmp`, `/dev/shm` staging is noisy but catchable with content/behavior context |

## Implementation Nuances

- Pair with [ADE1-02 Normalization Asymmetry](../../ADE1/ADE1-02-normalization-asymmetry/README.md) — different *spellings* of the same path (short names, symlinks, `//`, trailing dot) evade a path match even without moving the file.
- Staging in `/tmp` (T1074) is deliberately cheap for the attacker and noisy for the defender; prefer keying on the sensitive-source read plus an archive/compress action rather than the `/tmp` destination.
- On Linux, `$PATH` ordering and bind mounts make "the canonical binary path" unreliable — anchor process identity on hash/inode where the telemetry allows, not the path string.

## References

- [MITRE ATT&CK T1037 — Boot or Logon Initialization Scripts](https://attack.mitre.org/techniques/T1037/)
- [MITRE ATT&CK T1074 — Data Staged](https://attack.mitre.org/techniques/T1074/)
- [MITRE ATT&CK T1053.003 — Scheduled Task/Job: Cron](https://attack.mitre.org/techniques/T1053/003/)
- [Elastic detection-rules — Linux persistence rules](https://github.com/elastic/detection-rules/tree/main/rules/linux)
