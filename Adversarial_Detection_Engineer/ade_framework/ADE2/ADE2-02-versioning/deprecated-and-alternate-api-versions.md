---
id: ADE2-008
title: Deprecated and Alternate API Versions
ade_category: ADE2
ade_subcategory: ADE2-02
mitre_attack:
  - T1578 (Modify Cloud Compute Infrastructure)
  - T1562.007 (Impair Defenses: Disable or Modify Cloud Firewall)
platform: Cloud (AWS)
testable: logic-analysis
---

# Deprecated and Alternate API Versions

## Summary

A detection rule enumerates a fixed set of event names, API calls, or a specific software/OS/service version, while an **in-scope alternative version** achieves the same effect through different names the rule never lists. Cloud providers are the sharpest example: the same security-relevant change can be made through a legacy (EC2-Classic) API, its modern (VPC) replacement, or an adjacent service's API — and a rule pinned to one generation silently misses the others.

Grounded in a real finding: the Microsoft Sentinel analytic **"Changes to Internet Facing AWS RDS Database Instances"** monitors a small set of EC2-Classic RDS DB-security-group CloudTrail events, missing EC2-VPC RDS deployments, `ModifyDBInstance`, snapshot-restore workflows, and equivalent EC2 VPC security-group APIs.

## ADE Classification

**Category:** ADE2 — Omit Alternatives
**Subcategory:** ADE2-02 — Versioning
**Core principle:** rules age. APIs are deprecated and replaced, new service/OS versions add or rename operations, and a rule tuned to one version keeps matching that version while adjacent, in-scope versions pass straight through. The gap is invisible because the rule still fires on its original version — coverage *looks* intact.

## The Technique

The same objective — here, exposing a database to the internet or weakening its network controls — is reachable through multiple API "dialects":

| Generation / path | How the change is made |
|---|---|
| **EC2-Classic RDS** (legacy) | `AuthorizeDBSecurityGroupIngress`, `CreateDBSecurityGroup`, `RevokeDBSecurityGroupIngress` |
| **EC2-VPC RDS** (modern default) | `ModifyDBInstance` (`PubliclyAccessible=true`), VPC security-group changes via **EC2** APIs (`AuthorizeSecurityGroupIngress`) |
| **Snapshot workflow** | `RestoreDBInstanceFromDBSnapshot` into a public subnet / open SG |
| **Adjacent service** | EC2 `ModifySecurityGroupRules` on the SG the RDS instance uses |

A rule keyed to the EC2-Classic DB-security-group event names covers only row 1. Because EC2-Classic is deprecated and virtually all modern deployments are VPC, the rule's real-world coverage is close to zero even though it still validates against its original test data.

The same pattern recurs off-cloud: `Get-*` cmdlet vs its deprecated WMI equivalent, a Linux distro that moved a binary between `/usr/bin` and `/bin`, a protocol version bump (SMBv1→v3), or an OS release that renamed a logged field. See also the field-availability version of this in [ADE4-04](../../ADE4/ADE4-04-field-mismapping-semantics/unavailable-field.md).

## Vulnerable Rule

```yaml
# Sentinel analytic (paraphrased): only EC2-Classic RDS DB-security-group events
title: Changes to Internet Facing AWS RDS Database Instances
detection:
    selection:
        EventSource: 'rds.amazonaws.com'
        EventName:
            - 'AuthorizeDBSecurityGroupIngress'
            - 'CreateDBSecurityGroup'
            - 'RevokeDBSecurityGroupIngress'
    condition: selection
```

### Why it misses

`ModifyDBInstance` with `PubliclyAccessible=true`, a snapshot restore into a public subnet, or an EC2 VPC security-group change all expose the database without emitting any of the three enumerated event names. The rule was written for an API generation that most tenants no longer use.

## Hardened Rule

```yaml
title: Internet Exposure of AWS RDS (Hardened, version-agnostic)
description: |
    Correlate RDS configuration-state changes across deployment models rather
    than matching a fixed set of EC2-Classic event names.
detection:
    selection_rds_modify:
        EventSource: 'rds.amazonaws.com'
        EventName:
            - 'ModifyDBInstance'
            - 'CreateDBInstance'
            - 'RestoreDBInstanceFromDBSnapshot'
            - 'RestoreDBInstanceToPointInTime'
        requestParameters.publiclyAccessible: true
    selection_classic_sg:
        EventSource: 'rds.amazonaws.com'
        EventName|startswith:
            - 'AuthorizeDBSecurityGroup'
            - 'CreateDBSecurityGroup'
    selection_vpc_sg:
        EventSource: 'ec2.amazonaws.com'
        EventName:
            - 'AuthorizeSecurityGroupIngress'
            - 'ModifySecurityGroupRules'
        # correlate to an SG attached to an RDS instance
    condition: selection_rds_modify or selection_classic_sg or selection_vpc_sg
falsepositives:
    - Legitimate DBA changes to publicly accessible reporting replicas
level: medium
```

### Why the hardened rule works

It matches on **configuration state and effect** (`PubliclyAccessible`, SG ingress) across the RDS *and* EC2 APIs and across create/modify/restore paths, rather than a single deprecated event-name family. New API generations that change the same state are more likely to be caught.

## Detection Layers

| Audit method | Catches version drift? | How |
|---|---|---|
| Enumerate the alternatives at authoring time | Yes | List legacy + modern + snapshot + adjacent-service APIs for the same effect |
| Match on resulting *state* not the operation name | Yes | `PubliclyAccessible`, open SG ingress — stable across API versions |
| Deprecation review cadence | Partial | Periodically re-check whether the rule's APIs are still the ones in use |
| Coverage test on the *current* default deployment model | Yes | Emulate the change via the modern (VPC) path and confirm the rule fires |
| Version pin documented as a known limitation | Prevents surprise | If the rule is intentionally scoped to one version, record it |

## Implementation Nuances

- ADE2-02 is where "the rule still fires in the lab" is most misleading: the lab uses the version the rule was written for. Always emulate via the **current default** version/deployment model.
- Cross-references: the AWS RDS finding also carries an [ADE2-01 Method/Binary](../ADE2-01-method-binary/) dimension (alternative APIs = alternative methods); versioning is the *temporal* slice of the same "omitted alternative" problem.
- Field-level version drift (a field that exists only in one source/version) is [ADE4-04](../../ADE4/ADE4-04-field-mismapping-semantics/README.md); this technique is about **operation/version** drift, not field naming.

## References

- [MITRE ATT&CK T1578 — Modify Cloud Compute Infrastructure](https://attack.mitre.org/techniques/T1578/)
- [MITRE ATT&CK T1562.007 — Disable or Modify Cloud Firewall](https://attack.mitre.org/techniques/T1562/007/)
- [AWS — RDS API Reference (operations)](https://docs.aws.amazon.com/AmazonRDS/latest/APIReference/API_Operations.html)
- [Microsoft Sentinel — Changes to Internet Facing AWS RDS Database Instances](https://github.com/Azure/Azure-Sentinel/blob/master/Solutions/Amazon%20Web%20Services/Analytic%20Rules/AWS_ChangeToRDSDatabase.yaml)
