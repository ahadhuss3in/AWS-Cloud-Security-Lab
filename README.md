# AWS Cloud Security Lab

**Dual-track cloud security project:** compliance assessment (GRC) + threat detection and automated response (SOC) against the same deliberately misconfigured AWS environment.

> Author: Ahad Hussain | [LinkedIn](https://www.linkedin.com/in/ahad-asif-hussain-95015426a/) | [GitHub](https://github.com/ahadhuss3in)

---

## Architecture

```
Vulnerable AWS Environment (Free Tier)
├── GRC Track → Custom boto3 checker + Prowler → Risk Register → Control Mapping
└── SOC Track → CloudTrail + GuardDuty → Pacu Simulation → Lambda Auto-Response
```

### Misconfigurations deployed

| Resource | Misconfiguration | Framework Violation |
|----------|-----------------|-------------------|
| S3 bucket | Public read, no encryption | CIS 2.1.1, 2.1.5 / PCI DSS Req 3 |
| IAM user | AdministratorAccess direct attach, no MFA | CIS 1.5, 1.10 / PCI DSS Req 7/8 |
| EC2 Security Group | 0.0.0.0/0 on SSH, RDP, all traffic | CIS 5.2, 5.3 |
| EBS Volume | Unencrypted at rest | CIS 2.2.1 |
| CloudTrail | Disabled — no API logging | CIS 3.1 / PCI DSS Req 10 |
| GuardDuty | Disabled — no threat detection | AWS Security Best Practice |

---

## Track A — GRC / Compliance

### Tools
- **`compliance-checker/checker.py`** — Custom Python compliance checker using boto3. Implements 12 CIS Benchmark and PCI DSS controls directly against AWS APIs without relying on third-party tooling.
- **Prowler** — CSPM scan across CIS AWS v2.0, PCI DSS 3.2.1, ISO 27001 frameworks used as validation layer.

### Deliverables
- `grc/prowler-output/` — Before and after Prowler HTML + JSON reports
- `grc/risk-register.md` — Findings with severity scoring, control references, remediation status
- `grc/control-mapping.md` — ISO 27001 Annex A and PCI DSS control cross-reference

### Compliance posture (before/after)

| Framework | Before Remediation | After Remediation |
|-----------|-------------------|------------------|
| CIS AWS v2.0 | TBD after scan | TBD after remediation |
| PCI DSS 3.2.1 | TBD after scan | TBD after remediation |
| ISO 27001 | TBD after scan | TBD after remediation |

---

## Track B — SOC / Detection and Response

### Stack
- **CloudTrail** — API call logging across all regions
- **GuardDuty** — Threat detection on CloudTrail logs, VPC Flow Logs, DNS queries
- **Security Hub** — Aggregated findings from GuardDuty and Prowler
- **Pacu** — AWS exploitation framework for controlled attack simulation
- **Lambda + EventBridge** — Automated response playbooks triggered by GuardDuty findings

### Attack scenarios simulated

| Scenario | Tool/Module | MITRE ATT&CK |
|----------|-------------|--------------|
| IAM enumeration | Pacu: iam__enum_users_roles_policies_groups | T1580 |
| S3 data exfiltration | Pacu: s3__download_bucket | T1530 |
| Privilege escalation | Pacu: iam__privesc_scan | T1098.001 |
| Credential abuse (anomalous region) | Manual API calls | T1078.004 |

