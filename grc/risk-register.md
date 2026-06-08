# Risk Register — AWS Cloud Security Lab


Scan date     : 06-June-2026
Tool          : Prowler v5.29.2
Total checks  : 264
Total FAIL    : 175
Critical      : 11
High          : 49

# Risk Register — AWS Cloud Security Lab
**Tool:** Prowler v5.29.2
**Scan Date:** June 2026
**Account:** 532922060792
**Frameworks:** CIS AWS Benchmark v2.0 | ISO 27001:2022 | PCI DSS 3.2.1

---

## Scan Summary

| Metric | Count |
|--------|-------|
| Total Checks Run | 264 |
| Passed | 89 |
| Failed | 175 |
| Critical Failures | 11 |
| High Failures | 49 |

---

## Critical and  High severity  Findings
# Cloud Security Assessment Findings

| # | Finding                                                     | Resource                                                             | CIS 2.0  | ISO 27001:2022         | PCI DSS 3.2.1    | Severity | Risk                                                                                                                                                                                                                                                                                                                                        |
| - | ----------------------------------------------------------- | -------------------------------------------------------------------- | -------- | ---------------------- | ---------------- | -------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| 1 | AdministratorAccess policy attached (`*:*`)                 | `iam::user/vulnerable-user`                                          | 1.16     | A.5.18, A.8.2          | —                | CRITICAL | Full account takeover — attacker can disable logging, create backdoor principals, exfiltrate all data                                                                                                                                                                                                                                       |
| 2 | Root hardware MFA not enabled (virtual MFA only)            | `iam::root`                                                          | 1.6      | A.8.5                  | 8.4.1.3          | CRITICAL | Virtual MFA is weaker than hardware — device compromise or backup restoration weakens second-factor assurance                                                                                                                                                                                                                               |
| 3 | S3 bucket publicly accessible via bucket policy             | `s3:::lab-vulnerable-532922`                                         | —        | A.8.1                  | 1.2, 1.3, 7.2    | CRITICAL | Unauthenticated read access — data exfiltration possible (MITRE T1530), malware hosting, cost abuse                                                                                                                                                                                                                                         |
| 4 | EC2 security group all ports open to internet (`0.0.0.0/0`) | `ec2::sg/sg-020423ed4fb2503c2`                                       | 5.2, 5.3 | A.8.20, A.8.21, A.8.22 | 1.1, 1.2, 1.3    | CRITICAL | Full network exposure — RCE attempts, lateral movement, network scanning (MITRE T1046, T1199, T1048)                                                                                                                                                                                                                                        |
| 5 | EBS default encryption is not enabled                       | `arn:aws:ec2:us-east-1:532922060792:volume`                          | —        | A.8.24, A.8.12         | 3.4, 3.5         | HIGH     | EBS Default Encryption is not activated. New EBS volumes may be created without encryption, increasing the risk of unauthorized access to sensitive data at rest through compromised snapshots, backups, or storage media.                                                                                                                  |
| 6 | No CloudTrail trails enabled with logging                   | `arn:aws:cloudtrail:ap-northeast-1:532922060792:trail`               | 3.1, 3.2 | A.8.15, A.5.24         | 10.2, 10.3, 10.5 | HIGH     | No CloudTrail trails enabled with logging were found. Absence of audit logging prevents detection and investigation of malicious activity, including privilege escalation, unauthorized resource modifications, persistence mechanisms, and data access. This significantly reduces forensic visibility and incident response capabilities. |
| 7 | VPC subnet assigns public IP addresses by default           | `arn:aws:ec2:us-east-1:532922060792:subnet/subnet-007dc5b55a2c6078e` | 5.2, 5.3 | A.8.20, A.8.21         | 1.2, 1.3         | HIGH     | Internet-exposed instances become reachable by default, enabling port scans, SSH/RDP brute-force attacks, and exploitation attempts. Successful compromise can lead to data exfiltration, unauthorized modification of resources, and service disruption through abuse or DDoS attacks.                                                     |


## Remediation Plan

| # | Finding | Action | Priority | Status |
|---|---------|--------|----------|--------|
| 1 | AdministratorAccess attached | Detach `AdministratorAccess`, apply least-privilege custom policy | P1 | Open |
| 2 | Root hardware MFA | Replace virtual MFA with hardware MFA token on root account | P1 | Open |
| 3 | S3 publicly accessible | Enable all four S3 Block Public Access settings, remove public bucket policy | P1 | Open |
| 4 | EC2 SG all ports open | Remove `0.0.0.0/0` rules, restrict to specific ports and trusted CIDRs only | P1 | Open |
| 5 | EBS Encryption | Enable default EBS encryption, reducing the risk of unauthorized access to to data at rest| P2 | Open|
| 6 | CloudTrail Logging | Enable CloudTrail logging; Analysis of Logs| P1 | Open|
| 7 | VPC IPAddr assignment| Enable security groups/Disbale subnet IP assigment | P3 | Open |

---

## After Remediation

| Finding                    | Before | After | Evidence              |
|---------------------------|--------|-------|-----------------------|
| AdministratorAccess attached | FAIL | PASS | prowler-output-after  |
| Root hardware MFA          | FAIL   | FAIL  | Requires hardware token|
| S3 publicly accessible     | FAIL   | PASS  | prowler-output-after  |
| EC2 SG all ports open      | FAIL   | PASS  | prowler-output-after  |
| Total Critical             | 4      | 2     | 50% reduction         |
| Total Failures             | 175    | ~163  | —                     |
---

## Custom Compliance Checker — After Remediation (2026-06-08)

**Tool:** AWS Custom Compliance Checker  
**Frameworks:** CIS AWS Benchmark v2.0 | PCI DSS 3.2.1  
**Scan Time:** 2026-06-08T20:51:09  

### Summary

| Metric | Result |
|--------|--------|
| Total Checks Run | 20 |
| Passed | 15 ✅ |
| Failed | 5 ❌ |
| Critical Failures | 3 |
| High Failures | 1 |
| Medium Failures | 1 |

### Detailed Findings — After Remediation

| Control | Finding | Resource | Severity | Status | Evidence |
|---------|---------|----------|----------|--------|----------|
| CIS-2.1.5 | S3 Public Access Block | s3://lab-cloudtrail-logs-532922 | CRITICAL | ✅ PASS | compliance-report.json |
| CIS-2.1.5 | S3 Public Access Block | s3://lab-vulnerable-532922 | CRITICAL | ✅ PASS | compliance-report.json |
| CIS-2.1.1 | S3 Default Encryption | s3://lab-cloudtrail-logs-532922 | HIGH | ✅ PASS | compliance-report.json |
| CIS-2.1.1 | S3 Default Encryption | s3://lab-vulnerable-532922 | HIGH | ✅ PASS | compliance-report.json |
| CIS-1.5 | Root Account MFA | iam::root | CRITICAL | ✅ PASS | compliance-report.json |
| CIS-1.10 | IAM User MFA | iam::user/lab-admin | CRITICAL | ❌ FAIL | MFA required |
| CIS-1.10 | IAM User MFA | iam::user/vulnerable-user | CRITICAL | ❌ FAIL | MFA required |
| CIS-1.14 | Access Key Rotation (90-day) | iam::user/lab-admin/key | HIGH | ✅ PASS | compliance-report.json |
| CIS-1.14 | Access Key Rotation (90-day) | iam::user/vulnerable-user/key | HIGH | ✅ PASS | compliance-report.json |
| PCI-7.1 | No Direct Admin Policy | iam::user/lab-admin | CRITICAL | ❌ FAIL | Direct admin attached |
| PCI-7.1 | No Direct Admin Policy | iam::user/vulnerable-user | CRITICAL | ✅ PASS | compliance-report.json |
| CIS-3.1 | CloudTrail Actively Logging | cloudtrail::lab-trail | CRITICAL | ✅ PASS | compliance-report.json |
| CIS-5.2 | SSH Not Open to World | ec2::sg/sg-020423ed4fb2503c2 | CRITICAL | ✅ PASS | compliance-report.json |
| CIS-5.2 | SSH Not Open to World | ec2::sg/sg-06c37016f8a24b49d | CRITICAL | ✅ PASS | compliance-report.json |
| CIS-5.3 | RDP Not Open to World | ec2::sg/sg-020423ed4fb2503c2 | CRITICAL | ✅ PASS | compliance-report.json |
| CIS-5.3 | RDP Not Open to World | ec2::sg/sg-06c37016f8a24b49d | CRITICAL | ✅ PASS | compliance-report.json |
| CIS-2.2.1 | EBS Volume Encryption | ec2::volume/vol-0f55743c585520a08 | HIGH | ❌ FAIL | Unencrypted volume |
| CIS-3.9 | VPC Flow Logs Enabled | ec2::vpc/vpc-07c4ee874cd18e206 | MEDIUM | ❌ FAIL | No flow logs |
| AWS-GD-1 | GuardDuty Enabled | guardduty::8ecf545f5e2de9f99a60c9690ab93eaf | HIGH | ✅ PASS | compliance-report.json |

### Remediation Progress

| Finding | Before | After | Change | Evidence |
|---------|--------|-------|--------|----------|
| S3 Public Access | FAIL | **PASS** | ✅ Fixed | Both buckets now blocked |
| CloudTrail Logging | FAIL | **PASS** | ✅ Fixed | Actively logging |
| EC2 SG SSH Open | FAIL | **PASS** | ✅ Fixed | Restricted access |
| EC2 SG RDP Open | FAIL | **PASS** | ✅ Fixed | Restricted access |
| GuardDuty | FAIL | **PASS** | ✅ Fixed | Enabled and active |
| IAM User MFA | FAIL | **FAIL** | ❌ Pending | 2 users need MFA |
| Admin Policy Direct | FAIL | **PARTIAL** | ⚠️ Partial | 1 user still has admin |
| EBS Encryption | FAIL | **FAIL** | ❌ Pending | Volume not encrypted |
| VPC Flow Logs | FAIL | **FAIL** | ❌ Pending | Flow logs needed |
| **Total Improvements** | **10 Failed** | **5 Failed** | **50% reduction** | 5 issues resolved |
