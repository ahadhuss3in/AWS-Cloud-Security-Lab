# Incident Response Report
## AWS Cloud Security Lab — Simulated Attack Investigation

**Author:** Ahad Hussain
**Date:** 08 June 2026
**Environment:** AWS Account 532922060792 (lab environment)
**Severity:** High (simulated — controlled lab)
**Status:** Resolved

---

## 1. Executive Summary

A series of four attack techniques were simulated against a deliberately misconfigured AWS environment using compromised IAM credentials (`vulnerable-user`). Attack techniques were executed manually using AWS CLI, replicating the API call patterns of automated exploitation frameworks, and mapped to MITRE ATT&CK.

GuardDuty detected one finding during the simulation window — root account API usage from Doha, Qatar (Ooredoo ISP). The `vulnerable-user` attack chain was not flagged by GuardDuty due to an insufficient behavioral baseline (new account, <14 days of history). All attack activity was confirmed in CloudTrail logs, providing full evidence of each technique executed.

**Key findings:**
- 1 GuardDuty alert fired (root credential usage — Low severity)
- 12 CloudTrail events logged across 4 attack techniques
- Full attack chain from credential verification to backdoor account creation captured
- Detection gap identified: GuardDuty ML baseline not yet established

---

## 2. Attack Timeline (CloudTrail Evidence)

All times in AST (UTC+3), June 08 2026. User: `vulnerable-user`.

| Time (AST) | API Call | Technique | MITRE |
|-----------|----------|-----------|-------|
| 22:44:28 | GetCallerIdentity | Credential verification | T1078.004 |
| 22:45:27 | ListUsers | IAM enumeration | T1580 |
| 22:45:43 | ListRoles | IAM enumeration | T1580 |
| 22:46:33 | ListGroups | IAM enumeration | T1580 |
| 22:46:43 | ListPolicies | IAM enumeration | T1580 |
| 22:46:50 | GetAccountSummary | IAM enumeration | T1580 |
| 22:47:39 | ListBuckets | S3 discovery and exfiltration | T1530 |
| 22:48:53 | CreateUser (backdoor-user) | Persistence via new account | T1136.001 |
| 22:49:39 | AttachUserPolicy (AdministratorAccess) | Privilege escalation | T1098.001 |
| 22:49:48 | CreateAccessKey (backdoor-user) | Backdoor credential creation | T1098.001 |
| 22:51:27 | ListUsers | Post-compromise verification | T1580 |
| 22:52:21 | ListUsers | Post-compromise verification | T1580 |

---

## 3. Attack Scenarios

### Scenario 1 — IAM Enumeration
**MITRE:** T1580 — Cloud Infrastructure Discovery
**Time window:** 22:45:27 – 22:46:50
**Commands:** ListUsers, ListRoles, ListGroups, ListPolicies, GetAccountSummary
**Objective:** Map the IAM environment — identify users, roles, policies, and privileges available for lateral movement or privilege escalation.
**Outcome:** Full IAM inventory retrieved. `vulnerable-user` had AdministratorAccess — no privilege escalation required.

### Scenario 2 — S3 Discovery and Exfiltration
**MITRE:** T1530 — Data from Cloud Storage
**Time:** 22:47:39
**Commands:** ListBuckets, aws s3 ls, aws s3 cp (sensitive-data.csv downloaded)
**Objective:** Identify and exfiltrate data from accessible S3 buckets.
**Outcome:** `lab-vulnerable-532922` found publicly accessible. `sensitive-data.csv` (fake employee salary data) downloaded to `/tmp/stolen-data.csv`.

### Scenario 3 — Persistence via Backdoor Account
**MITRE:** T1136.001 — Create Account: Local Account / T1098.001 — Account Manipulation
**Time window:** 22:48:53 – 22:49:48
**Commands:** CreateUser, AttachUserPolicy, CreateAccessKey
**Objective:** Create a hidden admin account to maintain access even if the original credentials are revoked.
**Outcome:** `backdoor-user` created with AdministratorAccess and long-lived access keys. Account deleted post-simulation.

### Scenario 4 — Credential Use from Anomalous Regions
**MITRE:** T1078.004 — Valid Accounts: Cloud Accounts
**Regions:** ap-southeast-1, eu-west-1, us-west-2
**Commands:** ec2:DescribeInstances, s3:ListBuckets from non-baseline regions
**Objective:** Simulate attacker operating from geographically anomalous locations.
**Outcome:** API calls logged across three non-standard regions. GuardDuty did not fire due to lack of regional baseline.

---

## 4. GuardDuty Finding

**Finding ID:** 26cf54620fc8d8fde24e8ed0127115a9
**Type:** Root credential API usage
**Title:** The API ListManagedNotificationEvents was invoked using root credentials
**Severity:** Low (2.0)
**MITRE:** T1078 — Valid Accounts
**Source IP:** 78.101.130.87
**Location:** Doha, Qatar (Ooredoo Q.S.C., ASN 8781)
**Count:** 72 API calls between 19:38:53 – 20:14:53 UTC
**Analysis:** Root account was used to make routine API calls — a violation of CIS Benchmark 1.5 (avoid root account usage). Root should be reserved for break-glass scenarios only. This is a true positive finding unrelated to the simulated attack scenarios.

---

## 5. IOC Table

| Type | Indicator | Context | MITRE |
|------|-----------|---------|-------|
| IAM User | `vulnerable-user` | Simulated compromised account | T1078.004 |
| IAM User | `backdoor-user` | Backdoor account created during simulation | T1136.001 |
| Access Key | AKIA[REDACTED] | vulnerable-user key used in simulation | T1078.004 |
| S3 Bucket | lab-vulnerable-532922 | Exfiltration target | T1530 |
| File | sensitive-data.csv | Exfiltrated to /tmp/stolen-data.csv | T1530 |
| API Pattern | ListUsers, ListRoles, ListGroups | IAM enumeration sequence | T1580 |
| Regions | ap-southeast-1, eu-west-1, us-west-2 | Anomalous API call regions | T1078.004 |
| IP Address | 78.101.130.87 | Root account usage source (Doha, Ooredoo) | T1078 |

---

## 6. Detection Analysis

| Scenario | Expected Detection | Actual Detection | Gap |
|----------|------------------|-----------------|-----|
| IAM enumeration | GuardDuty: Discovery:IAMUser/AnomalousBehavior | Not fired | ML baseline insufficient (<14 days) |
| S3 exfiltration | GuardDuty: Exfiltration:S3/AnomalousBehavior | Not fired | ML baseline insufficient |
| Backdoor creation | GuardDuty: Persistence:IAMUser/AnomalousBehavior | Not fired | ML baseline insufficient |
| Anomalous region use | GuardDuty: UnauthorizedAccess:IAMUser/MaliciousIPCaller | Not fired | ML baseline insufficient |
| Root account usage | GuardDuty: Root credential usage | **FIRED** ✅ | N/A — threshold-based detection |

**Key insight:** GuardDuty's ML-based anomaly detection requires 7–14 days of baseline activity per identity. Threshold-based detections (root usage) fire immediately regardless of baseline. This explains why only the root finding fired.

---

## 7. Containment Actions

| Action | Trigger | Status |
|--------|---------|--------|
| `backdoor-user` deleted | Created during Scenario 3 | ✅ Completed |
| `backdoor-user` access key deleted | Created during Scenario 3 | ✅ Completed |
| `backdoor-user` admin policy detached | Attached during Scenario 3 | ✅ Completed |
| `vulnerable-user` key rotation | Key used throughout simulation | Pending — part of remediation phase |

---

## 8. Recommendations

| # | Recommendation | Priority | Framework Control |
|---|---------------|----------|------------------|
| 1 | Stop using root account for routine operations | P1 | CIS 1.5, ISO 27001 A.8.5 |
| 2 | Enable GuardDuty for minimum 14 days before red team exercises | P1 | AWS Best Practice |
| 3 | Implement IAM Access Analyzer to detect overpermissive policies continuously | P1 | CIS 1.16, ISO 27001 A.5.18 |
| 4 | Enable MFA delete on S3 buckets containing sensitive data | P2 | PCI DSS Req 3.4 |
| 5 | Implement SCPs (Service Control Policies) to block IAM user creation except by approved roles | P2 | CIS 1.16 |
| 6 | Set up CloudWatch alarms for IAM user creation and policy attachment as supplemental detection | P2 | CIS 3.4 |
| 7 | Rotate all `vulnerable-user` access keys and apply least-privilege policy | P1 | CIS 1.14, ISO 27001 A.5.17 |