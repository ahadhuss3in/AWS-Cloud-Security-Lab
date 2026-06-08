# Control Mapping — AWS Cloud Security Lab

Cross-reference of lab findings to ISO 27001 Annex A controls and PCI DSS v4.0 requirements.

---

## ISO 27001 Annex A Mapping

| Finding | ISO 27001 Control | Control Name |
|---------|------------------|-------------|
| S3 public access | A.8.24 | Use of cryptography |
| S3 no encryption | A.8.24 | Use of cryptography |
| IAM no MFA | A.8.5 | Secure authentication |
| IAM admin direct attach | A.8.2 | Privileged access rights |
| Access key no rotation | A.8.5 | Secure authentication |
| CloudTrail disabled | A.8.15 | Logging |
| SG open to world | A.8.20 | Network security |
| EBS unencrypted | A.8.24 | Use of cryptography |
| GuardDuty disabled | A.8.16 | Monitoring activities |
| VPC flow logs off | A.8.15 | Logging |

---

## PCI DSS v4.0 Requirement Mapping

| Finding | PCI DSS Requirement | Description |
|---------|--------------------|----|
| S3 public access | Req 3.5 | Protect primary account data |
| S3 no encryption | Req 3.5 | Protect stored account data |
| IAM no MFA | Req 8.4 | Multi-factor authentication |
| IAM admin direct attach | Req 7.2 | Least privilege access |
| Access key no rotation | Req 8.3 | Manage user IDs and credentials |
| CloudTrail disabled | Req 10.2 | Audit logs implementation |
| SG open to world | Req 1.3 | Restrict inbound/outbound traffic |
| EBS unencrypted | Req 3.5 | Protect stored data |
| GuardDuty disabled | Req 10.7 | Detect and report failures |
| VPC flow logs off | Req 10.2 | Implement audit logs |
