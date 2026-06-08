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

### Lambda automated response playbooks

| File | GuardDuty Trigger | Automated Action |
|------|-------------------|-----------------|
| `iam_key_quarantine.py` | UnauthorizedAccess:IAMUser/MaliciousIPCaller | Disable compromised IAM access key |
| `s3_block_public.py` | Policy:S3/BucketPublicAccessGranted | Re-enable S3 block public access |
| `sg_revoke_open_rule.py` | Recon:EC2/PortProbeUnprotectedPort | Revoke 0.0.0.0/0 security group rules |

---

## Repository Structure

```
aws-cloud-security-lab/
├── README.md
├── cloudformation/
│   └── vulnerable-env.yaml          # Full environment as Infrastructure as Code
├── compliance-checker/
│   └── checker.py                   # Custom boto3 compliance checker (12 controls)
├── grc/
│   ├── prowler-output/              # Prowler HTML + JSON scan reports
│   ├── risk-register.md             # Risk register with severity scoring
│   └── control-mapping.md           # ISO 27001 + PCI DSS cross-reference
├── soc/
│   ├── guardduty-findings/          # Raw GuardDuty finding JSON files
│   ├── attack-simulations.md        # Pacu commands, timestamps, findings triggered
│   ├── ir-report.md                 # Incident response write-up
│   └── mitre-attack-coverage.md     # MITRE ATT&CK technique coverage map
├── lambda/
│   ├── iam_key_quarantine.py        # Auto-disable compromised IAM keys
│   ├── s3_block_public.py           # Auto-block public S3 access
│   └── sg_revoke_open_rule.py       # Auto-revoke open security group rules
└── diagrams/
    └── architecture.png             # Lab architecture diagram
```

---

## How to Reproduce

### 1. Deploy environment (IaC)
```bash
aws cloudformation deploy \
  --template-file cloudformation/vulnerable-env.yaml \
  --stack-name aws-security-lab \
  --capabilities CAPABILITY_NAMED_IAM
```

### 2. Run compliance checks
```bash
pip install boto3 colorama
python3 compliance-checker/checker.py

pip install prowler
prowler aws --compliance cis_aws_2.0 pci_3.2.1 iso27001_2013_aws \
  --output-formats html json \
  --output-directory grc/prowler-output
```

### 3. Enable detection stack
```bash
aws cloudtrail create-trail --name lab-trail --s3-bucket-name YOUR_LOG_BUCKET
aws guardduty create-detector --enable
aws securityhub enable-security-hub
```

### 4. Simulate attacks
```bash
pip install pacu
pacu  # Use vulnerable-user credentials
```

---

## Skills Demonstrated
- Cloud security posture management (CSPM)
- CIS Benchmark and PCI DSS compliance assessment
- Python automation with boto3 (AWS SDK)
- Threat detection engineering (GuardDuty, CloudTrail)
- Attack simulation and MITRE ATT&CK mapping
- Automated incident response (Lambda/EventBridge SOAR-lite)
- Infrastructure as Code (CloudFormation)
# AWS-Cloud-Security-Lab
