#!/usr/bin/env python3
"""
AWS Custom Compliance Checker
CIS AWS Benchmark v2.0 + PCI DSS 3.2.1

Implements 12 security controls directly against AWS APIs using boto3.
Run this BEFORE Prowler to generate your own findings, then compare.

Author: Ahad Hussain
"""

import boto3
import json
from datetime import datetime, timezone

findings = []


def add_finding(control_id, title, severity, resource, status, description, remediation):
    findings.append({
        "control_id": control_id,
        "title": title,
        "severity": severity,
        "resource": resource,
        "status": status,
        "description": description,
        "remediation": remediation,
        "timestamp": datetime.now(timezone.utc).isoformat()
    })
    print(f"  [{status}] [{severity}] {control_id} — {title}")
    if status == "FAIL":
        print(f"         Resource : {resource}")
        print(f"         Fix      : {remediation}")


# ─────────────────────────────────────────────────────────────
# S3 CHECKS
# ─────────────────────────────────────────────────────────────

def check_s3_public_access_block():
    """CIS 2.1.5 / PCI DSS Req 1 — S3 buckets must block public access"""
    s3 = boto3.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])

    for bucket in buckets:
        name = bucket['Name']
        try:
            pab = s3.get_public_access_block(Bucket=name)['PublicAccessBlockConfiguration']
            all_blocked = all([
                pab.get('BlockPublicAcls', False),
                pab.get('IgnorePublicAcls', False),
                pab.get('BlockPublicPolicy', False),
                pab.get('RestrictPublicBuckets', False)
            ])
            status = "PASS" if all_blocked else "FAIL"
        except Exception:
            status = "FAIL"

        add_finding(
            "CIS-2.1.5", "S3 Public Access Block",
            "CRITICAL", f"s3://{name}", status,
            "Bucket does not fully block public access — data is world-readable.",
            "Enable all four public access block settings on the bucket and account level."
        )


def check_s3_encryption():
    """CIS 2.1.1 — S3 buckets must have default encryption enabled"""
    s3 = boto3.client('s3')
    buckets = s3.list_buckets().get('Buckets', [])

    for bucket in buckets:
        name = bucket['Name']
        try:
            s3.get_bucket_encryption(Bucket=name)
            status = "PASS"
        except Exception:
            status = "FAIL"

        add_finding(
            "CIS-2.1.1", "S3 Default Encryption",
            "HIGH", f"s3://{name}", status,
            "Bucket has no default encryption — objects stored in plaintext.",
            "Enable SSE-S3 or SSE-KMS default encryption on the bucket."
        )


# ─────────────────────────────────────────────────────────────
# IAM CHECKS
# ─────────────────────────────────────────────────────────────

def check_root_mfa():
    """CIS 1.5 — Root account must have MFA enabled"""
    iam = boto3.client('iam')
    summary = iam.get_account_summary()['SummaryMap']
    mfa_enabled = summary.get('AccountMFAEnabled', 0)
    status = "PASS" if mfa_enabled else "FAIL"

    add_finding(
        "CIS-1.5", "Root Account MFA",
        "CRITICAL", "iam::root", status,
        "Root account has no MFA — full account takeover risk if credentials are exposed.",
        "Enable hardware or virtual MFA on the root account immediately."
    )


def check_iam_mfa():
    """CIS 1.10 / PCI DSS Req 8.3 — IAM users must have MFA enabled"""
    iam = boto3.client('iam')
    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']
        mfa_devices = iam.list_mfa_devices(UserName=username)['MFADevices']
        status = "PASS" if mfa_devices else "FAIL"

        add_finding(
            "CIS-1.10", "IAM User MFA",
            "CRITICAL", f"iam::user/{username}", status,
            f"User {username} has no MFA — account compromise possible with credentials alone.",
            "Enable virtual or hardware MFA for all IAM users with console access."
        )


def check_iam_access_key_rotation():
    """CIS 1.14 — Access keys must be rotated every 90 days"""
    iam = boto3.client('iam')
    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']
        keys = iam.list_access_keys(UserName=username)['AccessKeyMetadata']

        for key in keys:
            if key['Status'] != 'Active':
                continue
            age = (datetime.now(timezone.utc) - key['CreateDate']).days
            status = "PASS" if age <= 90 else "FAIL"

            add_finding(
                "CIS-1.14", "Access Key Rotation (90-day)",
                "HIGH", f"iam::user/{username}/key/{key['AccessKeyId'][:8]}...", status,
                f"Access key is {age} days old — exceeds 90-day rotation policy.",
                "Rotate access keys every 90 days. Automate with IAM credential reports."
            )


def check_iam_admin_policy():
    """PCI DSS Req 7.1 — No users should have AdministratorAccess directly attached"""
    iam = boto3.client('iam')
    users = iam.list_users()['Users']

    for user in users:
        username = user['UserName']
        policies = iam.list_attached_user_policies(UserName=username)['AttachedPolicies']
        has_admin = any(p['PolicyName'] == 'AdministratorAccess' for p in policies)
        status = "FAIL" if has_admin else "PASS"

        add_finding(
            "PCI-7.1", "No Direct Admin Policy",
            "CRITICAL", f"iam::user/{username}", status,
            f"User {username} has AdministratorAccess directly attached — violates least privilege.",
            "Use IAM roles with least-privilege policies. Remove direct admin attachment."
        )


# ─────────────────────────────────────────────────────────────
# CLOUDTRAIL CHECKS
# ─────────────────────────────────────────────────────────────

def check_cloudtrail_enabled():
    """CIS 3.1 / PCI DSS Req 10 — CloudTrail must be enabled and logging"""
    ct = boto3.client('cloudtrail')
    trails = ct.describe_trails(includeShadowTrails=True)['trailList']

    if not trails:
        add_finding(
            "CIS-3.1", "CloudTrail Enabled",
            "CRITICAL", "cloudtrail::account", "FAIL",
            "No CloudTrail trails exist — zero visibility into API activity.",
            "Create a multi-region CloudTrail trail with log file validation and S3 encryption."
        )
        return

    for trail in trails:
        name = trail['Name']
        status_info = ct.get_trail_status(Name=trail['TrailARN'])
        is_logging = status_info.get('IsLogging', False)
        status = "PASS" if is_logging else "FAIL"

        add_finding(
            "CIS-3.1", "CloudTrail Actively Logging",
            "CRITICAL", f"cloudtrail::{name}", status,
            f"Trail {name} exists but logging is OFF — API calls are not recorded.",
            "Start logging on the trail immediately."
        )


# ─────────────────────────────────────────────────────────────
# EC2 / NETWORK CHECKS
# ─────────────────────────────────────────────────────────────

def check_security_groups_open_ssh():
    """CIS 5.2 — No security group should allow 0.0.0.0/0 on port 22"""
    ec2 = boto3.client('ec2')
    sgs = ec2.describe_security_groups()['SecurityGroups']

    for sg in sgs:
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']
        open_ssh = any(
            rule.get('FromPort') == 22 and
            any(ip['CidrIp'] == '0.0.0.0/0' for ip in rule.get('IpRanges', []))
            for rule in sg.get('IpPermissions', [])
        )
        status = "FAIL" if open_ssh else "PASS"

        add_finding(
            "CIS-5.2", "SSH Not Open to World",
            "CRITICAL", f"ec2::sg/{sg_id} ({sg_name})", status,
            f"SG {sg_name} allows SSH from anywhere — brute force and credential attack exposure.",
            "Restrict port 22 to specific CIDRs or use AWS Systems Manager Session Manager."
        )


def check_security_groups_open_rdp():
    """CIS 5.3 — No security group should allow 0.0.0.0/0 on port 3389"""
    ec2 = boto3.client('ec2')
    sgs = ec2.describe_security_groups()['SecurityGroups']

    for sg in sgs:
        sg_id = sg['GroupId']
        sg_name = sg['GroupName']
        open_rdp = any(
            rule.get('FromPort') == 3389 and
            any(ip['CidrIp'] == '0.0.0.0/0' for ip in rule.get('IpRanges', []))
            for rule in sg.get('IpPermissions', [])
        )
        status = "FAIL" if open_rdp else "PASS"

        add_finding(
            "CIS-5.3", "RDP Not Open to World",
            "CRITICAL", f"ec2::sg/{sg_id} ({sg_name})", status,
            f"SG {sg_name} allows RDP from anywhere — remote desktop attack surface exposed.",
            "Restrict port 3389 to specific CIDRs or use VPN/bastion host."
        )


def check_ebs_encryption():
    """CIS 2.2.1 — EBS volumes must be encrypted at rest"""
    ec2 = boto3.client('ec2')
    volumes = ec2.describe_volumes()['Volumes']

    for vol in volumes:
        vol_id = vol['VolumeId']
        encrypted = vol.get('Encrypted', False)
        status = "PASS" if encrypted else "FAIL"

        add_finding(
            "CIS-2.2.1", "EBS Volume Encryption",
            "HIGH", f"ec2::volume/{vol_id}", status,
            f"Volume {vol_id} stores data unencrypted — data at rest is readable if snapshot is shared.",
            "Enable EBS account-level default encryption or encrypt this volume."
        )


def check_vpc_flow_logs():
    """CIS 3.9 — VPC flow logging must be enabled"""
    ec2 = boto3.client('ec2')
    vpcs = ec2.describe_vpcs()['Vpcs']

    for vpc in vpcs:
        vpc_id = vpc['VpcId']
        flow_logs = ec2.describe_flow_logs(
            Filters=[{'Name': 'resource-id', 'Values': [vpc_id]}]
        )['FlowLogs']
        active = any(fl['FlowLogStatus'] == 'ACTIVE' for fl in flow_logs)
        status = "PASS" if active else "FAIL"

        add_finding(
            "CIS-3.9", "VPC Flow Logs Enabled",
            "MEDIUM", f"ec2::vpc/{vpc_id}", status,
            f"VPC {vpc_id} has no flow logs — network traffic is invisible for forensics.",
            "Enable VPC Flow Logs to CloudWatch Logs or S3."
        )


def check_guardduty_enabled():
    """AWS Best Practice — GuardDuty must be enabled for threat detection"""
    gd = boto3.client('guardduty')
    detectors = gd.list_detectors()['DetectorIds']

    if not detectors:
        add_finding(
            "AWS-GD-1", "GuardDuty Enabled",
            "HIGH", "guardduty::account", "FAIL",
            "GuardDuty is not enabled — no active threat detection on the account.",
            "Enable GuardDuty in all regions."
        )
        return

    for det_id in detectors:
        det = gd.get_detector(DetectorId=det_id)
        status = "PASS" if det['Status'] == 'ENABLED' else "FAIL"
        add_finding(
            "AWS-GD-1", "GuardDuty Enabled",
            "HIGH", f"guardduty::{det_id}", status,
            "GuardDuty detector exists but is not enabled.",
            "Enable the GuardDuty detector."
        )


# ─────────────────────────────────────────────────────────────
# REPORT
# ─────────────────────────────────────────────────────────────

def generate_report():
    failed = [f for f in findings if f['status'] == 'FAIL']
    passed = [f for f in findings if f['status'] == 'PASS']

    by_severity = {}
    for f in failed:
        sev = f['severity']
        by_severity[sev] = by_severity.get(sev, 0) + 1

    print("\n" + "═" * 60)
    print("  COMPLIANCE SUMMARY")
    print("═" * 60)
    print(f"  Total checks  : {len(findings)}")
    print(f"  PASSED        : {len(passed)}")
    print(f"  FAILED        : {len(failed)}")
    print()
    for sev in ['CRITICAL', 'HIGH', 'MEDIUM', 'LOW']:
        count = by_severity.get(sev, 0)
        if count:
            print(f"  {sev:<10} : {count} findings")
    print("═" * 60)

    report = {
        "tool": "AWS Custom Compliance Checker",
        "author": "Ahad Hussain",
        "frameworks": ["CIS AWS Benchmark v2.0", "PCI DSS 3.2.1"],
        "scan_time": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total": len(findings),
            "passed": len(passed),
            "failed": len(failed),
            "by_severity": by_severity
        },
        "findings": findings
    }

    with open("compliance-report.json", 'w') as f:
        json.dump(report, f, indent=2, default=str)

    print(f"\n  Report saved → compliance-report.json")
    print(f"  Copy to GRC folder: cp compliance-report.json ../grc/\n")


# ─────────────────────────────────────────────────────────────
# MAIN
# ─────────────────────────────────────────────────────────────

if __name__ == "__main__":
    print("\n" + "═" * 60)
    print("  AWS Custom Compliance Checker")
    print("  CIS AWS Benchmark v2.0 + PCI DSS 3.2.1")
    print("  Author: Ahad Hussain")
    print("═" * 60 + "\n")

    checks = [
        ("S3 — Public Access Block",     check_s3_public_access_block),
        ("S3 — Default Encryption",      check_s3_encryption),
        ("IAM — Root MFA",               check_root_mfa),
        ("IAM — User MFA",               check_iam_mfa),
        ("IAM — Access Key Rotation",    check_iam_access_key_rotation),
        ("IAM — Admin Policy Direct",    check_iam_admin_policy),
        ("CloudTrail — Enabled",         check_cloudtrail_enabled),
        ("EC2 — SG SSH Open",            check_security_groups_open_ssh),
        ("EC2 — SG RDP Open",            check_security_groups_open_rdp),
        ("EC2 — EBS Encryption",         check_ebs_encryption),
        ("VPC — Flow Logs",              check_vpc_flow_logs),
        ("GuardDuty — Enabled",          check_guardduty_enabled),
    ]

    for name, fn in checks:
        print(f"[*] {name}")
        try:
            fn()
        except Exception as e:
            print(f"    ERROR: {e}")
        print()

    generate_report()
