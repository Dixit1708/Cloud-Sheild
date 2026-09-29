"""
CloudShield Cloud Configuration Misconfiguration Checker
Scans a cloud configuration JSON document for common misconfigurations.
"""


def analyze_cloud_config(config_json):
    findings = []

    # 1. Public S3 buckets
    for bucket in config_json.get("s3_buckets", []):
        name = bucket.get("name", "unnamed-bucket")
        if bucket.get("public", False) or bucket.get("acl") == "public-read":
            findings.append({
                "severity": "Critical",
                "issue": "Publicly Accessible S3 Bucket",
                "description": f"Bucket '{name}' is configured with public read access.",
                "affected_resource": name,
                "recommendation": "Disable public access and use bucket policies / signed URLs "
                                   "for controlled sharing.",
                "risk_impact": "Sensitive data stored in the bucket can be read by anyone on the internet.",
                "remediation_steps": [
                    "Enable S3 Block Public Access at the account and bucket level.",
                    "Remove public-read ACLs and public bucket policies.",
                    "Use CloudFront + signed URLs for public content delivery instead.",
                ],
            })
        if not bucket.get("encrypted", True):
            findings.append({
                "severity": "High",
                "issue": "Missing Encryption at Rest",
                "description": f"Bucket '{name}' does not have server-side encryption enabled.",
                "affected_resource": name,
                "recommendation": "Enable SSE-S3 or SSE-KMS encryption on the bucket.",
                "risk_impact": "Data at rest is unprotected if the underlying storage is compromised.",
                "remediation_steps": [
                    "Enable default encryption on the bucket.",
                    "Prefer SSE-KMS with a customer-managed key for auditability.",
                ],
            })
        if not bucket.get("logging", True):
            findings.append({
                "severity": "Medium",
                "issue": "Missing Access Logging",
                "description": f"Bucket '{name}' does not have access logging enabled.",
                "affected_resource": name,
                "recommendation": "Enable S3 server access logging or CloudTrail data events.",
                "risk_impact": "Unauthorized or anomalous access cannot be detected or investigated.",
                "remediation_steps": ["Enable access logging to a dedicated log bucket."],
            })

    # 2. Security groups open to the internet
    for sg in config_json.get("security_groups", []):
        name = sg.get("name", "unnamed-sg")
        for rule in sg.get("inbound_rules", []):
            cidr = rule.get("cidr", "")
            port = rule.get("port", "unknown")
            if cidr in ("0.0.0.0/0", "::/0"):
                severity = "Critical" if port in (22, 3389, "22", "3389") else "High"
                findings.append({
                    "severity": severity,
                    "issue": "Security Group Open to the Internet",
                    "description": f"Security group '{name}' allows inbound traffic on port "
                                    f"{port} from {cidr}.",
                    "affected_resource": name,
                    "recommendation": "Restrict inbound rules to known IP ranges or use a "
                                       "bastion/VPN for administrative access.",
                    "risk_impact": "The service is exposed to scanning and brute-force attacks "
                                    "from anywhere on the internet.",
                    "remediation_steps": [
                        "Replace 0.0.0.0/0 with specific trusted CIDR ranges.",
                        "Use AWS Systems Manager Session Manager instead of open SSH/RDP.",
                        "Add a WAF in front of public-facing web services.",
                    ],
                })

    # 3. MFA
    if not config_json.get("mfa_enabled", True):
        findings.append({
            "severity": "Critical",
            "issue": "Multi-Factor Authentication Disabled",
            "description": "MFA is not enforced for account access.",
            "affected_resource": "Account / IAM Users",
            "recommendation": "Enforce MFA for all users, especially those with console access.",
            "risk_impact": "Stolen or weak passwords alone are enough to compromise accounts.",
            "remediation_steps": [
                "Require MFA via IAM policy condition keys.",
                "Enable hardware or virtual MFA devices for all human users.",
            ],
        })

    # 4. Password policy
    pw_policy = config_json.get("password_policy", {})
    if pw_policy.get("min_length", 14) < 14 or not pw_policy.get("require_symbols", True):
        findings.append({
            "severity": "Medium",
            "issue": "Weak Password Policy",
            "description": "The account password policy does not meet security best practices "
                            "(minimum length and complexity).",
            "affected_resource": "Account Password Policy",
            "recommendation": "Require a minimum of 14 characters with upper/lower case, "
                               "numbers, and symbols.",
            "risk_impact": "Weak passwords are easier to brute-force or guess.",
            "remediation_steps": ["Update the password policy in IAM account settings."],
        })

    # 5. Monitoring / logging
    if not config_json.get("cloudtrail_enabled", True):
        findings.append({
            "severity": "High",
            "issue": "Missing Centralized Logging (CloudTrail)",
            "description": "CloudTrail (or equivalent audit logging) is not enabled account-wide.",
            "affected_resource": "Account",
            "recommendation": "Enable CloudTrail across all regions with log file validation.",
            "risk_impact": "Security incidents cannot be investigated or detected in a timely manner.",
            "remediation_steps": [
                "Enable an organization-wide multi-region CloudTrail.",
                "Send logs to a dedicated, access-restricted S3 bucket.",
            ],
        })

    if not config_json.get("monitoring_enabled", True):
        findings.append({
            "severity": "Medium",
            "issue": "Missing Monitoring & Alerting",
            "description": "No monitoring/alerting service (e.g. GuardDuty, CloudWatch alarms) is configured.",
            "affected_resource": "Account",
            "recommendation": "Enable threat detection and alarms for anomalous activity.",
            "risk_impact": "Active threats can go unnoticed for extended periods.",
            "remediation_steps": [
                "Enable GuardDuty or equivalent threat-detection service.",
                "Configure CloudWatch alarms for root account usage and IAM changes.",
            ],
        })

    # 6. Publicly exposed generic resources
    for resource in config_json.get("public_resources", []):
        findings.append({
            "severity": "High",
            "issue": "Publicly Exposed Resource",
            "description": f"Resource '{resource}' is exposed to the public internet.",
            "affected_resource": resource,
            "recommendation": "Restrict access via security groups, private subnets, or IAM policy.",
            "risk_impact": "Increases the attack surface for unauthorized access.",
            "remediation_steps": ["Move the resource into a private subnet or restrict its ACL."],
        })

    if not findings:
        findings.append({
            "severity": "Low",
            "issue": "No Major Misconfigurations Detected",
            "description": "The cloud configuration did not trigger any known misconfiguration checks.",
            "affected_resource": "Overall Configuration",
            "recommendation": "Continue periodic reviews and keep configurations under version control.",
            "risk_impact": "N/A",
            "remediation_steps": ["Schedule recurring CloudShield scans."],
        })

    return findings
