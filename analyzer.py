"""
CloudShield IAM Policy Analyzer
Scans an IAM policy JSON document for risky permission patterns.
"""

HIGH_RISK_ACTIONS = {
    "iam:*", "iam:createuser", "iam:attachuserpolicy", "iam:putuserpolicy",
    "iam:createaccesskey", "iam:updateassumerolepolicy", "sts:assumerole",
}

ADMIN_LIKE_ACTIONS = {"*:*", "*"}


def _as_list(value):
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def analyze_iam_policy(policy_json):
    """
    Analyze an IAM policy document (AWS-style: {"Statement": [...]})
    and return a list of finding dicts.
    """
    findings = []
    statements = policy_json.get("Statement", [])
    statements = _as_list(statements)

    for idx, stmt in enumerate(statements, start=1):
        effect = stmt.get("Effect", "Allow")
        if effect != "Allow":
            continue

        actions = [a.lower() for a in _as_list(stmt.get("Action"))]
        resources = _as_list(stmt.get("Resource"))
        resource_wildcard = any(r == "*" for r in resources)
        action_wildcard = any(a == "*" for a in actions)

        # 1. Full admin access
        if action_wildcard and resource_wildcard:
            findings.append({
                "severity": "Critical",
                "issue": "Full Administrative Access Granted",
                "description": f"Statement #{idx} grants Action '*' on Resource '*', "
                                f"providing unrestricted administrative access to all AWS services.",
                "affected_resource": f"Statement #{idx}",
                "recommendation": "Apply the principle of least privilege. Scope actions and "
                                   "resources to only what is required for the role.",
                "risk_impact": "An attacker or compromised credential with this policy can "
                                "take full control of the entire cloud account.",
                "remediation_steps": [
                    "Remove wildcard '*' from both Action and Resource.",
                    "Define an explicit allow-list of required actions.",
                    "Use IAM Access Analyzer to generate a least-privilege policy.",
                    "Attach the policy to a role instead of a user where possible.",
                ],
            })
            continue

        # 2. Wildcard actions only
        if action_wildcard:
            findings.append({
                "severity": "High",
                "issue": "Wildcard Action Permissions",
                "description": f"Statement #{idx} uses Action '*', allowing any API action to be performed.",
                "affected_resource": f"Statement #{idx}",
                "recommendation": "Replace the wildcard with an explicit list of required actions "
                                   "(e.g. s3:GetObject, s3:PutObject).",
                "risk_impact": "Grants excessive capability beyond what the workload needs, "
                                "increasing blast radius if credentials leak.",
                "remediation_steps": [
                    "Audit CloudTrail logs to identify actually-used actions.",
                    "Rewrite the statement with an explicit action list.",
                    "Re-test the workload after tightening permissions.",
                ],
            })

        # 3. Wildcard resource only
        if resource_wildcard and not action_wildcard:
            findings.append({
                "severity": "High",
                "issue": "Wildcard Resource Permissions",
                "description": f"Statement #{idx} applies to Resource '*', allowing the listed "
                                f"actions on every resource in the account.",
                "affected_resource": f"Statement #{idx}",
                "recommendation": "Scope the Resource field to specific ARNs.",
                "risk_impact": "Actions intended for one resource can be performed on all "
                                "resources of that type, including sensitive ones.",
                "remediation_steps": [
                    "Identify the specific ARNs the role actually needs.",
                    "Replace '*' with those explicit ARNs.",
                    "Use resource tags + condition keys for dynamic scoping if needed.",
                ],
            })

        # 4. Dangerous IAM/privilege-escalation actions
        risky_hits = [a for a in actions if a in HIGH_RISK_ACTIONS]
        if risky_hits:
            findings.append({
                "severity": "Critical",
                "issue": "Privilege Escalation Risk",
                "description": f"Statement #{idx} includes sensitive IAM actions: "
                                f"{', '.join(sorted(set(risky_hits)))}.",
                "affected_resource": f"Statement #{idx}",
                "recommendation": "Restrict these actions to trusted break-glass admin roles "
                                   "only, protected by MFA.",
                "risk_impact": "These actions can be used to create new credentials or elevate "
                                "privileges, bypassing existing access controls.",
                "remediation_steps": [
                    "Move these permissions to a dedicated, tightly-monitored admin role.",
                    "Require MFA and approval workflow for use.",
                    "Enable CloudTrail alerts on these specific API calls.",
                ],
            })

        # 5. Missing condition block on broad statements
        if (action_wildcard or resource_wildcard) and "Condition" not in stmt:
            findings.append({
                "severity": "Medium",
                "issue": "Overly Broad Policy Without Conditions",
                "description": f"Statement #{idx} has broad permissions with no Condition block "
                                f"to constrain when/how it applies.",
                "affected_resource": f"Statement #{idx}",
                "recommendation": "Add Condition keys (e.g. IP range, MFA-present, source VPC) "
                                   "to limit the blast radius.",
                "risk_impact": "Without conditions, the permission applies unconditionally, "
                                "increasing exposure.",
                "remediation_steps": [
                    "Add aws:MultiFactorAuthPresent condition for sensitive actions.",
                    "Restrict by aws:SourceIp or aws:SourceVpc where applicable.",
                ],
            })

    if not statements:
        findings.append({
            "severity": "Low",
            "issue": "Empty or Unrecognized Policy Document",
            "description": "No 'Statement' array was found in the uploaded IAM policy JSON.",
            "affected_resource": "Policy Document",
            "recommendation": "Verify the file is a valid IAM policy document.",
            "risk_impact": "Analysis could not evaluate permissions.",
            "remediation_steps": ["Re-export the policy JSON from your cloud provider console."],
        })

    return findings
