def get_content():
    return {
        "id": "T1098.003",
        "url_id": "T1098/003",
        "title": "Account Manipulation: Additional Cloud Roles",
        "description": (
            "Adversaries may add roles or permissions to cloud accounts to maintain persistent or escalated privileges. "
            "This can enable them to access or control more resources within the victim environment."
        ),
        "tags": [
            "enterprise-attack",
            "Persistence",
            "Privilege Escalation",
            "Cloud"
        ],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "IaaS, Identity Provider, Office Suite, SaaS",
        "tips": [
            "Monitor changes to cloud IAM policies or roles, especially if they grant elevated privileges.",
            "Set alerts for unexpected role assignments in administrative or high-value accounts."
        ],
        "data_sources": (
            "AWS CloudTrail, Azure Activity Logs, GCP Audit Logs, "
            "Office 365 Admin Audit Logs, Identity Provider Logs"
        ),
        "log_sources": [
            {
                "type": "Cloud",
                "source": "Cloud Provider IAM Logs (e.g., AWS CloudTrail, Azure Activity Log)",
                "destination": "SIEM or centralized logging"
            }
        ],
        "source_artifacts": [
            {
                "type": "API/CLI Command",
                "location": "Cloud management interface (CLI, portal, etc.)",
                "identify": "Evidence of new or updated roles, permissions, or policies"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Log",
                "location": "Cloud Provider IAM Logs",
                "identify": "Role creation, policy updates, or role assignments"
            }
        ],
        "detection_methods": [
            "Monitor for suspicious role assignment or policy changes, especially if performed by non-admin accounts.",
            "Correlate role changes with subsequent actions indicating privilege escalation or data exfiltration."
        ],
        "apt": [
            "Nobelium",
            "APT42"
        ],
        "spl_query": [
            "index=cloud_logs eventName=\"AttachUserPolicy\" OR eventName=\"CreatePolicyVersion\" \n| stats count by userIdentity.arn, sourceIPAddress"
        ],
        "hunt_steps": [
            "Identify accounts that frequently update or create roles/policies without a clear business need.",
            "Cross-reference role additions with other suspicious activity (e.g., unusual login times or IPs)."
        ],
        "expected_outcomes": [
            "Detection of unauthorized role creation or policy modification that grants elevated privileges."
        ],
        "false_positive": (
            "Legitimate cloud administrator actions, such as creating new roles for valid services. "
            "Validate the context, timing, and frequency of role changes."
        ),
        "clearing_steps": [
            "Remove unauthorized roles, policies, or permissions from compromised accounts.",
            "Rotate or revoke access credentials and review associated logs for further malicious activity."
        ],
        "mitre_mapping": [
            {
                "tactic": "Privilege Escalation",
                "technique": "T1078 (Valid Accounts)",
                "example": "Adversaries may modify existing accounts or create new ones with elevated roles."
            }
        ],
        "watchlist": [
            "Unexpected role or policy changes in privileged accounts.",
            "Creation of new roles or policies that are overly permissive or mimic existing roles."
        ],
        "enhancements": [
            "Implement strict role-based access controls (RBAC) with least-privilege principles.",
            "Require MFA and change approvals for role or policy modifications in critical cloud environments."
        ],
        "summary": (
            "By adding additional roles or permissions, adversaries can maintain long-term access and potentially "
            "escalate privileges within a cloud tenant."
        ),
        "remediation": (
            "Regularly audit IAM roles and policies, enforce MFA, and implement change management processes "
            "for role assignments."
        ),
        "improvements": (
            "Enable real-time alerting on role creation or modification events. "
            "Integrate cloud IAM logs into a SIEM to correlate with other security telemetry."
        )
    }
