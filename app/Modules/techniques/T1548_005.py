def get_content():
    return {
        "id": "T1548.005",
        "url_id": "1548/005",
        "title": "Abuse Elevation Control Mechanism: Temporary Elevated Cloud Access",
        "description": (
            "Adversaries may abuse permission configurations that allow them to gain temporarily elevated access to cloud "
            "resources. Many cloud environments allow administrators to grant user or service accounts permission to request "
            "just-in-time access to roles, impersonate other accounts, pass roles onto resources and services, or otherwise gain "
            "short-term access to a set of privileges that may be distinct from their own."
        ),
        "tags": ["Privilege Escalation", "Defense Evasion", "Cloud Exploitation"],
        "tactic": "Defense Evasion, Privilege Escalation",
        "protocol": "Cloud Identity and Access Management (IAM)",
        "os": "IaaS, Identity Provider, Office Suite",
        "tips": [
            "Monitor for unexpected just-in-time access role requests.",
            "Ensure cloud identity policies enforce the principle of least privilege.",
            "Audit cloud service account usage and impersonation events.",
            "Limit 'PassRole' and 'ServiceAccountUser' permissions to essential users only.",
        ],
        "data_sources": "User Account: User Account Modification",
        "log_sources": [
            {"type": "Cloud IAM Logs", "source": "AWS CloudTrail, GCP IAM, Azure AD Logs", "destination": "SIEM"},
            {"type": "User Activity Logs", "source": "Cloud Access Monitoring", "destination": "Security Operations"},
        ],
        "source_artifacts": [
            {"type": "Cloud Role Assignment", "location": "IAM Role Logs", "identify": "Temporary privilege escalation events"},
            {"type": "Access Token Creation", "location": "Service Account Logs", "identify": "Use of impersonation permissions"},
        ],
        "destination_artifacts": [
            {"type": "Resource Privilege Escalation", "location": "Cloud Resource Logs", "identify": "Services performing actions with elevated privileges"},
        ],
        "detection_methods": [
            "Monitor IAM role assignment logs for unexpected privilege escalation.",
            "Detect unusual service account impersonation activity.",
            "Analyze role modifications that do not align with standard business workflows.",
        ],
        "apt": ["Unknown at this time"],
        "spl_query": [
            "index=cloud_logs sourcetype=iam_logs \n| search role_assumption \n| stats count by user, role, action",
        ],
        "hunt_steps": [
            "Identify accounts requesting just-in-time role escalations.",
            "Analyze service accounts using impersonation permissions.",
            "Audit cloud access logs for privilege misuse patterns.",
        ],
        "expected_outcomes": [
            "Privilege Escalation Detected: Investigate unauthorized cloud role modifications.",
            "No Malicious Activity Found: Ensure cloud IAM security policies are enforced.",
        ],
        "false_positive": "Some legitimate just-in-time access requests may occur; validate business justification before raising an alert.",
        "clearing_steps": [
            "Revoke unnecessary temporary cloud access roles.",
            "Audit IAM policies to restrict impersonation and privilege escalation.",
            "Implement logging and monitoring to track role modifications in real-time.",
        ],
        "mitre_mapping": [
            {"tactic": "Privilege Escalation", "technique": "T1548.005", "example": "Abusing IAM role assumptions for temporary elevated access."},
        ],
        "watchlist": [
            "Monitor cloud role assumptions for unexpected privilege escalations.",
            "Detect excessive use of just-in-time access permissions.",
            "Analyze service account activity for impersonation abuse.",
        ],
        "enhancements": [
            "Implement approval-based workflows for just-in-time access requests.",
            "Enforce MFA requirements for privilege escalation actions.",
        ],
        "summary": "Adversaries may exploit temporary privilege escalation mechanisms in cloud environments to gain unauthorized access.",
        "remediation": "Enforce strict IAM policies, audit role assignments, and limit access to sensitive cloud permissions.",
        "improvements": "Enhance logging and auditing of cloud privilege escalation attempts to detect misuse.",
    }
