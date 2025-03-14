def get_content():
    return {
        "id": "T1098.001",
        "url_id": "1098/001",
        "title": "Account Manipulation: Additional Cloud Credentials",
        "description": (
            "Adversaries may add credentials to cloud accounts (e.g., new SSH keys, access keys, or service principal "
            "credentials) to maintain persistent or elevated access."
        ),
        "tags": [
            "enterprise-attack",
            "Persistence",
            "Privilege Escalation",
            "Cloud"
        ],
        "tactic": "Persistence, Privilege Escalation",
        "protocol": "",
        "os": "IaaS, Identity Provider, SaaS",
        "tips": [
            "Monitor for suspicious creation or import of new keys and credentials in cloud environments.",
            "Check for unusual IAM or service principal modifications."
        ],
        "data_sources": (
            "Azure Activity Logs, AWS CloudTrail, GCP Audit Logs, Identity Provider Logs"
        ),
        "log_sources": [
            {
                "type": "Cloud",
                "source": "Cloud Provider Audit Logs (e.g., AWS CloudTrail, Azure Activity Log)",
                "destination": "SIEM or centralized logging"
            }
        ],
        "source_artifacts": [
            {
                "type": "API/CLI Command",
                "location": "Cloud management interface (CLI, portal, etc.)",
                "identify": "Evidence of adding new credentials or modifying existing ones"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Log",
                "location": "Cloud Provider Audit Logs",
                "identify": "Creation/import of keys or credentials"
            }
        ],
        "detection_methods": [
            "Monitor for unexpected credential creation or import APIs (e.g., CreateKeyPair, ImportKeyPair, CreateAccessKey).",
            "Alert on credential-related changes from unusual accounts or outside normal business hours."
        ],
        "apt": [
            "APT42",
            "Nobelium"
        ],
        "spl_query": [
            "index=cloud_logs eventName=\"CreateKeyPair\" OR eventName=\"CreateAccessKey\" \n| stats count by userIdentity.arn, sourceIPAddress"
        ],
        "hunt_steps": [
            "Identify unauthorized SSH key additions or new access key generation events.",
            "Correlate with suspicious login or network activity that may indicate adversary presence."
        ],
        "expected_outcomes": [
            "Detection of unauthorized credential additions that can facilitate persistent or escalated cloud access."
        ],
        "false_positive": (
            "Legitimate cloud operations such as credential rotation or new service deployments. "
            "Validate context and frequency of credential additions."
        ),
        "clearing_steps": [
            "Remove unauthorized credentials (SSH keys, service principal secrets, access keys).",
            "Rotate existing credentials and enable MFA for critical accounts."
        ],
        "mitre_mapping": [
            {
                "tactic": "Privilege Escalation",
                "technique": "T1078 (Valid Accounts)",
                "example": "Using newly added credentials to escalate privileges or bypass existing security measures."
            }
        ],
        "watchlist": [
            "Repeated or automated generation of new credentials across multiple accounts.",
            "Use of privileged roles (e.g., Application Administrator, root) to create keys or secrets."
        ],
        "enhancements": [
            "Implement Just-In-Time (JIT) access for credential management.",
            "Enable MFA and strong password policies on all privileged cloud accounts."
        ],
        "summary": (
            "Adversaries may add new or malicious credentials to cloud accounts to maintain persistent or elevated "
            "access in the environment."
        ),
        "remediation": (
            "Limit who can create or import credentials, enforce MFA, and regularly review credential usage. "
            "Implement least-privilege IAM policies."
        ),
        "improvements": (
            "Integrate cloud logs with SIEM for real-time alerting and correlation. "
            "Use anomaly detection on IAM credential creation events."
        )
    }
