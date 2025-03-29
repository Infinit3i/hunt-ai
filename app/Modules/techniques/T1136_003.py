def get_content():
    return {
        "id": "T1136.003",  # Tactic Technique ID
        "url_id": "T1136/003",  # URL segment for technique reference
        "title": "Create Account: Cloud Account",  # Name of the attack technique
        "description": "Adversaries may create new cloud accounts to maintain persistent access to victim resources by leveraging the permissions and trust associated with those accounts.",  # Simple description
        "tags": [
            "cloud account",
            "account creation",
            "persistence",
            "credential access"
        ],
        "tactic": "Persistence",  # Associated MITRE ATT&CK tactic
        "protocol": "N/A",  # Not specifically protocol-based
        "os": "IaaS, Identity Provider, Office Suite, SaaS",  # Targeted operating systems/environments
        "tips": [
            "Regularly audit user and service accounts in cloud environments.",
            "Enable and monitor multi-factor authentication (MFA) for administrative and privileged accounts.",
            "Review IAM/role assignments for anomalous or suspicious additions, especially admin privileges."
        ],
        "data_sources": "User Account",  # Data sources relevant to detection (e.g., user account logs)
        "log_sources": [
            {
                "type": "User Account",
                "source": "User Account Creation",
                "destination": ""
            }
        ],
        "source_artifacts": [
            {
                "type": "Cloud User/Service Account",
                "location": "Cloud identity provider or IAM service",
                "identify": "Check for newly created accounts with unusual or high privileges"
            }
        ],
        "destination_artifacts": [
            {
                "type": "IAM Permissions",
                "location": "Cloud resource or subscription",
                "identify": "Identify assigned roles or policies granting access to resources"
            }
        ],
        "detection_methods": [
            "Monitor cloud admin logs (e.g., Azure Activity Logs, AWS CloudTrail, GCP Admin Activity) for new account creations.",
            "Set alerts for sudden changes in privileged role assignments or unexpected additions to IAM policies.",
            "Track unusual usage of newly created service accounts or login patterns from unknown IP addresses."
        ],
        "apt": [],  # No specific APT groups listed here
        "spl_query": [
            "index=cloud \n| stats count by user_name, event_name, role_assigned"
        ],
        "hunt_steps": [
            "Review newly created cloud accounts or service principals for suspicious privileges or roles.",
            "Correlate creation events with any subsequent high-risk actions, such as provisioning resources or disabling logs.",
            "Check for new credentials (e.g., keys, tokens) associated with recently created accounts."
        ],
        "expected_outcomes": [
            "Identification of unauthorized cloud accounts with elevated privileges.",
            "Detection of unusual or suspicious usage of newly created accounts or service principals."
        ],
        "false_positive": (
            "Legitimate cloud administration tasks (e.g., new developer onboarding, service account creation for "
            "internal projects) may appear suspicious. Validate through change management or project documentation."
        ),
        "clearing_steps": [
            "Disable or remove unauthorized cloud accounts and revoke any associated credentials.",
            "Rotate existing credentials and review IAM policies to ensure least privilege.",
            "Implement stricter role assignment processes, including just-in-time or approval-based access."
        ],
        "mitre_mapping": [
            {
                "tactic": "Persistence",
                "technique": "Additional Cloud Credentials (T1098.001)",
                "example": "Adversaries may add more credentials to the newly created account for redundancy."
            }
        ],
        "watchlist": [
            "Newly created cloud accounts with admin or privileged roles.",
            "Suspicious role changes granting excessive permissions (owner, super admin, etc.).",
            "Accounts that remain unused after creation or only used sporadically from unexpected locations."
        ],
        "enhancements": [
            "Enforce MFA for all privileged and administrative cloud accounts.",
            "Use automated governance tools or scripts to detect and alert on unexpected account creations.",
            "Implement conditional access policies restricting login from unusual geolocations or IP addresses."
        ],
        "summary": (
            "Adversaries may create cloud accounts to gain persistent access and leverage the trust/permissions "
            "associated with those accounts. By obtaining administrative or service-level privileges, attackers "
            "can maintain footholds, escalate privileges, and access resources without deploying additional "
            "malware on endpoints."
        ),
        "remediation": (
            "Enforce least privilege by default, implement strong authentication (MFA), and regularly audit newly "
            "created accounts and their permissions. Remove unused or unauthorized accounts promptly."
        ),
        "improvements": (
            "Automate detection of suspicious account creation events, integrate with SIEM for real-time alerting, "
            "and adopt just-in-time or just-enough-administration practices for cloud identity and access management."
        )
    }
