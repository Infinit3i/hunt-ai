def get_content():
    return {
        "id": "T1069.003",
        "url_id": "T1069/003",
        "title": "Permission Groups Discovery: Cloud Groups",
        "description": "Adversaries may attempt to find cloud groups and permission settings. The knowledge of cloud permission groups can help adversaries determine the particular roles of users and groups within an environment, as well as which users are associated with a particular group.",
        "tags": ["discovery", "cloud", "azure", "aws", "gcp", "T1069.003"],
        "tactic": "Discovery",
        "protocol": "HTTPS, REST API, PowerShell, CLI",
        "os": "IaaS, Identity Provider, Office Suite, SaaS",
        "tips": [
            "Monitor for enumeration of cloud roles and groups via CLI or API",
            "Use cloud native logging like AWS CloudTrail and Azure Activity Logs to track group access"
        ],
        "data_sources": "Application Log, Command, Group, Process",
        "log_sources": [
            {"type": "Application Log", "source": "", "destination": ""},
            {"type": "Command", "source": "", "destination": ""},
            {"type": "Group", "source": "", "destination": ""},
            {"type": "Process", "source": "", "destination": ""}
        ],
        "source_artifacts": [
            {"type": "Command History", "location": "CloudShell / local terminal history", "identify": "Get-MsolRole, az ad user get-member-groups, ListRolePolicies"},
            {"type": "Cloud Activity Logs", "location": "Azure Activity Logs / AWS CloudTrail", "identify": "Group enumeration or role listing APIs"}
        ],
        "destination_artifacts": [
            {"type": "Cloud Audit Logs", "location": "Service provider log console", "identify": "Cloud group enumeration from adversary account or unknown location"}
        ],
        "detection_methods": [
            "Monitor API calls such as GetBucketAcl, ListAttachedRolePolicies, or az ad user get-member-groups",
            "Detect anomalies in cloud audit logs for group enumeration behavior",
            "Monitor usage of PowerShell modules such as AADInternals"
        ],
        "apt": ["APT34", "APT41", "FIN6", "SILENTTRINITY", "StellarParticle", "Bumblebee"],
        "spl_query": [
            "index=cloud sourcetype=azure_activity operationName=GetGroupMembers",
            "index=aws sourcetype=cloudtrail eventName=ListRolePolicies",
            "index=gcp sourcetype=gcp_auditlog method=cloudidentity.groups.list"
        ],
        "hunt_steps": [
            "Identify cloud users performing group or role enumeration",
            "Track correlation between group discovery and sensitive cloud asset access",
            "Look for spikes in group listing from previously inactive accounts"
        ],
        "expected_outcomes": [
            "Identification of unauthorized cloud group discovery",
            "Mapping of user-role relationships to assist follow-on privilege escalation"
        ],
        "false_positive": "Cloud admins or automation systems may query group roles during legitimate maintenance windows.",
        "clearing_steps": [
            "Clear CloudShell history or session storage",
            "Purge activity logs (where permitted), or rotate cloud credentials",
            "Review permissions of compromised accounts and remove excess roles"
        ],
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1087.004", "example": "User Account Discovery - Cloud account enumeration after group role discovery"}
        ],
        "watchlist": [
            "Access to cloud group enumeration APIs from unusual geolocations",
            "Use of enumeration commands by non-privileged users"
        ],
        "enhancements": [
            "Enable fine-grained logging for IAM APIs",
            "Integrate SIEM with cloud audit logs for real-time detection"
        ],
        "summary": "Cloud group discovery provides adversaries visibility into account permissions, helping them target roles for lateral movement and privilege escalation.",
        "remediation": "Apply least privilege, audit role assignments, and enable multi-factor authentication for accounts with IAM access.",
        "improvements": "Enforce anomaly detection over IAM API usage and deploy just-in-time permissions where supported.",
        "mitre_version": "16.1"
    }
