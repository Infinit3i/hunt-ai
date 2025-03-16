def get_content():
    return {
        "id": "T1538",  # MITRE ATT&CK technique ID
        "url_id": "1538",  # URL segment for reference
        "title": "Cloud Service Dashboard",  # Attack technique name
        "description": "An adversary may use a cloud service dashboard GUI with stolen credentials to gain useful information from an operational cloud environment, such as specific services, resources, and features. For example, the GCP Command Center can be used to view all assets, findings of potential security risks, and to run additional queries, such as finding public IP addresses and open ports. Depending on the configuration of the environment, an adversary may be able to enumerate more information via the graphical dashboard than an API. This allows the adversary to gain information without making any API requests.",
        "tags": [
            "t1538",
            "cloud service dashboard",
            "cloud gui attack",
            "stolen cloud credentials",
            "aws console attack",
            "gcp command center enumeration",
            "azure portal access",
            "cloud service reconnaissance",
            "cloud security monitoring",
            "cloud discovery",
            "unauthorized cloud access"
        ],
        "tactic": "Discovery",
        "platforms": ["IaaS", "Identity Provider", "Office Suite", "SaaS"],
        "data_sources": "Logon Session: Logon Session Creation, User Account: User Account Authentication",
        "log_sources": [
            {"type": "Cloud Logs", "source": "AWS CloudTrail", "destination": "SIEM"},
            {"type": "Cloud Logs", "source": "Azure Monitor", "destination": "Security Operations"},
            {"type": "Cloud Logs", "source": "Google Cloud Audit Logs", "destination": "Cloud Security Analytics"}
        ],
        "watchlist": [
            "suspicious cloud login activity",
            "unauthorized access to cloud dashboards",
            "multiple failed logins from unusual locations"
        ],
        "detection_methods": ["Cloud Access Logs", "User Behavior Analytics", "Session Anomaly Detection"],
        "apt": ["Scattered Spider", "Cloud-focused APTs"],
        "expected_outcomes": ["Detection of unauthorized cloud management console access"],
        "remediation": "Enable MFA for cloud accounts, monitor cloud service access logs, and restrict dashboard access to trusted networks.",
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1538", "example": "Adversary using a cloud management console to enumerate services and resources."}
        ],
        "summary": "Adversaries can exploit cloud service dashboards using stolen credentials to gather intelligence on services, resources, and configurations.",
        "improvements": "Enhance cloud logging, restrict admin access, and enforce conditional access policies."
    }
