def get_content():
    return {
        "id": "T1526",  # MITRE ATT&CK technique ID
        "url_id": "1526",  # URL segment for reference
        "title": "Cloud Service Discovery",  # Attack technique name
        "description": "An adversary may attempt to enumerate the cloud services running on a system after gaining access. These methods can differ from platform-as-a-service (PaaS), infrastructure-as-a-service (IaaS), or software-as-a-service (SaaS). Adversaries may use the information gained to shape follow-on behaviors, such as targeting data or credentials from enumerated services or evading identified defenses.",
        "tags": [
            "t1526",
            "cloud service discovery",
            "cloud enumeration",
            "aws reconnaissance",
            "azure discovery",
            "gcp cloud monitoring",
            "cloud security analysis",
            "cloud logging services",
            "cloud threat intelligence",
            "stormspotter azure tool",
            "aws pacu tool",
            "microsoft graph api",
            "azure resource manager api"
        ],
        "tactic": "Discovery",
        "platforms": ["IaaS", "Identity Provider", "Office Suite", "SaaS"],
        "data_sources": "Cloud Service: Cloud Service Enumeration, Logon Session: Logon Session Creation",
        "log_sources": [
            {"type": "Cloud Logs", "source": "AWS CloudTrail", "destination": "SIEM"},
            {"type": "Cloud Logs", "source": "Azure Monitor", "destination": "Security Operations"},
            {"type": "Cloud Logs", "source": "Google Cloud Audit Logs", "destination": "Cloud Security Analytics"}
        ],
        "watchlist": [
            "unexpected cloud API calls",
            "unauthorized cloud service enumeration",
            "anomalous cloud resource listing"
        ],
        "detection_methods": ["Cloud API Monitoring", "Behavioral Analysis", "Cloud Log Inspection"],
        "apt": ["Cloud-focused APTs"],
        "expected_outcomes": ["Detection of adversarial cloud reconnaissance"],
        "remediation": "Restrict cloud API access, monitor API calls, and enforce role-based access controls (RBAC).",
        "mitre_mapping": [
            {"tactic": "Discovery", "technique": "T1526", "example": "Adversary using API calls to list active cloud services."}
        ],
        "summary": "Adversaries use cloud enumeration techniques to map infrastructure, gather intelligence, and prepare for attacks.",
        "improvements": "Enhance cloud API monitoring, use IAM policies, and restrict service discovery permissions."
    }
