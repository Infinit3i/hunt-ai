def get_content():
    return {
        "id": "T1213.002",  # Tactic Technique ID
        "url_id": "1213/002",  # URL segment for technique reference
        "title": "Data from Information Repositories: SharePoint",  # Name of the attack technique
        "description": "Adversaries may leverage SharePoint repositories to gather valuable data such as policies, procedures, network diagrams, credentials, and more, potentially facilitating deeper compromise or lateral movement.",  # Simple description
        "tags": [
            "SharePoint",
            "Information Repositories",
            "Office Suite",
            "Unsecured Credentials",
            "Collection",
            "Windows",
            "NCC Group LAPSUS Apr 2022",
            "CISA",
            "UBA",
            "Microsoft SharePoint Logging"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Office Suite, Windows",  # Targeted environment
        "tips": [
            "Monitor SharePoint user access logs for large-scale or suspicious document retrieval",
            "Alert on privileged accounts (e.g., Domain Admin) accessing SharePoint content",
            "Leverage user behavior analytics (UBA) to detect anomalies in usage patterns"
        ],
        "data_sources": "Application Log: Application Log Content, Cloud Service: Cloud Service Metadata, Logon Session: Logon Session Creation",
        "log_sources": [
            {
                "type": "Application Log",
                "source": "SharePoint Access Logs",
                "destination": "SIEM"
            },
            {
                "type": "Cloud Service",
                "source": "SharePoint Online Logs",
                "destination": "SIEM"
            },
            {
                "type": "Logon Session",
                "source": "Authentication Logs",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Documents",
                "location": "SharePoint repository",
                "identify": "Policies, procedures, network diagrams, credentials, etc."
            }
        ],
        "destination_artifacts": [
            {
                "type": "Extracted Data",
                "location": "Adversary-controlled environment",
                "identify": "Downloaded or exfiltrated files from SharePoint"
            }
        ],
        "detection_methods": [
            "Analyze SharePoint logs for unusual access patterns or mass document retrieval",
            "Correlate suspicious SharePoint activity with endpoint or network logs",
            "Alert on privileged account usage in SharePoint outside of normal administrative tasks"
        ],
        "apt": [
            "DEV-0537 (LAPSUS)",
            "GOLD SAHARA",
            "APT15"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify large volumes of document/page retrieval by a single account",
            "Cross-reference suspicious user activity with IP addresses or login times",
            "Check for newly created or modified sharing links and permission changes"
        ],
        "expected_outcomes": [
            "Detection of unauthorized or excessive data gathering from SharePoint",
            "Identification of compromised privileged accounts used for data access",
            "Discovery of large-scale exfiltration attempts via SharePoint"
        ],
        "false_positive": "Legitimate bulk data usage, such as large project migrations or archiving, may mimic suspicious patterns. Validate context and business requirements.",
        "clearing_steps": [
            "Disable or restrict compromised accounts and revoke unauthorized shares/links",
            "Revert any permission changes that granted excessive access",
            "Review and strengthen SharePoint access policies and permissions"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Information Repositories: SharePoint (T1213.002)",
                "example": "Adversaries scraping or downloading large volumes of data from SharePoint"
            }
        ],
        "watchlist": [
            "High-volume SharePoint file access by a single user",
            "Off-hours or unusual geolocation-based SharePoint logins",
            "Privileged accounts frequently accessing or downloading documents"
        ],
        "enhancements": [
            "Enable advanced SharePoint auditing (e.g., user access logging)",
            "Implement multi-factor authentication for SharePoint access",
            "Use data loss prevention (DLP) solutions to detect sensitive document exfiltration"
        ],
        "summary": "SharePoint often contains sensitive information ranging from credentials to architectural diagrams, making it a prime target for adversaries seeking to gather data for further attacks or lateral movement.",
        "remediation": "Enforce strict access controls, monitor logs for suspicious usage, and regularly review SharePoint permissions to ensure least privilege.",
        "improvements": "Integrate SharePoint logs with a SIEM/UBA platform, perform periodic audits of shared content, and educate users on secure document handling and collaboration practices."
    }
