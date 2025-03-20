def get_content():
    return {
        "id": "T1213.001",  # Tactic Technique ID
        "url_id": "1213/001",  # URL segment for technique reference
        "title": "Data from Information Repositories: Confluence",  # Name of the attack technique
        "description": "Adversaries may leverage Confluence repositories to gather valuable information, including documentation, network diagrams, procedures, and credentials, potentially facilitating further compromise or infiltration.",  # Simple description
        "tags": [
            "Confluence",
            "Information Repositories",
            "Atlassian",
            "SaaS",
            "Credentials",
            "Documentation",
            "Network Diagrams",
            "MSTIC DEV-0537 Mar 2022",
            "Collection",
            "User-Behavioral Analytics"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "SaaS",  # Targeted environment
        "tips": [
            "Monitor privileged user access (e.g., Domain Admin) to Confluence repositories",
            "Alert on mass document/page retrieval indicative of automated scraping",
            "Leverage UBA to detect anomalies in Confluence usage patterns"
        ],
        "data_sources": "Application Log: Application Log Content, Logon Session: Logon Session Creation",
        "log_sources": [
            {
                "type": "Application Log",
                "source": "Confluence Access Logs",
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
                "type": "Confluence Pages/Spaces",
                "location": "Atlassian Confluence",
                "identify": "Policies, procedures, credentials, network diagrams, or other sensitive data"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Extracted Data",
                "location": "Adversary-controlled environment",
                "identify": "Exported or downloaded Confluence documents/pages"
            }
        ],
        "detection_methods": [
            "Review Confluence logs for mass access or unusual user patterns",
            "Correlate high-volume page retrieval with specific user accounts or sessions",
            "Alert on privileged account usage in Confluence beyond normal administrative tasks"
        ],
        "apt": [
            "DEV-0537 (LAPSUS)"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify large or abnormal Confluence export/download events",
            "Correlate suspicious Confluence access times with user session logs",
            "Check for newly created sharing links or changes in Confluence access permissions"
        ],
        "expected_outcomes": [
            "Detection of unauthorized or excessive data gathering from Confluence",
            "Identification of compromised or misused privileged accounts",
            "Discovery of sensitive information exfiltrated via Confluence"
        ],
        "false_positive": "Legitimate project activities may involve mass retrieval or export of Confluence data. Validate context and confirm business requirements.",
        "clearing_steps": [
            "Disable or restrict compromised user accounts",
            "Remove unauthorized sharing links or pages",
            "Revert any changes to Confluence access permissions"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Information Repositories: Confluence (T1213.001)",
                "example": "Collecting documentation or credentials from Confluence pages to support further attacks"
            }
        ],
        "watchlist": [
            "Mass Confluence page views/downloads by a single user",
            "Privileged accounts (e.g., Domain Admin) accessing Confluence",
            "Unusual or repeated access to sensitive Confluence spaces"
        ],
        "enhancements": [
            "Enable AccessLogFilter and centralized log collection for Confluence",
            "Implement strict permission controls and regular reviews of Confluence access rights",
            "Integrate Confluence logs with a SIEM/UBA solution to detect abnormal usage patterns"
        ],
        "summary": "Confluence often contains valuable data (e.g., credentials, system documentation) that adversaries can exploit to advance their operations or pivot to additional systems.",
        "remediation": "Apply least privilege for Confluence access, audit logs for abnormal usage, and ensure privileged accounts are not used to access information repositories unless necessary.",
        "improvements": "Regularly review and update Confluence permissions, enable multi-factor authentication for critical users, and use real-time monitoring to detect mass or anomalous data access."
    }
