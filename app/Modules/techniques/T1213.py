def get_content():
    return {
        "id": "T1213",  # Tactic Technique ID
        "url_id": "1213",  # URL segment for technique reference
        "title": "Data from Information Repositories",  # Name of the attack technique
        "description": "Adversaries may leverage information repositories to mine valuable data, such as policies, network diagrams, or code snippets, potentially gaining access to sensitive information for further attacks. They may also abuse external sharing features to exfiltrate data.",  # Simple description (one pair of quotes)
        "tags": [
            "Information Repositories",
            "Collection",
            "SaaS",
            "Office Suite",
            "SharePoint",
            "Confluence",
            "EvasivePanda",
            "ComRAT",
            "StellarParticle",
            "Raccoon2"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "IaaS, Linux, Office Suite, SaaS, Windows, macOS",  # Targeted operating systems/environments
        "tips": [
            "Monitor privileged user access to information repositories for unusual activity",
            "Alert on large-scale or programmatic downloads of documents and pages",
            "Leverage user behavior analytics (UBA) to detect anomalies in repository access patterns"
        ],
        "data_sources": "Application Log: Application Log Content, Logon Session: Logon Session Creation",
        "log_sources": [
            {
                "type": "Application Log",
                "source": "Repository/Collaboration Platform Logs",
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
                "type": "Information Repository Data",
                "location": "Collaboration platforms, databases, or SaaS services",
                "identify": "Policies, network diagrams, credentials, or other sensitive information"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Extracted Data",
                "location": "Adversary-controlled storage or external sharing service",
                "identify": "Exported documents or data from repositories"
            }
        ],
        "detection_methods": [
            "Monitor for large or unusual data retrieval from collaboration platforms",
            "Analyze repository logs for privileged user actions or mass document access",
            "Configure alerts for external sharing events or changes in access controls"
        ],
        "apt": [
            "FIN6",
            "StellarParticle",
            "EvasivePanda"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Review logs for mass downloads or large volumes of data accessed by single users",
            "Identify newly created or unusual sharing links in SaaS platforms",
            "Correlate repository access events with suspicious external network connections"
        ],
        "expected_outcomes": [
            "Detection of malicious use of information repositories for data gathering",
            "Identification of unauthorized external sharing or exfiltration attempts",
            "Discovery of repository misconfigurations leading to public or overly broad access"
        ],
        "false_positive": "Legitimate use cases, such as employees accessing many files for project work, can generate similar patterns. Validate context and business processes.",
        "clearing_steps": [
            "Revoke unauthorized access or sharing links in the information repository",
            "Implement more restrictive permissions and verify correct user groups",
            "Update policies and security configurations to limit mass data extraction"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Information Repositories (T1213)",
                "example": "Mining sensitive data (e.g., credentials, PII) from collaboration platforms like SharePoint or Confluence"
            }
        ],
        "watchlist": [
            "Users with privileged roles accessing large volumes of documents",
            "New or unexpected sharing links created for external domains",
            "Abnormal access patterns or repeated logins from atypical locations"
        ],
        "enhancements": [
            "Enable audit logging for all repository activity, including document reads and external shares",
            "Integrate repository logs with SIEM/UBA tools for correlation and anomaly detection",
            "Regularly review and remove stale user accounts or permissions within repositories"
        ],
        "summary": "Information repositories, such as collaboration platforms or cloud databases, can store extensive sensitive data. Attackers exploit these resources to collect information that can aid in credential theft, lateral movement, or direct access to targeted data.",
        "remediation": "Use least privilege principles, enforce strong authentication, regularly audit permissions, and monitor for large or abnormal data retrieval in information repositories.",
        "improvements": "Implement real-time alerts for suspicious repository access, enforce encryption of stored data, and train personnel on secure collaboration practices to reduce the risk of accidental exposure."
    }
