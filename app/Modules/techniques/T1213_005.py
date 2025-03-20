def get_content():
    return {
        "id": "T1213.005",  # Tactic Technique ID
        "url_id": "1213/005",  # URL segment for technique reference
        "title": "Data from Information Repositories: Messaging Applications",  # Name of the attack technique
        "description": "Adversaries may leverage messaging applications (e.g., Microsoft Teams, Slack) to mine sensitive information, including credentials, code snippets, or incident response discussions, which can aid further compromise or evasion.",  # Simple description
        "tags": [
            "Messaging Applications",
            "Chat Data",
            "Office Suite",
            "SaaS",
            "Credentials",
            "Source Code",
            "Incident Response",
            "Ragnar Locker 2021",
            "Scattered Spider",
            "Collection"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Office Suite, SaaS",  # Targeted environments
        "tips": [
            "Monitor chat access logs for abnormal or high-volume data retrieval",
            "Look for unexpected file attachments, code snippets, or credential leaks",
            "Alert on suspicious user behavior, such as reading multiple sensitive channels quickly"
        ],
        "data_sources": "Application Log: Application Log Content",
        "log_sources": [
            {
                "type": "Application Log",
                "source": "Messaging/Chat Platform Logs",
                "destination": "SIEM"
            }
        ],
        "source_artifacts": [
            {
                "type": "Chat Messages",
                "location": "Messaging applications (Teams, Slack, etc.)",
                "identify": "Credentials, code snippets, links to internal resources"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Extracted Data",
                "location": "Adversary-controlled environment",
                "identify": "Downloaded transcripts, attachments, or channel archives"
            }
        ],
        "detection_methods": [
            "Review chat platform logs for unusual user activity or mass message exports",
            "Correlate large file downloads or transcript exports with user account behavior",
            "Monitor for known keywords (e.g., credentials, passwords) in messages or attachments"
        ],
        "apt": [
            "DEV-0537 (LAPSUS)",
            "Scattered Spider"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify chat channels containing sensitive data (credentials, incident response notes)",
            "Check for abnormal login locations or repeated failed authentication attempts in messaging apps",
            "Correlate chat platform events with external network logs to spot exfiltration patterns"
        ],
        "expected_outcomes": [
            "Detection of adversaries scraping chat channels for sensitive data",
            "Identification of compromised or misused accounts accessing privileged discussions",
            "Prevention of data exfiltration via messaging platforms"
        ],
        "false_positive": "Legitimate collaboration on incident response or code reviews may involve sharing sensitive details. Validate context and confirm user roles.",
        "clearing_steps": [
            "Disable or limit access for compromised accounts",
            "Revoke any active sessions or tokens for affected messaging platforms",
            "Remove sensitive data from public or general-purpose channels"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Information Repositories: Messaging Applications (T1213.005)",
                "example": "Harvesting chat messages containing credentials or sensitive internal links"
            }
        ],
        "watchlist": [
            "High-volume channel downloads or transcript exports",
            "Sudden membership changes to restricted channels",
            "Unusual off-hours or geolocation-based chat access"
        ],
        "enhancements": [
            "Implement multi-factor authentication for messaging platforms",
            "Use data loss prevention (DLP) solutions to scan messages for credentials or PII",
            "Limit access to sensitive channels and enforce least privilege"
        ],
        "summary": "Messaging applications often contain valuable data, including credentials, proprietary info, and incident response communications. Adversaries who gain access can exploit these conversations to advance attacks or evade detection.",
        "remediation": "Apply least privilege to sensitive channels, enforce strong authentication, and continuously monitor messaging logs for suspicious activity.",
        "improvements": "Regularly review user and channel permissions, implement chat content scanning for sensitive data, and train staff on secure messaging practices."
    }
