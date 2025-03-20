def get_content():
    return {
        "id": "T1213.004",  # Tactic Technique ID
        "url_id": "1213/004",  # URL segment for technique reference
        "title": "Data from Information Repositories: Customer Relationship Management Software",  # Name of the attack technique
        "description": "Adversaries may exploit CRM software to gather sensitive customer data, such as PII and purchase histories, for financial gain or further compromise.",  # Simple description (one pair of quotes)
        "tags": [
            "CRM",
            "Customer Data",
            "PII",
            "Phishing",
            "SIM swapping",
            "Bleeping Computer US Cellular Hack 2022",
            "Bleeping Computer Mint Mobile Hack 2021",
            "Bleeping Computer Bank Hack 2020",
            "Financial Gain",
            "Collection"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "SaaS",  # Targeted environment
        "tips": [
            "Monitor CRM access for suspicious or large-scale data exports",
            "Look for unusual patterns in customer data retrieval or edits",
            "Enforce least privilege access controls and role-based permissions"
        ],
        "data_sources": "Application Log: Application Log Content, Logon Session: Logon Session Creation",
        "log_sources": [
            {
                "type": "Application Log",
                "source": "CRM Access/Activity Logs",
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
                "type": "Customer Data",
                "location": "CRM software (on-premises or cloud)",
                "identify": "PII, purchase history, support interactions"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Extracted Data",
                "location": "Adversary-controlled environment",
                "identify": "Exfiltrated customer records or PII"
            }
        ],
        "detection_methods": [
            "Review CRM logs for large or unexpected data queries",
            "Monitor for unusual account behavior or login locations",
            "Correlate CRM access with known phishing or SIM swapping attempts"
        ],
        "apt": [],  # No specific APT group listed
        "spl_query": [],
        "hunt_steps": [
            "Identify unusual spikes in CRM data exports",
            "Correlate suspicious CRM queries with external communication logs",
            "Check for newly created CRM user accounts with broad privileges"
        ],
        "expected_outcomes": [
            "Detection of unauthorized data collection or exfiltration",
            "Identification of compromised CRM accounts used for malicious queries",
            "Prevention of subsequent phishing or SIM swapping campaigns"
        ],
        "false_positive": "Legitimate bulk customer data exports for business operations may appear suspicious. Validate context and confirm business justification.",
        "clearing_steps": [
            "Remove or restrict compromised accounts and tokens",
            "Review and tighten CRM access policies/permissions",
            "Rotate or invalidate exposed API keys or service accounts"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Information Repositories: Customer Relationship Management Software (T1213.004)",
                "example": "Mining CRM systems for customer PII and purchase histories"
            }
        ],
        "watchlist": [
            "Unusual login patterns (time, location, or volume) in CRM logs",
            "Sudden large data exports or changes to CRM records",
            "Unauthorized modifications to CRM user roles or permissions"
        ],
        "enhancements": [
            "Implement MFA and SSO for CRM access",
            "Enable logging and auditing of all data export actions",
            "Use DLP solutions to detect and block unauthorized data exfiltration"
        ],
        "summary": "CRM platforms store extensive customer data that adversaries can exploit for financial gain or further attacks. Threat actors who gain access may exfiltrate personal and transaction information to facilitate phishing, SIM swapping, or target other organizations.",
        "remediation": "Enforce strict access controls and monitoring within CRM systems, apply MFA and role-based permissions, and audit logs for abnormal data retrieval or exports.",
        "improvements": "Regularly review CRM access policies, integrate CRM logs with SIEM for anomaly detection, and train personnel on safe data handling and suspicious activity reporting."
    }
