def get_content():
    return {
        "id": "T1213.003",  # Tactic Technique ID
        "url_id": "1213/003",  # URL segment for technique reference
        "title": "Data from Information Repositories: Code Repositories",  # Name of the attack technique
        "description": "Adversaries may leverage code repositories to collect valuable information, including proprietary source code or embedded credentials, enabling them to develop exploits or gain access to additional resources.",  # Simple description
        "tags": [
            "Code Repositories",
            "Git",
            "SaaS",
            "APT41",
            "LAPSUS",
            "Scattered Spider",
            "Wired Uber Breach",
            "Krebs Adobe",
            "MSTIC Octo Tempest",
            "Collection"
        ],  # Up to 10 tags
        "tactic": "Collection",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocols used in the attack technique (e.g., Git, HTTP/HTTPS, SSH)
        "os": "SaaS",  # Targeted environment
        "tips": [
            "Monitor code repository access for unusual activity, especially from privileged or newly created accounts",
            "Look for large or frequent repository clones or downloads, which may indicate data exfiltration",
            "Use user behavior analytics (UBA) to detect anomalies in repository usage patterns"
        ],
        "data_sources": "Application Log: Application Log Content, Logon Session: Logon Session Creation",
        "log_sources": [
            {
                "type": "Application Log",
                "source": "Repository Logs",
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
                "type": "Code",
                "location": "Local or cloud-based code repositories",
                "identify": "Proprietary source code, credentials, or other sensitive information"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Extracted Data",
                "location": "Adversary-controlled environment",
                "identify": "Downloaded or cloned code repository content"
            }
        ],
        "detection_methods": [
            "Monitor repository logs for unusual access times, IP addresses, or large-scale downloads",
            "Correlate suspicious repository activity with network or endpoint alerts",
            "Leverage UBA to detect abnormal user actions or excessive repository interactions"
        ],
        "apt": [
            "APT41",
            "DEV-0537 (LAPSUS)",
            "Scattered Spider"
        ],
        "spl_query": [],
        "hunt_steps": [
            "Identify sudden or large repository clones/forks by unexpected accounts",
            "Check commit history for newly introduced or removed credentials",
            "Correlate repository events with suspicious network or endpoint activity"
        ],
        "expected_outcomes": [
            "Detection of unauthorized code repository access or credential harvesting",
            "Identification of proprietary code exfiltration or malicious usage",
            "Discovery of suspicious patterns in code repository logs or commits"
        ],
        "false_positive": "Legitimate development activities may involve large repository operations or credential usage. Validate context and confirm developer workflows.",
        "clearing_steps": [
            "Revoke compromised credentials and personal access tokens",
            "Remove unauthorized forks or clones from the repository",
            "Enforce stricter repository access policies and permissions"
        ],
        "mitre_mapping": [
            {
                "tactic": "Collection",
                "technique": "Data from Information Repositories: Code Repositories (T1213.003)",
                "example": "Collecting proprietary code or credentials from private Git repositories"
            }
        ],
        "watchlist": [
            "New or unexpected user accounts accessing private repositories",
            "Unusually large or frequent repository clones or pull requests",
            "Commits containing suspicious files (e.g., potential credential leaks)"
        ],
        "enhancements": [
            "Implement code scanning for embedded credentials or sensitive information",
            "Restrict personal access tokens or API tokens to least privilege",
            "Enable single sign-on (SSO) and multi-factor authentication (MFA) for code repositories"
        ],
        "summary": "Adversaries may collect sensitive data from code repositories, including source code and credentials, to facilitate further compromise or exploit development.",
        "remediation": "Apply least privilege to repository access, enforce strong authentication, scan code for credentials, and monitor for unusual or excessive repository operations.",
        "improvements": "Implement real-time alerts on suspicious repository actions, integrate code repositories with DLP solutions, and regularly review user access logs to detect anomalies."
    }
