def get_content():
    return {
        "id": "T1584.006",  # Tactic Technique ID
        "url_id": "1584/006",  # URL segment for technique reference
        "title": "Compromise Infrastructure: Web Services",  # Name of the attack technique
        "description": (
            "Adversaries may compromise third-party web services (e.g., GitHub, Twitter, Dropbox, Google, SendGrid) "
            "that can be used during targeting. By taking ownership of legitimate user access, adversaries can "
            "leverage these services for Command and Control, Exfiltration, or Phishing. Such abuse is difficult "
            "to detect due to the trust and ubiquity associated with popular web services. Compromised web-based "
            "email services may further benefit adversaries by leveraging trusted domains to conduct malicious "
            "operations."
        ),
        "tags": [
            "web service compromise",
            "resource development",
            "cloud infrastructure",
            "command and control",
            "exfiltration",
            "phishing"
        ],
        "tactic": "Resource Development",  # Associated MITRE ATT&CK tactic
        "protocol": "HTTP/HTTPS",  # Protocol used in the attack technique
        "os": "N/A",  # Targeted operating systems
        "tips": [
            "Implement MFA and strict password policies for web-based services.",
            "Review login patterns for suspicious activities or unusual locations.",
            "Regularly audit access logs and user permissions for third-party services."
        ],
        "data_sources": "Internet Scan",  # Data sources relevant to detection
        "log_sources": [
            {"type": "Internet Scan", "source": "Response Content", "destination": ""}
        ],
        "source_artifacts": [
            {
                "type": "Web service credentials",
                "location": "Compromised user accounts",
                "identify": "Check for unauthorized access or changes"
            }
        ],
        "destination_artifacts": [
            {
                "type": "Network Traffic",
                "location": "Inbound/Outbound connections",
                "identify": "Identify suspicious interactions with web services"
            }
        ],
        "detection_methods": [
            "Monitor for unusual patterns in web service usage (e.g., excessive API calls, suspicious file sharing).",
            "Correlate known adversary infrastructure (e.g., IP ranges, domains) with web service access logs.",
            "Look for indicators of account takeover (e.g., changed recovery emails, suspicious login attempts)."
        ],
        "apt": [],  # No specific APT groups listed
        "spl_query": [
            "index=proxy OR index=cloud \n| stats count by src_ip, dest_ip, http_user_agent"
        ],
        "hunt_steps": [
            "Identify web service accounts with abnormal activity or new forwarding rules (in case of email).",
            "Cross-reference login events with threat intelligence for known malicious IPs or user agents.",
            "Check for unexpected OAuth token grants or API keys associated with compromised accounts."
        ],
        "expected_outcomes": [
            "Detection of compromised web service accounts used for malicious purposes.",
            "Identification of suspicious login patterns, file sharing, or command and control traffic."
        ],
        "false_positive": (
            "Legitimate user behavior, such as new integrations or travel-related login changes, can appear "
            "suspicious. Validate with business context and user confirmations."
        ),
        "clearing_steps": [
            "Reset credentials and enable MFA on compromised web service accounts.",
            "Revoke unauthorized API keys or OAuth tokens.",
            "Monitor and audit user activities post-incident to ensure no residual malicious access."
        ],
        "mitre_mapping": [
            {
                "tactic": "Resource Development",
                "technique": "Exfiltration Over Web Service (T1567)",
                "example": "After compromising a web service, adversaries may exfiltrate data via the same service."
            }
        ],
        "watchlist": [
            "Accounts exhibiting sudden spikes in data transfers or login frequency.",
            "API tokens with abnormal permissions or usage patterns.",
            "Emails or messages originating from legitimate domains but containing malicious links."
        ],
        "enhancements": [
            "Automate alerts for suspicious account activity and login anomalies.",
            "Use web service logs and SIEM correlation to detect patterns of malicious usage.",
            "Employ continuous user behavior analytics (UBA) to flag deviations from normal activity."
        ],
        "summary": (
            "Compromising web services enables adversaries to hide in trusted, high-traffic environments, "
            "leveraging stolen or hijacked accounts to blend malicious activity with legitimate usage. "
            "This approach complicates attribution and detection efforts."
        ),
        "remediation": (
            "Enforce strong access controls and MFA on all web service accounts, regularly review permissions "
            "and API keys, and monitor for unauthorized usage or suspicious login behaviors."
        ),
        "improvements": (
            "Integrate threat intelligence for known malicious web service accounts, adopt zero-trust principles "
            "for external services, and maintain continuous auditing of cloud and web service activities."
        )
    }
