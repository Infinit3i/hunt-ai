def get_content():
    return {
        "id": "T1566.002",
        "url_id": "1566/002",
        "title": "Phishing: Spearphishing Link",
        "tactic": "Initial Access",
        "tags": ["Spearphishing", "Social Engineering", "Email Attack"],
        "data_sources": "Email Gateway, Web Proxy Logs, Endpoint Monitoring, DNS Logs",
        "protocol": "HTTP, HTTPS",
        "os": "Windows, Linux, macOS",
        "objective": "Detect and mitigate spearphishing attempts that deliver malicious links to compromise a target system.",
        "scope": "Monitor for suspicious email links, unusual domain requests, and unauthorized script executions.",
        "threat_model": "Adversaries send highly targeted phishing emails containing malicious links that, when clicked, lead to credential theft, malware downloads, or further exploitation.",
        "hypothesis": [
            "Are there emails containing suspicious or obfuscated URLs?",
            "Are users clicking on links leading to known malicious domains?",
            "Is there an increase in endpoint connections to newly registered or low-reputation domains?"
        ],
        "tips": [
            "Train users to recognize phishing attempts and suspicious links.",
            "Implement URL rewriting and sandboxing to analyze link destinations.",
            "Monitor for rapid clicks on email links, which may indicate automated execution."
        ],
        "log_sources": [
            {"type": "Email Logs", "source": "Email Gateway", "destination": "Recipient Inbox"},
            {"type": "Web Logs", "source": "Web Proxy", "destination": "External Websites"},
            {"type": "DNS Logs", "source": "Domain Lookups", "destination": "Suspicious Domains"}
        ],
        "source_artifacts": [
            {"type": "Email", "location": "User Inbox", "identify": "Suspicious senders, unusual domains"},
            {"type": "Browser History", "location": "User's Browser", "identify": "Visits to phishing domains"}
        ],
        "destination_artifacts": [
            {"type": "Malware Payload", "location": "Endpoint", "identify": "Downloaded via phishing link"},
            {"type": "Credential Theft", "location": "Phishing Website", "identify": "Captured user credentials"}
        ],
        "detection_methods": [
            "Detect URLs using reputation-based analysis and threat intelligence.",
            "Monitor for anomalous user behavior when interacting with email links.",
            "Identify users visiting newly registered domains or known phishing sites."
        ],
        "apt": ["APT28 (Fancy Bear)", "APT29 (Cozy Bear)", "FIN7"],
        "spl_query": [
            "index=email sourcetype=mail_logs url=* | search suspicious_domains",
            "index=web sourcetype=proxy_logs url=* | eval domain=lower(domain) | search domain IN (malicious_domain_list)"
        ],
        "hunt_steps": [
            "Analyze email metadata for signs of impersonation or spoofing.",
            "Check if users clicked on suspicious links and accessed malicious domains.",
            "Investigate endpoint logs for execution of downloaded payloads.",
            "Correlate user activity across web and email logs for abnormal patterns."
        ],
        "expected_outcomes": [
            "Phishing Attack Detected: Alert security teams and block further emails from the sender.",
            "No Malicious Activity Found: Continue monitoring and refining detection rules."
        ],
        "false_positive": "Legitimate business emails containing external links that may appear suspicious but are not actually malicious.",
        "clearing_steps": [
            "Blacklist malicious domains in web filters and email gateways.",
            "Reset credentials for affected users if credential theft is suspected.",
            "Re-image endpoints if malware execution is confirmed."
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566.001 (Spearphishing Attachment)", "example": "Similar phishing tactic using email attachments."},
            {"tactic": "Execution", "technique": "T1204.001 (Malicious Link Execution)", "example": "User clicks malicious link leading to malware execution."},
            {"tactic": "Credential Access", "technique": "T1110.003 (Password Spraying)", "example": "Harvested credentials used for further attacks."}
        ],
        "watchlist": [
            "Monitor new or unusual domains accessed from corporate devices.",
            "Flag email links leading to known phishing sites or newly registered domains.",
            "Identify users clicking on links at unusual times or in bulk."
        ],
        "enhancements": [
            "Deploy multi-factor authentication (MFA) to mitigate credential theft.",
            "Improve user awareness training for recognizing phishing attempts.",
            "Implement sandboxing and email filtering to analyze suspicious links."
        ],
        "summary": "Spearphishing links are highly targeted email attacks designed to trick users into clicking malicious links that can lead to credential theft or malware infections.",
        "remediation": "Block phishing domains, enforce MFA, and train users to recognize suspicious emails.",
        "improvements": "Enhance email security filters and integrate threat intelligence feeds to detect new phishing campaigns."
    }
