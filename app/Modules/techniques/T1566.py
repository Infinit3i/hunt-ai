def get_content():
    return {
        "id": "T1566",
        "url_id": "T1566",
        "title": "Phishing",
        "tactic": "Initial Access",
        "tags": ["Social Engineering", "Email Attack", "Credential Theft"],
        "data_sources": "Email logs, Web proxy logs, Network traffic analysis, Endpoint monitoring",
        "protocol": "SMTP, HTTP, HTTPS",
        "os": "Windows, macOS, Linux",
        "objective": "Detect and mitigate phishing attempts aimed at credential theft, malware delivery, or social engineering attacks.",
        "scope": "Monitor email communications, web traffic, and endpoint behavior for indicators of phishing.",
        "threat_model": "Adversaries use phishing emails to trick users into revealing sensitive information, executing malicious payloads, or redirecting them to attacker-controlled websites.",
        "hypothesis": [
            "Are employees receiving emails with suspicious links or attachments?",
            "Are users entering credentials on non-approved websites?",
            "Are email attachments being opened and executing unauthorized scripts?"
        ],
        "tips": [
            "Implement DMARC, DKIM, and SPF to prevent spoofed emails.",
            "Educate employees on phishing tactics and encourage reporting of suspicious emails.",
            "Use email security solutions to block known malicious senders and attachments."
        ],
        "log_sources": [
            {"type": "Email Logs", "source": "Inbound email monitoring", "destination": "SIEM"},
            {"type": "Web Proxy Logs", "source": "URL filtering", "destination": "SIEM"},
            {"type": "Endpoint Monitoring", "source": "Behavioral analysis of email attachments", "destination": "EDR"}
        ],
        "source_artifacts": [
            {"type": "Email", "location": "Inbox and sent items", "identify": "Suspicious sender addresses, unexpected attachments"}
        ],
        "destination_artifacts": [
            {"type": "Endpoint", "location": "Downloads folder", "identify": "Suspicious files or scripts executed from attachments"}
        ],
        "detection_methods": [
            "Monitor for emails with executable attachments or macros.",
            "Detect credential harvesting attempts by monitoring domain categorization and URL reputation.",
            "Analyze user clicks on email links leading to suspicious domains."
        ],
        "apt": ["Lazarus Group", "APT29", "FIN7"],
        "spl_query": [
            "index=email_logs subject=*invoice* OR subject=*urgent* OR subject=*account update*",
            "index=web_proxy_logs url=*.*.*.* AND category!=known_safe"
        ],
        "hunt_steps": [
            "Identify emails flagged as phishing attempts based on suspicious indicators.",
            "Analyze email headers for signs of spoofing.",
            "Review web proxy logs for employees accessing phishing domains.",
            "Correlate attachment execution with endpoint alerts for potential payload delivery."
        ],
        "expected_outcomes": [
            "Phishing attempt detected: Block malicious sender and alert affected users.",
            "Credential harvesting attempt prevented: Reset credentials and investigate access logs.",
            "Malware execution identified: Isolate affected endpoints and analyze forensic data."
        ],
        "false_positive": "Legitimate business emails with similar subject lines may trigger alerts. Use sender reputation and user reports to refine detections.",
        "clearing_steps": [
            "Blacklist malicious email senders in security gateways.",
            "Perform endpoint scans for users who engaged with the phishing email.",
            "Reset credentials for users who entered passwords on untrusted sites."
        ],
        "mitre_mapping": [
            {"tactic": "Execution", "technique": "T1204 (User Execution)", "example": "User opens a phishing attachment leading to malware installation."},
            {"tactic": "Credential Access", "technique": "T1110 (Brute Force)", "example": "Harvested credentials used for further access attempts."},
            {"tactic": "Command and Control", "technique": "T1071.001 (Web Protocols)", "example": "Malware communicates with C2 via phishing payload."}
        ],
        "watchlist": [
            "Monitor new domains registered within the last 30 days in email links.",
            "Alert on emails containing known phishing keywords or urgent calls to action.",
            "Track repeated failed logins from external IP addresses."
        ],
        "enhancements": [
            "Implement multi-factor authentication to mitigate credential theft.",
            "Use AI-driven email security solutions for real-time phishing detection.",
            "Enforce browser-based security solutions to warn users about suspicious links."
        ],
        "summary": "Phishing remains one of the most effective attack vectors used by adversaries to steal credentials, distribute malware, or conduct social engineering campaigns.",
        "remediation": "Block phishing attempts using email security solutions, educate users, and enforce strong authentication mechanisms.",
        "improvements": "Enhance phishing detection by leveraging threat intelligence feeds and behavioral analytics."
    }
