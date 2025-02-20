def get_content():
    return {
        "id": "T1566.003",
        "url_id": "T1566/003",
        "title": "Phishing: Spearphishing via Service",
        "tags": ["Phishing", "Social Engineering", "Credential Theft"],
        "tactic": "Initial Access",
        "data_sources": "Email Gateway Logs, Web Proxy Logs, Network Traffic Analysis, Endpoint Detection Logs",
        "protocol": "SMTP, HTTP, HTTPS",
        "os": "Windows, macOS, Linux",
        "objective": "Detect and mitigate spearphishing attacks delivered via third-party services like social media, messaging platforms, or collaboration tools.",
        "scope": "Monitor inbound communications from untrusted or unusual services for potential phishing attempts.",
        "threat_model": "Adversaries use trusted third-party services to deliver phishing messages containing malicious links or attachments, bypassing traditional email security defenses.",
        "hypothesis": [
            "Are users receiving unexpected messages with embedded links from external collaboration services?",
            "Are there signs of malicious intent in messages received through third-party communication platforms?",
            "Have users reported suspicious messages with unusual login requests or file attachments?"
        ],
        "tips": [
            "Educate employees on recognizing phishing attempts from collaboration and messaging platforms.",
            "Monitor for unexpected authentication attempts following clicks on third-party links.",
            "Enable MFA for all users to reduce credential theft risks."
        ],
        "log_sources": [
            {"type": "Email Gateway", "source": "Inbound Message Analysis", "destination": "End-user Mailboxes"},
            {"type": "Web Proxy", "source": "URL Filtering Logs", "destination": "User Workstations"},
            {"type": "Network Traffic", "source": "DPI Analysis", "destination": "Internet Gateways"}
        ],
        "source_artifacts": [
            {"type": "Email Headers", "location": "Message Metadata", "identify": "Sender and Domain Verification"},
            {"type": "Link Analysis", "location": "Email Body & Attachments", "identify": "Embedded Malicious URLs"}
        ],
        "destination_artifacts": [
            {"type": "Network Requests", "location": "Browser Logs", "identify": "Connections to Phishing Domains"},
            {"type": "Credential Harvesting", "location": "User Submissions", "identify": "Stolen Login Data"}
        ],
        "detection_methods": [
            "Monitor for messages from untrusted collaboration platforms containing suspicious links.",
            "Analyze URL redirects leading to credential harvesting pages.",
            "Identify anomalous logins after users engage with third-party messages."
        ],
        "apt": ["APT28", "APT29", "FIN7", "Charming Kitten"],
        "spl_query": [
            "index=email_logs sender_domain!=company.com AND subject=*password* OR subject=*urgent*",
            "index=web_proxy_logs url=*login* AND referrer!=trusted_domains"
        ],
        "hunt_steps": [
            "Identify users who interacted with messages from untrusted collaboration tools.",
            "Analyze network logs for connections to newly registered or suspicious domains.",
            "Check for unusual authentication attempts after message interaction.",
            "Look for phishing sites impersonating legitimate services."
        ],
        "expected_outcomes": [
            "Suspicious Spearphishing Identified: Block the source and educate affected users.",
            "Credential Harvesting Detected: Reset credentials and investigate for further compromise."
        ],
        "false_positive": "Legitimate business interactions through third-party services may trigger detections.",
        "clearing_steps": [
            "Block the identified phishing domains and URLs at the gateway.",
            "Reset passwords for affected accounts and enforce MFA.",
            "Educate users on recognizing phishing attempts via messaging services."
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566 (Phishing)", "example": "Spearphishing through LinkedIn messages leading to credential theft."},
            {"tactic": "Credential Access", "technique": "T1110 (Brute Force)", "example": "Harvested credentials used for automated login attempts."},
            {"tactic": "Defense Evasion", "technique": "T1027 (Obfuscated Files or Information)", "example": "Attackers use shortened URLs or redirect chains to evade detection."}
        ],
        "watchlist": [
            "Monitor for new collaboration platforms being used in the organization.",
            "Detect login attempts from untrusted locations after message interaction.",
            "Alert on domains registered recently that match known phishing patterns."
        ],
        "enhancements": [
            "Deploy phishing-resistant MFA for all external authentication attempts.",
            "Use AI-based email filters to detect phishing attempts from untrusted sources.",
            "Implement automated sandboxing for analyzing URLs in incoming messages."
        ],
        "summary": "Spearphishing via service leverages trusted third-party platforms to deliver malicious messages, bypassing traditional email security.",
        "remediation": "Block phishing domains, enforce security awareness training, and require MFA for all users.",
        "improvements": "Integrate behavioral analytics to detect unusual communication patterns and phishing attempts."
    }
