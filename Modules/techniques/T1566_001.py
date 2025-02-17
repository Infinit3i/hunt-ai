def get_content():
    return {
        "id": "T1566.001",
        "url_id": "T1566/001",
        "title": "Phishing: Spear Phishing Attachment",
        "tactic": "Initial Access",
        "data_sources": "Email, Web Proxy, Endpoint",
        "protocol": "SMTP, HTTP/HTTPS",
        "os": "Platform Agnostic",
        "objective": "Identify and mitigate phishing attempts involving malicious attachments.",
        "scope": "Detect phishing emails using email metadata, web proxy logs, and endpoint interactions.",
        "threat_model": "Adversaries may use malicious attachments in spear phishing campaigns to compromise users.",
        "hypothesis": [
            "How are attachments being delivered?",
            "Are certain senders sending multiple suspicious emails?",
            "Are recipients interacting with suspicious attachments?"
        ],
        "log_sources": [
            {"type": "Email Metadata", "source": "Microsoft 365, Google Workspace, Exchange, Proofpoint, Splunk Email Logs"},
            {"type": "Web Proxy Logs", "source": "Bluecoat, Zscaler, Netskope, Cisco Umbrella"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 1, 3, 11), EDR (CrowdStrike, Defender ATP)"},
            {"type": "Mail Protocol Logs", "source": "SMTP, IMAP, POP3"},
            {"type": "Threat Intelligence Feeds", "source": "VirusTotal, Hybrid Analysis, MISP"}
        ],
        "detection_methods": [
            "Analyze sender, recipient, subject, and attachments.",
            "Examine email protocols and endpoint interactions.",
            "Query attachments (e.g., attach_filename=*) for anomalies.",
            "Identify common senders, trends, and suspicious domains."
        ],
        "spl_query": "index=email sourcetype=\"email\" attach_filename=* | stats count by sender, subject, recipient | sort - count",
        "sigma_rule": "https://grep.app/search?f.repo=SigmaHQ%2Fsigma&q=T1566.001",
        "hunt_steps": [
            "Run Queries in SIEM: Extract attachment file names and senders. Correlate with web traffic and endpoint logs.",
            "Investigate Attachments: Check attachment hashes in VirusTotal, Hybrid Analysis, and MISP. Identify recent file downloads from suspicious emails.",
            "Monitor Suspicious Senders & Domains: Flag repeat offenders and analyze email behavior. Cross-reference against known phishing domains.",
            "Look for Execution on Endpoints: Check Sysmon Event ID 1 (Process Creation) for attachment execution. Review PowerShell, VBA Macros, WScript executions.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response. If no malicious activity is found → Refine detections and automate."
        ],
        "expected_outcomes": [
            "Phishing Activity Detected: Block sender domain/IPs. Alert SOC team and conduct forensic email analysis.",
            "No Malicious Activity Found: Improve detection with machine learning analytics on email trends. Enhance security awareness training based on findings."
        ],
        "mitre_mapping": [
            {"tactic": "Initial Access", "technique": "T1566.001 (Spear Phishing Attachment)", "example": "Malicious email with attachment"},
            {"tactic": "Execution", "technique": "T1204.002 (User Execution - Malicious File)", "example": "User opens infected attachment"},
            {"tactic": "Credential Access", "technique": "T1555.003 (Credential Dumping via Phishing)", "example": "Email redirects user to fake login"}
        ],
        "watchlist": [
            "Flag suspicious domains and sender IPs.",
            "Automate attachment hash analysis in VirusTotal & MISP.",
            "Develop behavioral analytics to detect mass email attacks."
        ],
        "enhancements": [
            "Implement DMARC, SPF, and DKIM email protections.",
            "Enable attachment sandboxing for unknown file types.",
            "Strengthen user awareness training for phishing tactics."
        ],
        "summary": "Document flagged phishing attempts.",
        "remediation": "Block senders, revoke compromised credentials, improve detection.",
        "improvements": "Enhance automated phishing detection and response."
    }
