def get_content():
    return {
        "id": "T1071.003",
        "url_id": "T1071/003",
        "title": "Application Layer Protocol: Mail Protocols",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Email Logs, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS)",
        "protocol": "SMTP, IMAP, POP3",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using mail protocols (SMTP, IMAP, POP3) to communicate with compromised systems and exfiltrate data.",
        "scope": "Identify suspicious email-based communications indicating command-and-control (C2) activity.",
        "threat_model": "Adversaries leverage email protocols to send encoded commands, exfiltrate data, and avoid detection.",
        "hypothesis": [
            "Are there unusual outbound SMTP/IMAP/POP3 connections from internal systems?",
            "Are adversaries using encoded email messages for C2 communication?",
            "Are large email attachments being sent to unknown or suspicious domains?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Email Logs", "source": "Microsoft Exchange, Google Workspace, Proofpoint"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"}
        ],
        "detection_methods": [
            "Monitor for unusual outbound email connections to external servers.",
            "Detect unauthorized email attachments containing encoded payloads.",
            "Identify suspicious SMTP relay activity from non-email servers."
        ],
        "spl_query": [
            "index=network sourcetype=email_logs \n| search protocol=*smtp* OR protocol=*imap* OR protocol=*pop3* \n| stats count by src_ip, dest_ip, subject"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify suspicious email-based communications.",
            "Analyze Email Headers: Detect anomalies in sender and recipient details.",
            "Monitor for Unusual Attachments: Identify large or encoded email attachments.",
            "Correlate with Threat Intelligence: Identify known malicious email-based behaviors.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Mail-Based C2 Detected: Block malicious email traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for email protocol-based C2 obfuscation."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1071.003 (Mail Protocols)", "example": "C2 traffic hidden in SMTP email messages."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Sensitive data exfiltrated via email attachments."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting sent emails after C2 communication."}
        ],
        "watchlist": [
            "Flag outbound SMTP/IMAP/POP3 connections to suspicious domains.",
            "Monitor for anomalies in email subject lines and attachments.",
            "Detect unauthorized use of email relays from non-mail servers."
        ],
        "enhancements": [
            "Deploy email content inspection tools to analyze suspicious messages.",
            "Implement behavioral analytics to detect abnormal email activity.",
            "Improve correlation between email traffic and known threat actor techniques."
        ],
        "summary": "Document detected malicious email-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized email communications, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of mail protocol-based command-and-control techniques."
    }
