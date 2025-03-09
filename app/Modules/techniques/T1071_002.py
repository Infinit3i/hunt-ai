def get_content():
    return {
        "id": "T1071.002",
        "url_id": "T1071/002",
        "title": "Application Layer Protocol: File Transfer Protocols",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS)",
        "protocol": "FTP, SFTP, SCP",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using file transfer protocols (FTP/SFTP/SCP) to communicate with compromised systems and exfiltrate data.",
        "scope": "Identify suspicious usage of file transfer protocols indicating command-and-control (C2) activity.",
        "threat_model": "Adversaries leverage file transfer protocols to move data, execute commands, and bypass security controls.",
        "hypothesis": [
            "Are there abnormal FTP/SFTP/SCP connections to uncommon or unknown external hosts?",
            "Are adversaries using encrypted file transfers to evade detection?",
            "Are large volumes of data being transferred unexpectedly?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"}
        ],
        "detection_methods": [
            "Monitor for unusual FTP/SFTP/SCP connections to external servers.",
            "Detect unauthorized file transfers from critical assets.",
            "Identify abnormal authentication patterns related to file transfer protocols."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*ftp* OR protocol=*sftp* OR protocol=*scp* \n| stats count by src_ip, dest_ip, file_name"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify unusual file transfer activity.",
            "Analyze Network Anomalies: Detect unauthorized file movements.",
            "Monitor for Suspicious Authentication: Investigate unusual credential use with FTP/SFTP/SCP.",
            "Correlate with Threat Intelligence: Identify known malicious file transfer behaviors.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Malicious File Transfer Detected: Block and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for protocol-based data exfiltration."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1071.002 (File Transfer Protocols)", "example": "Malware using FTP for C2 communications."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Sensitive data exfiltrated via SFTP."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware clearing FTP logs after data transfer."}
        ],
        "watchlist": [
            "Flag outbound FTP/SFTP/SCP connections to unknown destinations.",
            "Monitor for anomalies in file transfer behavior.",
            "Detect unauthorized credential use for file transfers."
        ],
        "enhancements": [
            "Deploy deep packet inspection to analyze FTP/SFTP/SCP traffic.",
            "Implement behavioral analytics to detect abnormal file transfers.",
            "Improve correlation between file transfer activity and known threats."
        ],
        "summary": "Document detected malicious file transfer activity and affected systems.",
        "remediation": "Block unauthorized file transfers, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of file transfer protocol abuse."
    }
