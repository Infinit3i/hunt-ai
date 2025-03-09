def get_content():
    return {
        "id": "T1573",
        "url_id": "T1573",
        "title": "Encrypted Channel",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS), SSL/TLS Inspection Logs",
        "protocol": "TLS, SSH, VPN, Custom Encryption Protocols",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using encrypted communication channels to establish command-and-control (C2) connections and evade network detection.",
        "scope": "Identify encrypted traffic patterns, custom encryption implementations, and unusual secure communication methods used for C2.",
        "threat_model": "Adversaries encrypt C2 communications using TLS, SSH, or custom encryption to bypass security controls and evade detection.",
        "hypothesis": [
            "Are there unusual encrypted sessions with non-standard protocols?",
            "Is adversary traffic using encryption to bypass network security tools?",
            "Are adversaries implementing custom encryption schemes to evade detection?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"},
            {"type": "SSL/TLS Inspection Logs", "source": "TLS Interception Appliances, Web Proxies"}
        ],
        "detection_methods": [
            "Monitor for unusual TLS, SSH, or VPN traffic patterns.",
            "Detect encrypted connections to known C2 infrastructure.",
            "Identify usage of non-standard cryptographic protocols or excessive encryption within traffic."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*tls* OR protocol=*ssh* OR protocol=*vpn* \n| stats count by src_ip, dest_ip, protocol"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify encrypted traffic related to C2 communications.",
            "Analyze SSL/TLS Metadata: Inspect certificates and handshake anomalies.",
            "Monitor for Non-Standard Encryption: Detect adversaries implementing custom encryption schemes.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques using encrypted channels.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Encrypted C2 Detected: Block malicious encrypted traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for encrypted command-and-control techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1573 (Encrypted Channel)", "example": "C2 traffic encrypted via TLS tunneling."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated through encrypted SSH tunnels."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after encrypted communication."}
        ],
        "watchlist": [
            "Flag encrypted traffic to suspicious or unknown destinations.",
            "Monitor for unusual certificate usage in TLS communications.",
            "Detect anomalies in encrypted traffic behavior that do not match expected patterns."
        ],
        "enhancements": [
            "Deploy TLS inspection to analyze encrypted traffic contents.",
            "Implement behavioral analytics to detect abnormal encryption use.",
            "Improve correlation between encrypted traffic and known threat actor techniques."
        ],
        "summary": "Document detected malicious encrypted command-and-control activity and affected systems.",
        "remediation": "Block unauthorized encrypted communications, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of encrypted channel-based command-and-control techniques."
    }
