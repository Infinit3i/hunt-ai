def get_content():
    return {
        "id": "T1205.001",
        "url_id": "T1205/001",
        "title": "Traffic Signaling: Port Knocking",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS)",
        "protocol": "TCP, UDP, ICMP, Custom Signaling Mechanisms",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using port knocking techniques to establish command-and-control (C2) communications while evading detection.",
        "scope": "Identify network traffic patterns indicative of adversaries leveraging port knocking techniques for C2 establishment.",
        "threat_model": "Adversaries use port knocking by sending a sequence of connection attempts to closed ports to trigger the opening of a communication channel, bypassing security controls.",
        "hypothesis": [
            "Are there repeated connection attempts to closed ports in a distinct sequence?",
            "Are adversaries leveraging custom packet sequences for covert signaling?",
            "Is there an increase in connection attempts to ports that are typically closed?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"}
        ],
        "detection_methods": [
            "Monitor for repeated connection attempts to closed ports in short time intervals.",
            "Detect unusual patterns of port access not associated with legitimate services.",
            "Identify sequences of failed connection attempts that lead to a successful connection."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search action=blocked \n| transaction src_ip maxspan=10s maxevents=5 \n| stats count by src_ip, dest_ip, dest_port"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify port knocking sequences within firewall logs.",
            "Analyze Network Connection Attempts: Detect rapid sequences of failed connections leading to successful access.",
            "Monitor for Covert Signaling: Identify unexpected traffic patterns that do not match legitimate service behavior.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques leveraging port knocking.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Port Knocking-Based C2 Detected: Block malicious port knocking sequences and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for port knocking-based C2 techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1205.001 (Port Knocking)", "example": "C2 traffic using a predefined sequence of failed connections to activate a backdoor."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after using port knocking for C2 establishment."}
        ],
        "watchlist": [
            "Flag repeated connection attempts to closed ports within a short time window.",
            "Monitor for anomalies in port access patterns that differ from legitimate service behavior.",
            "Detect unauthorized use of port knocking mechanisms within corporate environments."
        ],
        "enhancements": [
            "Deploy anomaly-based detection to analyze unusual connection attempts.",
            "Implement behavioral analytics to detect port knocking activity.",
            "Improve correlation between port knocking attempts and known threat actor techniques."
        ],
        "summary": "Document detected malicious port knocking-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized port knocking sequences, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of port knocking-based command-and-control techniques."
    }
