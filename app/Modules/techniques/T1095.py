def get_content():
    return {
        "id": "T1095",
        "url_id": "T1095",
        "title": "Non-Application Layer Protocol",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS)",
        "protocol": "ICMP, UDP, GRE, ESP",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using non-application layer protocols to communicate with compromised systems and bypass detection.",
        "scope": "Identify suspicious usage of non-application layer protocols indicating command-and-control (C2) activity.",
        "threat_model": "Adversaries use non-application layer protocols such as ICMP and UDP to establish covert communication channels.",
        "hypothesis": [
            "Are there unusual ICMP or UDP communications between internal and external hosts?",
            "Are adversaries leveraging encapsulated protocols to bypass network inspection?",
            "Are large data packets being sent via non-standard protocols?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"}
        ],
        "detection_methods": [
            "Monitor for unusual ICMP or UDP connections between internal and external hosts.",
            "Detect excessive non-standard protocol usage over the network.",
            "Identify encapsulated malicious payloads within non-application layer protocols."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*icmp* OR protocol=*udp* OR protocol=*gre* \n| stats count by src_ip, dest_ip, protocol"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify suspicious non-application layer protocol communications.",
            "Analyze Packet Payloads: Detect anomalies in protocol behavior.",
            "Monitor for Encapsulation: Identify malicious usage of non-application protocols.",
            "Correlate with Threat Intelligence: Identify known techniques using non-standard protocols.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Non-Application Layer Protocol C2 Detected: Block malicious traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for non-application protocol-based C2 obfuscation."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1095 (Non-Application Layer Protocol)", "example": "C2 traffic hidden within ICMP packets."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Sensitive data exfiltrated through UDP packets."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after using ICMP for communication."}
        ],
        "watchlist": [
            "Flag outbound ICMP/UDP traffic to unusual destinations.",
            "Monitor for anomalies in non-application layer protocol usage.",
            "Detect unauthorized encapsulation of payloads in ICMP or UDP packets."
        ],
        "enhancements": [
            "Deploy deep packet inspection to analyze ICMP and UDP traffic.",
            "Implement anomaly detection to monitor non-application protocol misuse.",
            "Improve correlation between non-standard protocol usage and known threats."
        ],
        "summary": "Document detected malicious non-application layer protocol command-and-control activity and affected systems.",
        "remediation": "Block unauthorized ICMP and UDP communications, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of non-application layer protocol-based command-and-control techniques."
    }
