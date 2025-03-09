def get_content():
    return {
        "id": "T1572",
        "url_id": "T1572",
        "title": "Protocol Tunneling",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS), VPN Logs",
        "protocol": "ICMP, HTTP, HTTPS, DNS, SSH, Custom Tunneling Protocols",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using protocol tunneling to encapsulate command-and-control (C2) traffic within legitimate protocols and evade detection.",
        "scope": "Identify network traffic patterns indicative of protocol tunneling and covert communications.",
        "threat_model": "Adversaries encapsulate C2 traffic within legitimate protocols (e.g., HTTP, DNS, ICMP) to bypass security controls and avoid detection.",
        "hypothesis": [
            "Are there unexpected protocol tunnels observed in network traffic?",
            "Are adversaries leveraging DNS or ICMP tunneling for covert communications?",
            "Is there an unusual amount of encapsulated traffic between hosts?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"},
            {"type": "VPN Logs", "source": "Corporate VPN Solutions, OpenVPN, WireGuard"}
        ],
        "detection_methods": [
            "Monitor for excessive or anomalous DNS, ICMP, or HTTP traffic.",
            "Detect protocol encapsulation mismatches in network traffic.",
            "Identify long-duration, low-bandwidth connections indicative of persistent tunnels."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*icmp* OR protocol=*dns* OR protocol=*http* \n| stats count by src_ip, dest_ip, protocol"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify potential protocol tunneling activity.",
            "Analyze Packet Payloads: Detect anomalies in encapsulated traffic.",
            "Monitor for Unusual Data Transfer: Identify large volumes of data hidden within legitimate protocols.",
            "Correlate with Threat Intelligence: Compare with known tunneling techniques used by adversaries.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Protocol Tunneling Detected: Block malicious tunneling traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for protocol tunneling techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1572 (Protocol Tunneling)", "example": "C2 traffic encapsulated within ICMP packets."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated using DNS tunneling."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after using protocol tunneling."}
        ],
        "watchlist": [
            "Flag high-frequency DNS requests to uncommon domains.",
            "Monitor for unexpected encapsulation of data in ICMP packets.",
            "Detect unauthorized VPN or tunneling activity in corporate environments."
        ],
        "enhancements": [
            "Deploy deep packet inspection to analyze encapsulated traffic.",
            "Implement behavioral analytics to detect protocol tunneling misuse.",
            "Improve correlation between tunneling activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious protocol tunneling command-and-control activity and affected systems.",
        "remediation": "Block unauthorized tunneling traffic, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of protocol tunneling-based command-and-control techniques."
    }
