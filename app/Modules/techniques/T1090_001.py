def get_content():
    return {
        "id": "T1090.001",
        "url_id": "T1090/001",
        "title": "Proxy: Internal Proxy",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS), VPN Logs",
        "protocol": "SOCKS, HTTP, HTTPS, SSH, Custom Proxy Protocols",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using internal proxies to route command-and-control (C2) traffic through compromised internal systems and evade detection.",
        "scope": "Identify network traffic patterns indicative of internal proxy usage for C2 communications.",
        "threat_model": "Adversaries set up internal proxies within a compromised network to relay C2 traffic through multiple hosts, making detection and attribution more difficult.",
        "hypothesis": [
            "Are there unexpected internal proxy connections observed in network traffic?",
            "Are adversaries leveraging internal proxies to obfuscate communications?",
            "Is there lateral movement using proxy connections within the environment?"
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
            "Monitor for excessive or anomalous internal proxy traffic.",
            "Detect patterns indicative of internal proxy chaining or lateral movement.",
            "Identify frequent proxy authentication requests from unexpected hosts."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*socks* OR protocol=*http* OR protocol=*https* \n| stats count by src_ip, dest_ip, protocol"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify internal proxy-related network traffic.",
            "Analyze Proxy Logs: Detect anomalies in internal proxy access patterns.",
            "Monitor for Multi-Hop Routing: Identify traffic relayed through multiple internal intermediary nodes.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques leveraging internal proxies.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Internal Proxy-Based C2 Detected: Block malicious internal proxy traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for internal proxy-based C2 techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1090.001 (Internal Proxy)", "example": "C2 traffic relayed through an internal proxy within a compromised network."},
            {"tactic": "Lateral Movement", "technique": "T1570 (Lateral Tool Transfer)", "example": "Adversary moving laterally via internal proxy connections."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after using internal proxy services."}
        ],
        "watchlist": [
            "Flag traffic associated with unexpected internal proxy services.",
            "Monitor for anomalies in internal proxy authentication and usage patterns.",
            "Detect unauthorized internal proxy usage within enterprise networks."
        ],
        "enhancements": [
            "Deploy deep packet inspection to analyze internal proxied traffic.",
            "Implement behavioral analytics to detect proxy misuse within corporate environments.",
            "Improve correlation between internal proxy activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious internal proxy-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized internal proxy traffic, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of internal proxy-based command-and-control techniques."
    }
