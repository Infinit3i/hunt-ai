def get_content():
    return {
        "id": "T1090.002",
        "url_id": "T1090/002",
        "title": "Proxy: External Proxy",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS), VPN Logs",
        "protocol": "SOCKS, HTTP, HTTPS, SSH, Custom Proxy Protocols",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using external proxies to route command-and-control (C2) traffic through intermediary systems and evade detection.",
        "scope": "Identify network traffic patterns indicative of external proxy usage for C2 communications.",
        "threat_model": "Adversaries leverage external proxies, including commercial VPNs, Tor, or compromised systems, to relay C2 traffic and obscure their origin.",
        "hypothesis": [
            "Are there unexpected external proxy connections observed in network traffic?",
            "Are adversaries leveraging external proxies to obfuscate communications?",
            "Is there an unusual amount of encrypted or proxied traffic between hosts and external endpoints?"
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
            "Monitor for excessive or anomalous external proxy traffic.",
            "Detect patterns indicative of proxy chaining or multi-hop routing.",
            "Identify frequent access to known proxy services, Tor nodes, or VPNs."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*socks* OR protocol=*http* OR protocol=*https* \n| stats count by src_ip, dest_ip, protocol"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify external proxy-related network traffic.",
            "Analyze Proxy Logs: Detect anomalies in external proxy access patterns.",
            "Monitor for Multi-Hop Routing: Identify traffic relayed through multiple intermediary nodes.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques leveraging external proxies.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "External Proxy-Based C2 Detected: Block malicious proxy traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for external proxy-based C2 techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1090.002 (External Proxy)", "example": "C2 traffic relayed through an external proxy service or VPN."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated using a commercial VPN service."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after using external proxy services."}
        ],
        "watchlist": [
            "Flag traffic associated with known proxy services, Tor exit nodes, or commercial VPNs.",
            "Monitor for anomalies in external proxy authentication and usage patterns.",
            "Detect unauthorized external proxy usage within enterprise networks."
        ],
        "enhancements": [
            "Deploy deep packet inspection to analyze proxied traffic.",
            "Implement behavioral analytics to detect proxy misuse.",
            "Improve correlation between proxy activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious external proxy-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized proxy traffic, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of external proxy-based command-and-control techniques."
    }
