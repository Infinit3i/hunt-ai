def get_content():
    return {
        "id": "T1090.003",
        "url_id": "T1090/003",
        "title": "Proxy: Multi-Hop Proxy",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS), VPN Logs",
        "protocol": "SOCKS, HTTP, HTTPS, SSH, Custom Proxy Protocols",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using multi-hop proxies to route command-and-control (C2) traffic through multiple intermediary nodes, making detection and attribution more difficult.",
        "scope": "Identify network traffic patterns indicative of multi-hop proxy usage for C2 communications.",
        "threat_model": "Adversaries leverage multi-hop proxies, including chained VPNs, Tor, or compromised systems, to relay C2 traffic through multiple nodes, obfuscating their origin.",
        "hypothesis": [
            "Are there unexpected multi-hop proxy connections observed in network traffic?",
            "Are adversaries chaining multiple proxies to obfuscate communications?",
            "Is there an unusual pattern of encrypted or proxied traffic hopping between multiple hosts?"
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
            "Monitor for excessive or anomalous multi-hop proxy traffic.",
            "Detect patterns indicative of proxy chaining or repeated relay routing.",
            "Identify frequent access to known multi-hop proxy services, Tor nodes, or cascading VPNs."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*socks* OR protocol=*http* OR protocol=*https* \n| stats count by src_ip, dest_ip, protocol"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify multi-hop proxy-related network traffic.",
            "Analyze Proxy Logs: Detect anomalies in proxy relay patterns.",
            "Monitor for Multi-Hop Routing: Identify traffic relayed through multiple intermediary nodes.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques leveraging multi-hop proxies.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Multi-Hop Proxy-Based C2 Detected: Block malicious proxy traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for multi-hop proxy-based C2 techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1090.003 (Multi-Hop Proxy)", "example": "C2 traffic relayed through multiple intermediary proxy nodes."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated through a chain of VPN connections."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after using a multi-hop proxy service."}
        ],
        "watchlist": [
            "Flag traffic associated with known multi-hop proxy services, Tor exit nodes, or chained VPNs.",
            "Monitor for anomalies in proxy authentication and relay patterns.",
            "Detect unauthorized use of multi-hop proxies within enterprise networks."
        ],
        "enhancements": [
            "Deploy deep packet inspection to analyze multi-hop proxied traffic.",
            "Implement behavioral analytics to detect proxy chaining misuse.",
            "Improve correlation between proxy activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious multi-hop proxy-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized multi-hop proxy traffic, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of multi-hop proxy-based command-and-control techniques."
    }
