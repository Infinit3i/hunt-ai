def get_content():
    return {
        "id": "T1090.004",
        "url_id": "T1090/004",
        "title": "Proxy: Domain Fronting",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS), TLS Inspection Logs",
        "protocol": "HTTPS, TLS, Custom Proxy Protocols",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using domain fronting to disguise command-and-control (C2) traffic by leveraging high-reputation Content Delivery Networks (CDNs) or cloud providers.",
        "scope": "Identify network traffic patterns indicative of domain fronting for C2 communications.",
        "threat_model": "Adversaries exploit domain fronting techniques to bypass security controls, making C2 traffic appear as legitimate communication with cloud services.",
        "hypothesis": [
            "Are there unexpected HTTPS connections to high-reputation CDNs with unusual Host headers?",
            "Are adversaries leveraging domain fronting to obfuscate C2 traffic?",
            "Is there an increase in encrypted outbound traffic to known domain fronting endpoints?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"},
            {"type": "TLS Inspection Logs", "source": "TLS Interception Appliances, Web Proxies"}
        ],
        "detection_methods": [
            "Monitor for HTTPS traffic with mismatched SNI and Host headers.",
            "Detect anomalous outbound traffic to cloud infrastructure with unusual headers.",
            "Identify domain fronting techniques used to obfuscate C2 communication."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*https* \n| where sni!=host_header \n| stats count by src_ip, dest_ip, sni, host_header"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify domain fronting-related HTTPS traffic.",
            "Analyze TLS Metadata: Detect anomalies in SNI and Host header mismatches.",
            "Monitor for Unusual CDN Access: Identify high-frequency HTTPS requests to cloud services.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques leveraging domain fronting.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Domain Fronting-Based C2 Detected: Block malicious HTTPS traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for domain fronting-based C2 techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1090.004 (Domain Fronting)", "example": "C2 traffic routed through a CDN to disguise communications."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated using domain fronting techniques."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after using domain fronting."}
        ],
        "watchlist": [
            "Flag HTTPS traffic where the SNI and Host headers do not match.",
            "Monitor for excessive outbound connections to cloud/CDN infrastructure.",
            "Detect unauthorized domain fronting within corporate environments."
        ],
        "enhancements": [
            "Deploy TLS inspection to analyze domain fronting attempts.",
            "Implement behavioral analytics to detect domain fronting misuse.",
            "Improve correlation between HTTPS traffic and known threat actor techniques."
        ],
        "summary": "Document detected malicious domain fronting-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized domain fronting traffic, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of domain fronting-based command-and-control techniques."
    }
