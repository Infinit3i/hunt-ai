def get_content():
    return {
        "id": "T1008",
        "url_id": "T1008",
        "title": "Fallback Channels",
        "tactic": "Command and Control",
        "data_sources": "Zeek, Suricata, Firewall, Proxy, Endpoint Logs, Intrusion Detection Systems (IDS)",
        "protocol": "HTTP, HTTPS, DNS, ICMP, Custom C2 Protocols",
        "os": "Platform Agnostic",
        "tips": [],
        "description": "Adversaries may use fallback channels if primary communication methods are disrupted or discovered. Fallback channels are alternate communication paths that are used if the primary channel is compromised or inaccessible. Adversaries may use fallback channels to ensure they maintain access to compromised systems.",
        "log_sources": [
            {"type": "Zeek"},
            {"type": "Suricata"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"}
        ],
        "detection_methods": [
            "Monitor for sudden protocol shifts in ongoing C2 communications.",
            "Detect backup C2 channels being activated following security changes.",
            "Identify fallback mechanisms that use uncommon or stealthy protocols."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*dns* OR protocol=*icmp* OR protocol=*http* \n| stats count by src_ip, dest_ip, protocol"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify fallback C2-related network traffic.",
            "Analyze Protocol Shifts: Detect anomalies where adversaries switch communication methods.",
            "Monitor for Unusual C2 Behavior: Identify backup communication paths activating.",
            "Correlate with Threat Intelligence: Compare with known C2 fallback techniques.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Fallback Channel-Based C2 Detected: Block malicious C2 traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for fallback channel-based C2 techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1008 (Fallback Channels)", "example": "Adversaries switching from HTTPS to DNS tunneling after network security blocks primary C2."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated using a secondary protocol like ICMP."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after switching to a fallback C2 channel."}
        ],
        "watchlist": [
            "Flag sudden changes in outbound C2 traffic to alternative protocols.",
            "Monitor for anomalies in fallback communication behavior.",
            "Detect unauthorized use of backup C2 channels within corporate environments."
        ],
        "enhancements": [
            "Deploy anomaly detection to analyze fallback C2 attempts.",
            "Implement behavioral analytics to detect sudden shifts in adversary communication methods.",
            "Improve correlation between fallback C2 activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious fallback channel-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized fallback C2 traffic, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of fallback channel-based command-and-control techniques."
    }