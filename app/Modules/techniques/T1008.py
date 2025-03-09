def get_content():
    return {
        "id": "T1008",
        "url_id": "T1008",
        "title": "Fallback Channels",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS)",
        "protocol": "HTTP, HTTPS, DNS, ICMP, Custom C2 Protocols",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using fallback channels to maintain command-and-control (C2) communications when primary channels are blocked or disrupted.",
        "scope": "Identify network traffic patterns indicative of fallback C2 channels being activated.",
        "threat_model": "Adversaries establish multiple C2 communication paths and dynamically switch to alternative channels when primary ones are interrupted.",
        "hypothesis": [
            "Are there sudden shifts in C2 communication channels after security controls are enforced?",
            "Are adversaries utilizing multiple redundant C2 paths to maintain persistence?",
            "Is there an increase in alternative protocol usage (e.g., DNS or ICMP) following disruptions to primary C2 channels?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
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