def get_content():
    return {
        "id": "T1571",
        "url_id": "T1571",
        "title": "Non-Standard Port",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS)",
        "protocol": "TCP, UDP, Custom Protocols",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using non-standard ports for command-and-control (C2) communications to evade detection.",
        "scope": "Identify unusual network traffic patterns utilizing non-standard ports for C2 activity.",
        "threat_model": "Adversaries use non-standard ports to bypass security controls and blend malicious traffic with legitimate network activities.",
        "hypothesis": [
            "Are there unexpected outbound connections using uncommon ports?",
            "Are adversaries utilizing non-standard ports to evade detection?",
            "Is there a pattern of C2 communications on non-default protocol ports?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"}
        ],
        "detection_methods": [
            "Monitor for outbound network traffic on uncommon ports.",
            "Detect protocol mismatches where application traffic does not match expected port behavior.",
            "Identify C2 traffic using dynamically assigned or custom ports."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search port!=80 AND port!=443 AND port!=22 AND port!=53 \n| stats count by src_ip, dest_ip, port"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify traffic on non-standard ports.",
            "Analyze Protocol Mismatches: Detect anomalies between expected and observed network behavior.",
            "Monitor for Dynamic Port Usage: Identify patterns in C2 traffic across varying ports.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques utilizing non-standard ports.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Non-Standard Port C2 Detected: Block malicious traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for non-standard port usage in C2."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1571 (Non-Standard Port)", "example": "C2 traffic using TCP port 8443 instead of 443."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated through UDP port 2222."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs containing non-standard port usage."}
        ],
        "watchlist": [
            "Flag outbound connections using uncommon ports.",
            "Monitor for anomalies in port usage trends.",
            "Detect unauthorized applications using non-standard ports for communication."
        ],
        "enhancements": [
            "Deploy network segmentation to restrict non-standard port usage.",
            "Implement deep packet inspection to analyze traffic on uncommon ports.",
            "Improve correlation between non-standard ports and known threat actor techniques."
        ],
        "summary": "Document detected malicious command-and-control activity leveraging non-standard ports.",
        "remediation": "Block unauthorized non-standard port communications, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of non-standard port-based command-and-control techniques."
    }
