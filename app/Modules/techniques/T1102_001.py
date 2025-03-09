def get_content():
    return {
        "id": "T1102.001",
        "url_id": "T1102/001",
        "title": "Web Service: Third-Party Social Media Services",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS), Cloud Logs",
        "protocol": "HTTP, HTTPS, API-Based Communications",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using third-party social media services to establish command-and-control (C2) communications and evade detection.",
        "scope": "Identify network traffic patterns indicative of adversaries leveraging social media platforms for C2.",
        "threat_model": "Adversaries abuse popular social media services such as Twitter, Facebook, and Telegram to send encoded C2 instructions, blend malicious traffic with legitimate activity, and avoid detection.",
        "hypothesis": [
            "Are there unauthorized interactions with social media APIs that could be indicative of C2 activity?",
            "Are adversaries leveraging public social media accounts to send encoded commands to compromised hosts?",
            "Is there an increase in API requests to social media services from non-standard user agents or unusual traffic patterns?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"},
            {"type": "Cloud Logs", "source": "AWS CloudTrail, Azure Monitor, Google Cloud Logging"}
        ],
        "detection_methods": [
            "Monitor for unusual API requests to social media platforms.",
            "Detect anomalous account activity such as frequent automated posts or interactions.",
            "Identify large volumes of outbound HTTP/HTTPS traffic directed at social media services."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*http* OR protocol=*https* \n| stats count by src_ip, dest_ip, uri"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify suspicious API traffic directed at social media services.",
            "Analyze Social Media API Calls: Detect anomalies in external social media service interactions.",
            "Monitor for Unusual Web Activity: Identify excessive data transfer to social media platforms.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques leveraging social media.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Social Media-Based C2 Detected: Block malicious social media traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for social media-based C2 techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1102.001 (Third-Party Social Media Services)", "example": "C2 traffic routed through Twitter DMs or Telegram messages."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated using encoded messages in public social media posts."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after using social media-based C2."}
        ],
        "watchlist": [
            "Flag outbound connections to known social media APIs for unusual access patterns.",
            "Monitor for anomalies in social media authentication and usage patterns.",
            "Detect unauthorized use of social media accounts for C2."
        ],
        "enhancements": [
            "Deploy deep packet inspection to analyze social media API traffic.",
            "Implement behavioral analytics to detect social media misuse.",
            "Improve correlation between social media activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious social media-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized social media traffic, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of social media-based command-and-control techniques."
    }
