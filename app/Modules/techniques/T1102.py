def get_content():
    return {
        "id": "T1102",
        "url_id": "T1102",
        "title": "Web Service",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS), Cloud Logs",
        "protocol": "HTTP, HTTPS, Custom API Protocols",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using legitimate web services to establish command-and-control (C2) communications and evade detection.",
        "scope": "Identify network traffic patterns indicative of adversaries leveraging public web services for C2.",
        "threat_model": "Adversaries abuse popular web services such as cloud storage, messaging platforms, and APIs to blend C2 traffic with legitimate network activity.",
        "hypothesis": [
            "Are there unauthorized connections to cloud-based services being used for C2?",
            "Are adversaries leveraging common web applications to obfuscate malicious communications?",
            "Is there an increase in HTTP/HTTPS requests to external web services with unusual traffic patterns?"
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
            "Monitor for unusual HTTP/HTTPS traffic to cloud-based services.",
            "Detect anomalous API usage patterns linked to known web services.",
            "Identify large volumes of encoded data sent to external applications."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*http* OR protocol=*https* \n| stats count by src_ip, dest_ip, uri"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify web service-related network traffic.",
            "Analyze API Calls: Detect anomalies in external cloud service interactions.",
            "Monitor for Unusual Web Traffic: Identify excessive data transfer to web services.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques leveraging web services.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Web Service-Based C2 Detected: Block malicious web service traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for web service-based C2 techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1102 (Web Service)", "example": "C2 traffic routed through cloud storage services such as Google Drive or Dropbox."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated using a messaging API like Slack or Telegram."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after using web service-based C2."}
        ],
        "watchlist": [
            "Flag outbound connections to unusual cloud service endpoints.",
            "Monitor for anomalies in API authentication and usage patterns.",
            "Detect unauthorized use of cloud storage or messaging services for C2."
        ],
        "enhancements": [
            "Deploy deep packet inspection to analyze web service traffic.",
            "Implement behavioral analytics to detect API misuse.",
            "Improve correlation between web service activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious web service-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized web service traffic, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of web service-based command-and-control techniques."
    }
