def get_content():
    return {
        "id": "T1102.003",
        "url_id": "T1102/003",
        "title": "Web Service: Bidirectional Communication",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS), Cloud Logs, API Logs",
        "protocol": "HTTP, HTTPS, WebSocket, API-Based Communications",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using bidirectional web services to establish persistent command-and-control (C2) communications and evade detection.",
        "scope": "Identify network traffic patterns indicative of adversaries leveraging bidirectional web services for C2.",
        "threat_model": "Adversaries use bidirectional web services, such as messaging APIs and real-time communication platforms, to maintain interactive and persistent C2 channels, making it difficult to distinguish from normal traffic.",
        "hypothesis": [
            "Are there unauthorized bidirectional communications with web services that could indicate C2 activity?",
            "Are adversaries leveraging WebSockets or API calls for real-time command-and-control?",
            "Is there an increase in persistent HTTPS connections to known messaging or cloud-based API endpoints?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 3, 22), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"},
            {"type": "Cloud Logs", "source": "AWS CloudTrail, Azure Monitor, Google Cloud Logging"},
            {"type": "API Logs", "source": "Application Gateway Logs, Cloud API Monitoring"}
        ],
        "detection_methods": [
            "Monitor for persistent connections to web-based APIs and WebSockets.",
            "Detect anomalies in bidirectional communication patterns.",
            "Identify excessive API requests that resemble interactive C2 behavior."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search protocol=*http* OR protocol=*https* OR protocol=*websocket* \n| stats count by src_ip, dest_ip, uri"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify suspicious bidirectional web-based communication.",
            "Analyze WebSocket and API Calls: Detect anomalies in continuous real-time interactions.",
            "Monitor for Unusual Web Activity: Identify persistent sessions to cloud-based services.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques leveraging bidirectional web services.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Bidirectional Communication-Based C2 Detected: Block malicious traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for bidirectional communication-based C2 techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1102.003 (Bidirectional Communication)", "example": "C2 traffic maintained through WebSocket-based communication."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated using a continuous API polling mechanism."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after using bidirectional web-based C2."}
        ],
        "watchlist": [
            "Flag outbound connections to known bidirectional communication services for unusual access patterns.",
            "Monitor for anomalies in WebSocket and API authentication and usage patterns.",
            "Detect unauthorized use of cloud-based messaging services for C2."
        ],
        "enhancements": [
            "Deploy deep packet inspection to analyze bidirectional API traffic.",
            "Implement behavioral analytics to detect interactive C2 misuse.",
            "Improve correlation between bidirectional communication activity and known threat actor techniques."
        ],
        "summary": "Document detected malicious bidirectional web service-based command-and-control activity and affected systems.",
        "remediation": "Block unauthorized bidirectional web service traffic, revoke compromised access, and enhance monitoring.",
        "improvements": "Refine detection models and improve analysis of bidirectional web service-based command-and-control techniques."
    }
