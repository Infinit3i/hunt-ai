def get_content():
    return {
        "id": "T1132.001",
        "url_id": "T1132/001",
        "title": "Data Encoding: Standard Encoding",
        "tactic": "Command and Control",
        "data_sources": "Network Traffic, Firewall Logs, Proxy Logs, Endpoint Logs, Intrusion Detection Systems (IDS)",
        "protocol": "HTTP, HTTPS, DNS, SMTP, FTP, TCP, UDP",
        "os": "Platform Agnostic",
        "objective": "Detect and mitigate adversaries using standard encoding techniques such as Base64, URL encoding, or UTF-8 encoding to obfuscate command-and-control (C2) communications and evade detection.",
        "scope": "Identify encoded network traffic patterns, encoded payloads, and disguised command-and-control (C2) channels.",
        "threat_model": "Adversaries use standard encoding techniques to transform data, allowing them to bypass security controls and avoid detection in network and endpoint monitoring.",
        "hypothesis": [
            "Are there unusual Base64 or URL-encoded payloads in network traffic?",
            "Is data being exfiltrated using standard encoding techniques?",
            "Are adversaries encoding commands to evade detection?"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 1, 3), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"}
        ],
        "detection_methods": [
            "Monitor for Base64, URL encoding, or UTF-8 encoding in network payloads.",
            "Detect encoded content in HTTP headers, DNS queries, or email bodies.",
            "Identify anomalous encoding patterns in network and endpoint logs."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search payload=*base64* OR payload=*url_encoded* OR payload=*utf8* \n| stats count by src_ip, dest_ip, payload"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify encoded payloads in network traffic.",
            "Analyze Encoded Data: Decode and analyze encoded strings in network logs.",
            "Monitor for Encoding Techniques: Identify adversary behavior related to data encoding.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques using standard encoding.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Standard Encoding Detected: Block obfuscated traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection models for standard encoding techniques."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1132.001 (Standard Encoding)", "example": "Base64-encoded C2 commands in HTTP traffic."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated via URL-encoded requests."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after encoding usage."}
        ],
        "watchlist": [
            "Flag outbound traffic with Base64, URL-encoded, or UTF-8 encoded payloads.",
            "Monitor for unusual encoding transformations in network traffic.",
            "Detect anomalies in encoded command structures."
        ],
        "enhancements": [
            "Deploy TLS inspection to analyze encrypted encoded payloads.",
            "Enable deep packet inspection for detecting encoding-based obfuscation.",
            "Implement behavioral analytics to detect unusual encoding techniques."
        ],
        "summary": "Document detected encoding attempts and affected systems.",
        "remediation": "Block obfuscated data channels, revoke compromised access, and improve network monitoring.",
        "improvements": "Enhance anomaly detection models and improve threat hunting for encoding techniques."
    }
