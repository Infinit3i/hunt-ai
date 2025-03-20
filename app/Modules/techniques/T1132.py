def get_content():
    return {
        "id": "T1132",
        "url_id": "T1132",
        "title": "Data Encoding",
        "description": "Adversaries may encode data to make the content of command and control traffic more difficult to detect. Some data encoding systems may also result in data compression, such as gzip.",  # Simple description (one pair of quotes)
        "tags": [
            "Data Encoding",
            "Command and Control",
            "Network Traffic",
            "Binary-to-Text",
            "Character Encoding",
            "Wikipedia Binary-to-text Encoding",
            "Wikipedia Character Encoding",
            "Mythc Documentation",
            "ProofPoint Ursnif Aug 2016",
            "Forcepoint Monsoon",
            "Cisco H1N1 Part 2",
            "Anomali Linux Rabbit 2018",
            "University of Birmingham C2",
            "Itzik Kotler, SafeBreach"
        ],
        "tactic": "Command and Control",  # Associated MITRE ATT&CK tactic
        "protocol": "Various",  # Protocol used in the attack technique
        "os": "Linux, Windows, macOS",  # Targeted operating systems
        "tips": [
            "Analyze network data for uncommon data flows (e.g., a client sending significantly more data than it receives)",
            "Look for processes utilizing the network that do not normally communicate or have never been seen before",
            "Analyze packet contents for unexpected protocol behavior on the port in use"
        ],
        "log_sources": [
            {"type": "Network Traffic", "source": "Zeek (Bro), Suricata, Wireshark"},
            {"type": "Firewall Logs", "source": "Palo Alto, Fortinet, Cisco ASA"},
            {"type": "Proxy Logs", "source": "Zscaler, Bluecoat, McAfee Web Gateway"},
            {"type": "Endpoint Logs", "source": "Sysmon (Event ID 1, 3), EDR (CrowdStrike, Defender ATP)"},
            {"type": "IDS", "source": "Snort, Suricata, Zeek (Bro)"}
        ],
        "detection_methods": [
            "Monitor for Base64, XOR, or custom encoding in network payloads.",
            "Detect large compressed or encrypted outbound traffic sessions.",
            "Identify abnormal HTTP headers, DNS queries, or non-standard packet structures."
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search payload=*base64* OR payload=*xor* OR payload=*gzip* \n| stats count by src_ip, dest_ip, payload"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify obfuscated payloads in network traffic.",
            "Analyze Encoded Data: Decode and analyze encoded strings in network logs.",
            "Monitor for Unusual Encoding Patterns: Identify adversary behavior related to data encoding.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques using data encoding.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Encoded Data Identified: Block obfuscated traffic and investigate affected hosts.",
            "No Malicious Activity Found: Improve detection of encoded data anomalies."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1132 (Data Encoding)", "example": "Base64-encoded C2 commands in HTTP traffic."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated via encoded DNS queries."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware deleting logs after encoding usage."}
        ],
        "watchlist": [
            "Flag outbound traffic with encoded payloads.",
            "Monitor for excessive compressed data transfers.",
            "Detect anomalies in encryption and encoding techniques."
        ],
        "enhancements": [
            "Deploy TLS inspection to analyze encrypted payloads.",
            "Enable deep packet inspection for detecting encoded data.",
            "Implement behavioral analytics to detect unusual encoding techniques."
        ],
        "summary": "Document detected encoding attempts and affected systems.",
        "remediation": "Block obfuscated data channels, revoke compromised access, and improve network monitoring.",
        "improvements": "Enhance anomaly detection models and improve threat hunting for encoding techniques."
    }
