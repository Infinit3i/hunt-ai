def get_content():
    return {
        "id": "T1001.001",
        "url_id": "T1001/001",
        "title": "Data Obfuscation: Junk Data",
        "description": "Adversaries may add junk data to protocols used for command and control to make detection more difficult. By adding random or meaningless data to the protocols used for command and control, adversaries can prevent trivial methods for decoding, deciphering, or otherwise analyzing the traffic. Examples may include appending/prepending data with junk characters or writing junk characters between significant characters.",
        "tags": ["data obfuscation", "junk data", "command and control", "detection"],
        "tactic": "Command and Control",
        "data_sources": "Zeek, Suricata, Firewall, Proxy, Sysmon",
        "protocol": "HTTP, HTTPS, DNS, TCP, UDP",
        "os": "Mac, Linux, Windows",
        "tips": [
            "Review baseline network traffic to determine normal padding levels.",
            "Correlate suspicious data with known C2 patterns.",
            "Verify with endpoint logs to distinguish benign from malicious events."
        ],
        "log_sources": [
            {"type": "Zeek", "source": "", "destination": ""},
            {"type": "Suricata", "source": "", "destination": ""},
            {"type": "Firewall", "source": "Palo Alto, Fortinet, Cisco ASA", "destination": ""},
            {"type": "Proxy", "source": "Zscaler, Bluecoat, McAfee Web Gateway", "destination": ""},
            {"type": "Sysmon", "source": "1, 3", "destination": "1, 3"}
        ],
        "detection_methods": [
            "Monitor for network packets with excessive random padding.",
            "Detect unusual entropy levels in encrypted payloads.",
            "Identify anomalies in packet size distributions and unexpected data patterns."
        ],
        "apt": [
            "Fancy Bear",
            "Cozy Bear"
        ],
        "spl_query": [
            "index=network sourcetype=firewall_logs \n| search payload=*random* OR payload=*junk* OR payload=*padding* \n| stats count by src_ip, dest_ip, payload"
        ],
        "hunt_steps": [
            "Run Queries in SIEM: Identify network traffic with junk data.",
            "Analyze Payloads: Decode and inspect unusual data patterns.",
            "Monitor for Junk Injection: Identify adversary behavior related to junk data insertion.",
            "Correlate with Threat Intelligence: Compare with known C2 techniques using junk data.",
            "Validate & Escalate: If malicious activity is found → Escalate to Incident Response."
        ],
        "expected_outcomes": [
            "Junk Data Identified: Block and investigate obfuscated communications."
        ],
        "false_positive": "May include benign padding from legitimate applications or normal network overhead.",
        "clearing_steps": [
            "Review affected systems for compromise.",
            "Investigate and correlate logs across endpoints and network devices.",
            "Reset affected credentials and apply necessary patches."
        ],
        "mitre_mapping": [
            {"tactic": "Command and Control", "technique": "T1001.001 (Junk Data)", "example": "Excessive padding used in HTTP payloads to disguise commands."},
            {"tactic": "Exfiltration", "technique": "T1048 (Exfiltration Over Alternative Protocol)", "example": "Data exfiltrated via junk-padded DNS queries."},
            {"tactic": "Defense Evasion", "technique": "T1070.004 (Indicator Removal on Host)", "example": "Malware injecting junk data into logs to obscure activity."}
        ],
        "watchlist": [
            "Flag network traffic with excessive padding.",
            "Monitor for unexpected entropy variations in payloads.",
            "Detect anomalies in encoded data structures."
        ],
        "enhancements": [
            "Implement deep packet inspection to detect obfuscated C2 traffic.",
            "Deploy anomaly detection for entropy-based payload analysis.",
            "Improve correlation between encoded traffic and known malware behavior."
        ],
        "summary": "Document detected junk data obfuscation techniques and affected systems.",
        "remediation": "Block obfuscated communication channels, revoke compromised access, and enhance network monitoring.",
        "improvements": "Refine detection models and improve analysis of obfuscated network traffic."
    }
